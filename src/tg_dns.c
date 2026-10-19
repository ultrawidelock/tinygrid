/* SPDX-License-Identifier: Apache-2.0 */
/*
 * DNS-SD resolution of one service instance: an SRV query to the server the
 * network data names (the SRP server's address, port 53, as OpenThread's
 * client defaults to), then an AAAA query for the target host when the answer
 * did not already carry its address. One query at a time.
 */
#include "tg_int.h"

#define TRY_MS 3000u
#define TRIES 3u
#define RT_AAAA 28u
#define RT_SRV 33u

static struct {
	tg_dns_fn cb;
	void *ctx;
	uint16_t id, port;
	uint8_t tries, type;
	uint8_t qname[128], qlen; /* wire form */
} q;

/* Expand the name at m[off] into wire form; returns the offset after it. */
static int name_at(const uint8_t *m, uint16_t n, uint16_t off, uint8_t *out, uint8_t *olen)
{
	int end = -1;
	uint8_t o = 0, hops = 0;

	while (off < n) {
		uint8_t l = m[off];

		if ((l & 0xc0u) == 0xc0u) {
			if (off + 1u >= n || ++hops > 8u) {
				return -1;
			}
			if (end < 0) {
				end = off + 2;
			}
			off = (uint16_t)(((l & 0x3fu) << 8) | m[off + 1]);
			continue;
		}
		if (l > 63u || off + 1u + l > n || o + 1u + l > 127u) {
			return -1;
		}
		for (uint8_t i = 0; i <= l; i++) {
			uint8_t c = m[off + i];

			out[o + i] = (i && c >= 'A' && c <= 'Z') ? (uint8_t)(c | 0x20u) : c;
		}
		o = (uint8_t)(o + 1u + l);
		off = (uint16_t)(off + 1u + l);
		if (l == 0u) {
			*olen = o;
			return end < 0 ? off : end;
		}
	}
	return -1;
}

static uint8_t *labels(uint8_t *p, const char *s)
{
	while (*s) {
		const char *e = s;

		while (*e && *e != '.') {
			e++;
		}
		*p = (uint8_t)(e - s);
		for (const char *c = s; c < e; c++) {
			p[1 + (c - s)] = (uint8_t)((*c >= 'A' && *c <= 'Z') ? (*c | 0x20) : *c);
		}
		p += 1 + (e - s);
		s = *e ? e + 1 : e;
	}
	return p;
}

static void finish(int err, const uint8_t *addr, uint16_t port)
{
	tg_dns_fn cb = q.cb;

	q.cb = NULL;
	tg_disarm(T_DNS);
	if (cb) {
		cb(q.ctx, err, addr, port);
	}
}

static void ask(void)
{
	uint8_t m[160], dst[16];

	if (!tg.have_srp) {
		finish(TG_E_STATE, NULL, 0);
		return;
	}
	memset(m, 0, 12);
	put16(m, ++q.id);
	put16(m + 2, 0x0100u); /* recursion desired */
	put16(m + 4, 1);
	memcpy(m + 12, q.qname, q.qlen);
	put16(m + 12 + q.qlen, q.type);
	put16(m + 14 + q.qlen, 1);
	memcpy(dst, tg.srp_addr, 16);
	(void)tg_udp_send(NULL, TG_DNS_CLIENT_PORT, dst, 53, m, (size_t)(16u + q.qlen));
	tg_arm(T_DNS, TRY_MS);
}

int tg_dns_resolve(const char *instance, const char *type, tg_dns_fn cb, void *ctx)
{
	uint8_t *p;

	if (instance == NULL || type == NULL || cb == NULL ||
	    strlen(instance) + strlen(type) > 100u) {
		return TG_E_INVAL;
	}
	if (q.cb != NULL) {
		return TG_E_BUSY;
	}
	if (!tg_ready() || !tg.have_srp) {
		return TG_E_STATE;
	}
	p = q.qname;
	*p = (uint8_t)strlen(instance); /* one label, dots and all */
	memcpy(p + 1, instance, *p);
	p = labels(p + 1 + *p, type);
	p = labels(p, "default.service.arpa");
	*p++ = 0;
	q.qlen = (uint8_t)(p - q.qname);
	q.cb = cb;
	q.ctx = ctx;
	q.type = RT_SRV;
	q.tries = 1;
	ask();
	return TG_OK;
}

void tg_dns_timer(void)
{
	if (q.cb == NULL) {
		return;
	}
	if (q.tries++ >= TRIES) {
		finish(TG_E_STATE, NULL, 0);
	} else {
		ask();
	}
}

void tg_dns_rx(const uint8_t *m, uint16_t n)
{
	uint8_t name[128], target[128], nl, tl = 0;
	const uint8_t *addr = NULL;
	uint16_t an, total, off = 12;
	int k;

	if (q.cb == NULL || n < 12u || get16(m) != q.id || !(m[2] & 0x80u)) {
		return; /* not the answer to the query in flight */
	}
	if ((m[3] & 0x0fu) != 0u) {
		finish(TG_E_INVAL, NULL, 0); /* NXDOMAIN and the like: no such name */
		return;
	}
	for (uint16_t i = 0; i < get16(m + 4); i++) { /* questions */
		k = name_at(m, n, off, name, &nl);
		if (k < 0) {
			return;
		}
		off = (uint16_t)(k + 4);
	}
	an = get16(m + 6);
	total = (uint16_t)(an + get16(m + 8) + get16(m + 10));
	if (q.type == RT_AAAA) {
		memcpy(target, q.qname, q.qlen);
		tl = q.qlen;
	}
	/* Two passes over the records: SRV first, then an AAAA for its target. */
	for (int pass = 0; pass < 2; pass++) {
		uint16_t o = off;

		for (uint16_t i = 0; i < total; i++) {
			uint16_t type, rdl;

			k = name_at(m, n, o, name, &nl);
			if (k < 0 || (uint16_t)k + 10u > n) {
				return;
			}
			type = get16(m + k);
			rdl = get16(m + k + 8);
			o = (uint16_t)(k + 10);
			if ((uint32_t)o + rdl > n) {
				return;
			}
			if (pass == 0 && type == RT_SRV && q.type == RT_SRV && rdl > 6u && !tl &&
			    nl == q.qlen && memcmp(name, q.qname, nl) == 0 &&
			    name_at(m, n, (uint16_t)(o + 6u), target, &tl) > 0) {
				q.port = get16(m + o + 4);
			}
			if (pass == 1 && type == RT_AAAA && rdl == 16u && tl && nl == tl &&
			    memcmp(name, target, tl) == 0) {
				addr = m + o;
				break;
			}
			o = (uint16_t)(o + rdl);
		}
	}
	if (addr) {
		finish(TG_OK, addr, q.port);
	} else if (q.type == RT_SRV && tl) {
		memcpy(q.qname, target, tl); /* the service is there; ask where */
		q.qlen = tl;
		q.type = RT_AAAA;
		q.tries = 1;
		ask();
	} else {
		finish(TG_E_INVAL, NULL, 0);
	}
}
