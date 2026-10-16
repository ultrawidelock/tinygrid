/* SPDX-License-Identifier: ISC */
/*
 * SRP client (draft-ietf-dnssd-srp): one DNS Update carries the host, its
 * off-mesh address, its key and every service, signed with SIG(0). The
 * layout follows OpenThread's client (src/core/net/srp_client.cpp) record for
 * record, since that is what Thread border routers are tested against.
 *
 * The update is built in the reassembly buffer, which is idle whenever no
 * datagram is arriving in fragments.
 */
#include "tg_int.h"

#ifndef TG_SRP_LEASE_S
#define TG_SRP_LEASE_S 7200u /* OPENTHREAD_CONFIG_SRP_CLIENT_DEFAULT_LEASE */
#endif
#ifndef TG_SRP_KEY_LEASE_S
#define TG_SRP_KEY_LEASE_S TG_SRP_LEASE_S /* a key lease may not be shorter */
#endif

#define RT_SOA 6u
#define RT_PTR 12u
#define RT_TXT 16u
#define RT_SIG 24u
#define RT_KEY 25u
#define RT_AAAA 28u
#define RT_SRV 33u
#define RT_OPT 41u
#define RT_ANY 255u
#define CL_IN 1u
#define CL_NONE 254u
#define CL_ANY 255u

static const char *host;
static struct tg_srp_svc *svcs;
static uint16_t msg_id;
static uint32_t granted = TG_SRP_LEASE_S;
static uint8_t backoff;
static bool waiting, registered, drop_host;

static uint8_t *labels(uint8_t *p, const char *s)
{
	while (*s) {
		const char *e = s;

		while (*e && *e != '.') {
			e++;
		}
		*p = (uint8_t)(e - s);
		memcpy(p + 1, s, (size_t)(e - s));
		p += 1 + (e - s);
		s = *e ? e + 1 : e;
	}
	return p;
}

static uint8_t *ptr(uint8_t *p, uint16_t off)
{
	put16(p, (uint16_t)(0xc000u | off));
	return p + 2;
}

static uint8_t *rr(uint8_t *p, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t len)
{
	put16(p, type);
	put16(p + 2, cls);
	put32(p + 4, ttl);
	put16(p + 8, len);
	return p + 10;
}

/* rr() with the length patched once the rdata is written */
static void rdlen(uint8_t *after_rr, uint8_t *end)
{
	put16(after_rr - 2, (uint16_t)(end - after_rr));
}

void tg_srp_kick(uint32_t delay_ms)
{
	if (host && !waiting) {
		tg_arm(T_SRP, delay_ms);
	}
}

int tg_srp_host(const char *label)
{
	if (label == NULL || strlen(label) > 63u) {
		return TG_E_INVAL;
	}
	host = label;
	return TG_OK;
}

int tg_srp_add(struct tg_srp_svc *svc)
{
	struct tg_srp_svc *s;

	if (host == NULL) {
		return TG_E_STATE;
	}
	for (s = svcs; s && s != svc; s = s->next) {
	}
	if (s == NULL) {
		svc->next = svcs;
		svcs = svc;
	}
	svc->state = TG_SRP_ADD;
	tg_srp_kick(0);
	return TG_OK;
}

int tg_srp_remove(struct tg_srp_svc *svc)
{
	if (svc->state != TG_SRP_IDLE) {
		svc->state = TG_SRP_DEL;
		tg_srp_kick(0);
	}
	return TG_OK;
}

void tg_srp_reset(bool tell_server)
{
	for (struct tg_srp_svc *s = svcs; s; s = s->next) {
		s->state = TG_SRP_IDLE;
	}
	svcs = NULL;
	drop_host = tell_server && registered;
	if (drop_host) {
		tg_srp_kick(0);
	} else {
		registered = false;
		tg_disarm(T_SRP);
	}
}

static uint16_t build(void)
{
	uint8_t *b = tg.pkt, *p = b + 12, *v;
	uint16_t zone, hoff = 0, nup = 0, sig;
	uint32_t lease = drop_host ? 0u : TG_SRP_LEASE_S;
	uint32_t ttl = TG_SRP_LEASE_S;
	uint8_t addr[16], key[64], *rd;

	if (tg_plat_srp_pub(key) != 0) {
		return 0;
	}
	if (!tg_omr(addr)) {
		tg_mleid(addr);
	}
	memset(b, 0, 12);
	put16(b, ++msg_id);
	put16(b + 2, 0x2800u); /* opcode UPDATE */
	put16(b + 4, 1);       /* zone */
	put16(b + 10, 1);      /* additional: OPT; SIG comes after signing */
	zone = (uint16_t)(p - b);
	p = labels(p, "default.service.arpa");
	*p++ = 0;
	put16(p, RT_SOA);
	put16(p + 2, CL_IN);
	p += 4;

	for (struct tg_srp_svc *s = drop_host ? NULL : svcs; s; s = s->next) {
		bool del = s->state == TG_SRP_DEL;
		uint16_t soff, ioff, suboff = 0;

		s->sent = s->state;
		if (s->sent == TG_SRP_IDLE) {
			continue;
		}
		/* Service Discovery: PTR type -> instance */
		soff = (uint16_t)(p - b);
		p = ptr(labels(p, s->type), zone);
		v = rr(p, RT_PTR, del ? CL_NONE : CL_IN, del ? 0u : ttl, 0);
		ioff = (uint16_t)(v - b);
		p = ptr(labels(v, s->instance), soff);
		rdlen(v, p);
		nup++;
		for (uint8_t i = 0; !del && i < s->nsub; i++) {
			p = labels(p, s->subtypes[i]);
			if (i == 0u) {
				suboff = (uint16_t)(p - b);
				p = ptr(labels(p, "_sub"), soff);
			} else {
				p = ptr(p, suboff);
			}
			v = rr(p, RT_PTR, CL_IN, ttl, 2);
			p = ptr(v, ioff);
			nup++;
		}
		/* Service Description: wipe the instance, then SRV and TXT */
		p = rr(ptr(p, ioff), RT_ANY, CL_ANY, 0, 0);
		nup++;
		if (del) {
			continue;
		}
		v = rr(ptr(p, ioff), RT_SRV, CL_IN, ttl, 0);
		put16(v, 0);
		put16(v + 2, 0);
		put16(v + 4, s->port);
		if (hoff) {
			p = ptr(v + 6, hoff);
		} else {
			hoff = (uint16_t)(v + 6 - b);
			p = ptr(labels(v + 6, host), zone);
		}
		rdlen(v, p);
		v = rr(ptr(p, ioff), RT_TXT, CL_IN, ttl, 0);
		if (s->txt_len) {
			memcpy(v, s->txt, s->txt_len);
			p = v + s->txt_len;
		} else {
			*v = 0;
			p = v + 1;
		}
		rdlen(v, p);
		nup += 2;
	}

	/* Host Description: wipe the name, then its address and key */
	if (hoff) {
		p = ptr(p, hoff);
	} else {
		hoff = (uint16_t)(p - b);
		p = ptr(labels(p, host), zone);
	}
	p = rr(p, RT_ANY, CL_ANY, 0, 0);
	p = rr(ptr(p, hoff), RT_AAAA, CL_IN, ttl, 16);
	memcpy(p, addr, 16);
	p += 16;
	v = rr(ptr(p, hoff), RT_KEY, CL_IN, ttl, 68);
	v[0] = 0x02u; /* owner: non-zone entity */
	v[1] = 0x01u; /* signatory: general */
	v[2] = 3;     /* protocol: DNSSEC */
	v[3] = 13;    /* ECDSA P-256 SHA-256 */
	memcpy(v + 4, key, 64);
	p = v + 68;
	nup += 3;
	put16(b + 8, nup);

	/* Additional: OPT carrying the Update Lease option */
	*p++ = 0;
	p = rr(p, RT_OPT, 1232, 0x00008000u, 12); /* DO bit */
	put16(p, 2);                              /* Update Lease */
	put16(p + 2, 8);
	put32(p + 4, lease);
	put32(p + 8, drop_host ? 0u : TG_SRP_KEY_LEASE_S);
	p += 12;

	/* SIG(0), RFC 2931: sign the RDATA (signer name uncompressed, no
	 * signature) followed by the message as it stands. */
	sig = (uint16_t)(p - b);
	rd = rr(p, RT_SIG, CL_ANY, 0, 0);
	memset(rd, 0, 18);
	rd[2] = 13;
	p = labels(rd + 18, host);
	p = labels(p, "default.service.arpa");
	*p++ = 0;
	if (tg_plat_srp_sign(rd, (size_t)(p - rd), b, sig, key) != 0) {
		return 0;
	}
	p = b + sig;
	*p++ = 0; /* owner: root */
	rd = rr(p, RT_SIG, CL_ANY, 0, 0);
	memset(rd, 0, 18);
	rd[2] = 13;
	p = ptr(rd + 18, hoff);
	memcpy(p, key, 64);
	p += 64;
	rdlen(rd, p);
	put16(b + 10, 2);
	return (uint16_t)(p - b);
}

void tg_srp_timer(void)
{
	bool work = drop_host;
	uint16_t n;

	if (host == NULL || !tg_ready() || !tg.have_srp) {
		return; /* kicked again once there is somewhere to register */
	}
	for (struct tg_srp_svc *s = svcs; s; s = s->next) {
		work |= s->state == TG_SRP_ADD || s->state == TG_SRP_DEL;
	}
	if (!work && !waiting && !registered) {
		return;
	}
	if (tg.r_busy) {
		tg_arm(T_SRP, 200); /* the buffer is holding a reassembly */
		return;
	}
	n = build();
	if (n == 0u || tg_srp_send(tg.pkt, n) != TG_OK) {
		tg_arm(T_SRP, 1000);
		return;
	}
	waiting = true;
	tg_arm(T_SRP, 2000u << (backoff < 5u ? backoff : 5u));
	if (backoff < 255u) {
		backoff++;
	}
}

static const uint8_t *skip_name(const uint8_t *p, const uint8_t *end)
{
	while (p < end) {
		if (*p == 0u) {
			return p + 1;
		}
		if ((*p & 0xc0u) == 0xc0u) {
			return p + 2;
		}
		p += 1 + *p;
	}
	return NULL;
}

void tg_srp_rx(const uint8_t *m, uint16_t n)
{
	const uint8_t *p = m + 12, *end = m + n;
	struct tg_srp_svc **pp;
	uint16_t skip;
	bool more;

	if (!waiting || n < 12u || get16(m) != msg_id || (get16(m + 2) & 0xf800u) != 0xa800u) {
		return; /* not the answer to this update */
	}
	waiting = false;
	if ((get16(m + 2) & 0x0fu) != 0u) {
		tg_arm(T_SRP, 2000u << (backoff < 5u ? backoff : 5u)); /* refused; try again later */
		return;
	}
	backoff = 0;
	granted = TG_SRP_LEASE_S;
	/* The granted lease, from the OPT record among the additional records. */
	skip = (uint16_t)(get16(m + 4) + get16(m + 6) + get16(m + 8));
	for (uint16_t i = 0; p && i < get16(m + 4); i++) {
		p = skip_name(p, end);
		p = p ? p + 4 : NULL;
		skip--;
	}
	for (uint16_t i = 0; p && i < (uint16_t)(skip + get16(m + 10)); i++) {
		p = skip_name(p, end);
		if (p == NULL || p + 10 > end) {
			break;
		}
		if (i >= skip && get16(p) == RT_OPT && get16(p + 8) >= 8u && p + 18 <= end &&
		    get16(p + 10) == 2u) {
			granted = get32(p + 14);
		}
		p += 10 + get16(p + 8);
	}

	if (drop_host) {
		drop_host = false;
		registered = false;
		if (svcs) {
			tg_arm(T_SRP, 0); /* services added while the host was going */
		}
		tg_plat_changed();
		return;
	}
	more = false;
	for (pp = &svcs; *pp;) {
		struct tg_srp_svc *s = *pp;
		uint8_t sent = s->sent;

		s->sent = TG_SRP_IDLE;
		if (sent == TG_SRP_IDLE || (s->state != sent && s->state != TG_SRP_REG)) {
			more = true; /* added, or changed, while this was in flight */
		} else if (s->state == TG_SRP_DEL) {
			s->state = TG_SRP_IDLE;
			*pp = s->next;
			continue;
		} else {
			s->state = TG_SRP_REG;
		}
		pp = &s->next;
	}
	registered = true;
	/* renew at 80% of the lease */
	tg_arm(T_SRP, more ? 0u : (granted ? granted : TG_SRP_LEASE_S) * 800u);
	tg_plat_changed();
}
