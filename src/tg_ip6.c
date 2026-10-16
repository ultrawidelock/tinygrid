/* SPDX-License-Identifier: ISC */
/*
 * IPv6 for a child: its handful of addresses, UDP in and out, and an echo
 * reply. Every unicast leaves through the parent; only MLE goes link-local.
 */
#include "tg_int.h"

#define SRP_CLIENT_PORT 49999u

static const uint8_t ll_pre[8] = {0xfeu, 0x80u};

void tg_lladdr(uint8_t out[16], const uint8_t ext[8])
{
	memcpy(out, ll_pre, 8);
	memcpy(out + 8, ext, 8);
	out[8] ^= 0x02u;
}

void tg_mladdr(uint8_t out[16], const uint8_t iid[8])
{
	memcpy(out, tg.mlp, 8);
	memcpy(out + 8, iid, 8);
}

static void rloc_addr(uint8_t out[16])
{
	static const uint8_t mid[6] = {0, 0, 0, 0xffu, 0xfeu, 0};

	memcpy(out, tg.mlp, 8);
	memcpy(out + 8, mid, 6);
	put16(out + 14, tg.rloc);
}

int tg_ctx_find(const uint8_t prefix[8])
{
	if (memcmp(prefix, tg.mlp, 8) == 0) {
		return 0; /* context 0 is always the mesh-local prefix */
	}
	for (uint8_t i = 0; i < tg.nctx; i++) {
		if (memcmp(prefix, tg.ctx[i].prefix, 8) == 0) {
			return tg.ctx[i].id;
		}
	}
	return -1;
}

const uint8_t *tg_ctx_prefix(uint8_t id)
{
	if (id == 0u) {
		return tg.mlp;
	}
	for (uint8_t i = 0; i < tg.nctx; i++) {
		if (tg.ctx[i].id == id) {
			return tg.ctx[i].prefix;
		}
	}
	return NULL;
}

bool tg_is_ours(const uint8_t a[16])
{
	static const uint8_t z[13];
	uint8_t m[16];

	if (a[0] == 0xffu) { /* all-nodes, link- and realm-local */
		return (a[1] == 0x02u || a[1] == 0x03u) && memcmp(a + 2, z, 13) == 0 && a[15] == 1u;
	}
	tg_lladdr(m, tg.ext);
	if (memcmp(a, m, 16) == 0) {
		return true;
	}
	if (memcmp(a + 8, tg.iid, 8) == 0) {
		return memcmp(a, tg.mlp, 8) == 0 || (tg.have_omr && memcmp(a, tg.omr, 8) == 0);
	}
	rloc_addr(m);
	return tg.role == TG_CHILD && memcmp(a, m, 16) == 0;
}

static uint32_t sum(uint32_t s, const uint8_t *p, size_t n)
{
	for (; n > 1u; n -= 2u, p += 2) {
		s += get16(p);
	}
	if (n) {
		s += (uint32_t)p[0] << 8;
	}
	return s;
}

static uint16_t csum(const uint8_t *ip6, const uint8_t *l4, const uint8_t *d, uint16_t dlen)
{
	uint16_t len = (uint16_t)(8u + dlen);
	uint8_t ph[4] = {(uint8_t)(len >> 8), (uint8_t)len, 0, ip6[6]};
	uint32_t s = sum(sum(sum(sum(0, ip6 + 8, 32), ph, 4), l4, 8), d, dlen);

	while (s >> 16) {
		s = (s & 0xffffu) + (s >> 16);
	}
	return (uint16_t)s;
}

/* Send one datagram whose transport header (UDP or ICMPv6) is l4[8]. */
static int send(uint8_t ip6[48], const uint8_t *d, uint16_t dlen, bool mle)
{
	const uint8_t *src = ip6 + 8, *dst = ip6 + 24;
	struct tg_maddr ms = {0}, md = {0};
	uint8_t hdr[64], hl, cpos;
	uint16_t c;

	if (dlen > TG_PKT_MAX - 48u) {
		return TG_E_INVAL;
	}
	if (!mle && tg.role != TG_CHILD) {
		return TG_E_STATE;
	}
	ip6[0] = 0x60u;
	put16(ip6 + 4, (uint16_t)(8u + dlen));
	if (ip6[6] == 17u) {
		put16(ip6 + 44, (uint16_t)(8u + dlen));
	}
	cpos = ip6[6] == 17u ? 46u : 42u;
	put16(ip6 + cpos, 0);
	c = (uint16_t)~csum(ip6, ip6 + 40, d, dlen);
	put16(ip6 + cpos, c ? c : 0xffffu);

	if (memcmp(src, ll_pre, 8) == 0) {
		ms.mode = 3;
		memcpy(ms.e, tg.ext, 8);
	} else {
		ms.mode = 2;
		ms.s = tg.rloc;
	}
	if (dst[0] == 0xffu) {
		md.mode = 2;
		md.s = 0xffffu;
	} else if (memcmp(dst, ll_pre, 8) == 0) {
		md.mode = 3;
		memcpy(md.e, dst + 8, 8);
		md.e[0] ^= 0x02u;
	} else {
		md.mode = 2;
		md.s = tg.par.rloc;
	}
	hl = tg_iphc(hdr, ip6, &ms, &md);
	if (ip6[6] != 17u) {
		memcpy(hdr + hl, ip6 + 40, 8); /* ICMPv6 header, uncompressed */
		hl += 8;
	}
	return tg_mac_send(hdr, hl, d, dlen, (uint16_t)(48u + dlen), &md, ms.mode == 3u, !mle);
}

int tg_ip6_send_udp(const uint8_t src[16], const uint8_t dst[16], uint8_t hlim, uint16_t sport,
		    uint16_t dport, const uint8_t *data, uint16_t len, bool mle)
{
	uint8_t ip6[48] = {0};

	ip6[6] = 17;
	ip6[7] = hlim;
	memcpy(ip6 + 8, src, 16);
	memcpy(ip6 + 24, dst, 16);
	put16(ip6 + 40, sport);
	put16(ip6 + 42, dport);
	return send(ip6, data, len, mle);
}

static void pick_src(uint8_t out[16], const uint8_t dst[16])
{
	if (memcmp(dst, ll_pre, 8) == 0) {
		tg_lladdr(out, tg.ext);
	} else if (memcmp(dst, tg.mlp, 8) != 0 && tg.have_omr) {
		memcpy(out, tg.omr, 8);
		memcpy(out + 8, tg.iid, 8);
	} else {
		tg_mladdr(out, tg.iid);
	}
}

int tg_udp_send(const uint8_t *src, uint16_t sport, const uint8_t dst[16], uint16_t dport,
		const uint8_t *data, size_t len)
{
	uint8_t s[16];

	if (len > 1232u) {
		return TG_E_INVAL;
	}
	if (src == NULL) {
		pick_src(s, dst);
		src = s;
	}
	return tg_ip6_send_udp(src, dst, 64, sport, dport, data, (uint16_t)len, false);
}

void tg_udp_bind(struct tg_udp *sock)
{
	for (struct tg_udp *s = tg.socks; s; s = s->next) {
		if (s == sock) {
			return;
		}
	}
	sock->next = tg.socks;
	tg.socks = sock;
}

void tg_ip6_rx(uint8_t *pkt, uint16_t len, bool sec)
{
	uint8_t *src = pkt + 8, *dst = pkt + 24, *p = pkt + 40;
	uint16_t n = (uint16_t)(len - 40u);

	if (len < 48u || (pkt[0] >> 4) != 6u || !tg_is_ours(dst)) {
		return;
	}
	{
		uint8_t l4[8];
		uint16_t c;

		memcpy(l4, p, 8);
		if (pkt[6] == 17u) {
			if (get16(p + 4) != n) {
				return;
			}
		} else if (pkt[6] != 58u) {
			return;
		}
		c = csum(pkt, l4, p + 8, (uint16_t)(n - 8u));
		if (c != 0xffffu) {
			return;
		}
	}
	if (pkt[6] == 17u) {
		uint16_t sport = get16(p), dport = get16(p + 2);

		if (dport == TG_MLE_PORT) {
			if (pkt[7] == 255u && memcmp(src, ll_pre, 8) == 0) {
				tg_mle_rx(src, dst, p + 8, (uint16_t)(n - 8u));
			}
			return;
		}
		if (!sec) {
			return;
		}
		if (dport == SRP_CLIENT_PORT) {
			if (tg.have_srp && sport == tg.srp_port) {
				tg_srp_rx(p + 8, (uint16_t)(n - 8u));
			}
			return;
		}
		for (struct tg_udp *s = tg.socks; s; s = s->next) {
			if (s->port == dport) {
				s->rx(s, src, sport, dst, p + 8, (size_t)(n - 8u));
				return;
			}
		}
		return;
	}
	if (sec && p[0] == 128u && p[1] == 0u) { /* echo request */
		uint8_t ip6[48] = {0};

		ip6[6] = 58;
		ip6[7] = 64;
		if (dst[0] == 0xffu) {
			pick_src(ip6 + 8, src);
		} else {
			memcpy(ip6 + 8, dst, 16);
		}
		memcpy(ip6 + 24, src, 16);
		memcpy(ip6 + 40, p, 8);
		ip6[40] = 129;
		(void)send(ip6, p + 8, (uint16_t)(n - 8u), false);
	}
}

/* The SRP client's own socket: the server answers it, nothing else does. */
int tg_srp_send(const uint8_t *m, uint16_t n)
{
	return tg_udp_send(NULL, SRP_CLIENT_PORT, tg.srp_addr, tg.srp_port, m, n);
}
