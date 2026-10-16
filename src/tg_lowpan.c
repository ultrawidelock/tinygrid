/* SPDX-License-Identifier: ISC */
/*
 * 6LoWPAN for a Thread child: RFC 6282 IPHC and UDP NHC both ways, the RFC
 * 4944 mesh header skipped on receive, and one reassembly at a time.
 *
 * Decompression takes every form a router may send. Compression emits only
 * the forms this node needs: no traffic class, no flow label, UDP always
 * through NHC with its checksum carried.
 */
#include "tg_int.h"

#define REASM_MS 2000u

/* The IID a MAC address stands for. */
static void iid_of(uint8_t iid[8], const struct tg_maddr *a)
{
	if (a->mode == 3u) {
		memcpy(iid, a->e, 8);
		iid[0] ^= 0x02u;
	} else {
		static const uint8_t pre[6] = {0, 0, 0, 0xffu, 0xfeu, 0};

		memcpy(iid, pre, 6);
		put16(iid + 6, a->s);
	}
}

static bool is_short_iid(const uint8_t *iid)
{
	static const uint8_t pre[6] = {0, 0, 0, 0xffu, 0xfeu, 0};

	return memcmp(iid, pre, 6) == 0;
}

/* One unicast address; returns the bytes consumed or -1. */
static int addr_in(uint8_t out[16], const uint8_t *p, bool ac, uint8_t am, uint8_t cid,
		   const struct tg_maddr *mac)
{
	const uint8_t *pre;

	memset(out, 0, 16);
	if (!ac) {
		if (am == 0u) {
			memcpy(out, p, 16);
			return 16;
		}
		out[0] = 0xfeu;
		out[1] = 0x80u;
	} else {
		if (am == 0u) {
			return 0; /* the unspecified address */
		}
		pre = tg_ctx_prefix(cid);
		if (pre == NULL) {
			return -1;
		}
		memcpy(out, pre, 8);
	}
	switch (am) {
	case 1:
		memcpy(out + 8, p, 8);
		return 8;
	case 2:
		out[11] = 0xffu;
		out[12] = 0xfeu;
		memcpy(out + 14, p, 2);
		return 2;
	default:
		iid_of(out + 8, mac);
		return 0;
	}
}

/*
 * Expand the IPHC (and UDP NHC) header at p into a 40 or 48 byte header at out.
 * Returns the compressed length consumed, the expanded length in *olen, or -1.
 * Lengths and the checksum's coverage are filled in by the caller.
 */
static int iphc_in(uint8_t *out, uint8_t *olen, const uint8_t *p, uint8_t n,
		   const struct tg_maddr *src, const struct tg_maddr *dst)
{
	uint8_t tf, nh, hl, sam, dam, sci = 0, dci = 0;
	const uint8_t *q = p + 2;
	int k;

	if (n < 2u) {
		return -1;
	}
	tf = (p[0] >> 3) & 3u;
	nh = (p[0] >> 2) & 1u;
	hl = p[0] & 3u;
	sam = (p[1] >> 4) & 3u;
	dam = p[1] & 3u;
	if (p[1] & 0x80u) {
		sci = *q >> 4;
		dci = *q & 0xfu;
		q++;
	}
	memset(out, 0, 40);
	out[0] = 0x60u;
	switch (tf) {
	case 0: /* ECN DSCP | pad flow label */
		out[0] |= (uint8_t)(((q[0] & 0x3fu) << 2 | q[0] >> 6) >> 4);
		out[1] = (uint8_t)(((q[0] & 0x3fu) << 2 | q[0] >> 6) << 4) | (q[1] & 0x0fu);
		out[2] = q[2];
		out[3] = q[3];
		q += 4;
		break;
	case 1: /* ECN | pad flow label */
		out[0] |= (uint8_t)((q[0] >> 6) >> 4);
		out[1] = (uint8_t)((q[0] >> 6) << 4) | (q[0] & 0x0fu);
		out[2] = q[1];
		out[3] = q[2];
		q += 3;
		break;
	case 2: /* ECN DSCP */
		out[0] |= (uint8_t)(((q[0] & 0x3fu) << 2 | q[0] >> 6) >> 4);
		out[1] = (uint8_t)(((q[0] & 0x3fu) << 2 | q[0] >> 6) << 4);
		q += 1;
		break;
	default:
		break;
	}
	if (!nh) {
		out[6] = *q++;
	}
	static const uint8_t hls[4] = {0, 1, 64, 255};
	out[7] = hl ? hls[hl] : *q++;

	k = addr_in(out + 8, q, (p[1] & 0x40u) != 0u, sam, sci, src);
	if (k < 0) {
		return -1;
	}
	q += k;
	if (p[1] & 0x08u) { /* multicast */
		uint8_t *d = out + 24;

		if (p[1] & 0x04u) {
			return -1; /* unicast-prefix-based: never needed by a child */
		}
		memset(d, 0, 16);
		d[0] = 0xffu;
		switch (dam) {
		case 0:
			memcpy(d, q, 16);
			q += 16;
			break;
		case 1:
			d[1] = q[0];
			memcpy(d + 11, q + 1, 5);
			q += 6;
			break;
		case 2:
			d[1] = q[0];
			memcpy(d + 13, q + 1, 3);
			q += 4;
			break;
		default:
			d[1] = 0x02u;
			d[15] = q[0];
			q += 1;
			break;
		}
	} else {
		if ((p[1] & 0x04u) && dam == 0u) {
			return -1;
		}
		k = addr_in(out + 24, q, (p[1] & 0x04u) != 0u, dam, dci, dst);
		if (k < 0) {
			return -1;
		}
		q += k;
	}
	*olen = 40;
#if TG_MCAST
	if (nh && (q[0] & 0xf0u) == 0xe0u) {
		/* NHC extension header: hop-by-hop only, as MPL carries it. */
		uint8_t *h = out + 40, l, ext, pad;
		bool udp_next = q[0] & 1u;

		if (((q[0] >> 1) & 7u) != 0u) {
			return -1;
		}
		q++;
		h[0] = udp_next ? 17u : *q++;
		l = *q++;
		if (l > 14u) {
			return -1;
		}
		ext = (uint8_t)((2u + l + 7u) & ~7u);
		h[1] = (uint8_t)(ext / 8u - 1u);
		memcpy(h + 2, q, l);
		q += l;
		pad = (uint8_t)(ext - 2u - l);
		memset(h + 2 + l, 0, pad);
		if (pad > 1u) {
			h[2 + l] = 1u; /* PadN */
			h[3 + l] = (uint8_t)(pad - 2u);
		}
		out[6] = 0;
		*olen = (uint8_t)(40u + ext);
		nh = udp_next;
	} else
#endif
	if (nh) {
		out[6] = 17;
	}
	if (nh) {
		uint8_t *u = out + *olen;

		if ((q[0] & 0xf8u) != 0xf0u || (q[0] & 0x04u)) {
			return -1; /* only UDP, and only with its checksum */
		}
		switch (q[0] & 3u) {
		case 0:
			memcpy(u, q + 1, 4);
			q += 5;
			break;
		case 1:
			memcpy(u, q + 1, 2);
			u[2] = 0xf0u;
			u[3] = q[3];
			q += 4;
			break;
		case 2:
			u[0] = 0xf0u;
			u[1] = q[1];
			memcpy(u + 2, q + 2, 2);
			q += 4;
			break;
		default:
			u[0] = 0xf0u;
			u[1] = (uint8_t)(0xb0u | q[1] >> 4);
			u[2] = 0xf0u;
			u[3] = (uint8_t)(0xb0u | (q[1] & 0xfu));
			q += 2;
			break;
		}
		memcpy(u + 6, q, 2);
		q += 2;
		*olen = (uint8_t)(*olen + 8u);
	}
	if (q - p > n) {
		return -1;
	}
	return (int)(q - p);
}

static void lengths(uint8_t *pkt, uint16_t total)
{
	uint16_t at = 40;
	uint8_t nh = pkt[6];

	put16(pkt + 4, (uint16_t)(total - 40u));
	if (nh == 0u) {
		at = (uint16_t)(40u + (pkt[41] + 1u) * 8u);
		nh = pkt[40];
	}
	if (nh == 17u && at + 8u <= total) {
		put16(pkt + at + 4, (uint16_t)(total - at));
	}
}

void tg_reasm_timeout(void)
{
	tg.r_busy = false;
}

void tg_lowpan_rx(uint8_t *p, uint8_t n, struct tg_maddr *src, struct tg_maddr *dst, bool sec)
{
	uint8_t hl;
	int k;

	if (n && (p[0] & 0xc0u) == 0x80u) { /* mesh header: the addresses it names win */
		uint8_t v = p[0] & 0x20u, f = p[0] & 0x10u, o = 1;

		if ((p[0] & 0x0fu) == 0x0fu) {
			o++;
		}
		if (n < o + (v ? 2u : 8u) + (f ? 2u : 8u)) {
			return;
		}
		src->mode = v ? 2u : 3u;
		if (v) {
			src->s = get16(p + o);
			o += 2;
		} else {
			memcpy(src->e, p + o, 8);
			o += 8;
		}
		dst->mode = f ? 2u : 3u;
		if (f) {
			dst->s = get16(p + o);
			o += 2;
		} else {
			memcpy(dst->e, p + o, 8);
			o += 8;
		}
		p += o;
		n = (uint8_t)(n - o);
	}
	if (n >= 2u && p[0] == 0x50u) { /* LOWPAN_BC0 */
		p += 2;
		n = (uint8_t)(n - 2u);
	}
	if (n < 2u) {
		return;
	}
	if ((p[0] & 0xe0u) == 0x60u) {
		/* One frame expands to at most 125 - 2 + 64 bytes; the shared
		 * buffer may be holding a reassembly. */
		uint8_t ub[188];

		k = iphc_in(ub, &hl, p, n, src, dst);
		if (k < 0) {
			return;
		}
		memcpy(ub + hl, p + k, (size_t)(n - k));
		lengths(ub, (uint16_t)(hl + n - k));
		tg_ip6_rx(ub, (uint16_t)(hl + n - k), sec);
		return;
	}
	if (n < 5u || (p[0] & 0xd8u) != 0xc0u) {
		return; /* neither FRAG1 nor FRAGN */
	}
	{
		uint16_t size = get16(p) & 0x7ffu, tag = get16(p + 2);
		uint8_t sid[8] = {0};

		if (src->mode == 3u) {
			memcpy(sid, src->e, 8);
		} else {
			put16(sid, src->s);
		}
		if ((p[0] & 0xf8u) == 0xc0u) {
			if (size > TG_PKT_MAX || size < 40u) {
				return;
			}
			k = iphc_in(tg.pkt, &hl, p + 4, (uint8_t)(n - 4u), src, dst);
			if (k < 0 || hl + (n - 4u - k) > size) {
				return;
			}
			memcpy(tg.pkt + hl, p + 4 + k, (size_t)(n - 4u - k));
			tg.r_got = (uint16_t)(hl + n - 4u - k);
			tg.r_size = size;
			tg.r_tag = tag;
			memcpy(tg.r_src, sid, 8);
			tg.r_busy = true;
			tg_arm(T_REASM, REASM_MS);
		} else {
			uint16_t off = (uint16_t)(p[4] * 8u);

			if (!tg.r_busy || tag != tg.r_tag || size != tg.r_size ||
			    memcmp(sid, tg.r_src, 8) != 0 || off + (n - 5u) > size) {
				return;
			}
			memcpy(tg.pkt + off, p + 5, (size_t)(n - 5u));
			tg.r_got = (uint16_t)(tg.r_got + n - 5u);
		}
		if (tg.r_got >= tg.r_size) {
			tg.r_busy = false;
			tg_disarm(T_REASM);
			lengths(tg.pkt, tg.r_size);
			tg_ip6_rx(tg.pkt, tg.r_size, sec);
		}
	}
}

/* ---- compression ------------------------------------------------------- */

/* The address mode for a 64-bit IID against the MAC address carrying it. */
static uint8_t am_for(const uint8_t *iid, const struct tg_maddr *mac)
{
	uint8_t m[8];

	iid_of(m, mac);
	if (memcmp(iid, m, 8) == 0) {
		return 3;
	}
	return is_short_iid(iid) ? 2u : 1u;
}

static uint8_t *addr_out(uint8_t *q, const uint8_t *a, uint8_t am)
{
	if (am == 1u) {
		memcpy(q, a + 8, 8);
		return q + 8;
	}
	if (am == 2u) {
		memcpy(q, a + 14, 2);
		return q + 2;
	}
	return q;
}

/*
 * Compress the 40-byte IPv6 header at ip6, plus the UDP header after it when
 * its next header is UDP. Returns the compressed length.
 */
uint8_t tg_iphc(uint8_t *out, const uint8_t *ip6, const struct tg_maddr *src,
		const struct tg_maddr *dst)
{
	static const uint8_t ll[8] = {0xfeu, 0x80u};
	const uint8_t *s = ip6 + 8, *d = ip6 + 24;
	uint8_t *q = out + 3; /* room for a context byte */
	uint8_t b0 = 0x78u, b1 = 0, cid = 0, sam = 0, dam = 0;
	bool hbh = ip6[6] == 0u;
	const uint8_t *u = ip6 + (hbh ? 48 : 40);
	bool udp = (hbh ? ip6[40] : ip6[6]) == 17u;
	int c;

	if (udp || hbh) {
		b0 |= 0x04u;
	} else {
		*q++ = ip6[6];
	}
	switch (ip6[7]) {
	case 1:
		b0 |= 1u;
		break;
	case 64:
		b0 |= 2u;
		break;
	case 255:
		b0 |= 3u;
		break;
	default:
		*q++ = ip6[7];
	}

	if (memcmp(s, ll, 8) == 0) {
		sam = am_for(s + 8, src);
	} else if ((c = tg_ctx_find(s)) >= 0) {
		b1 |= 0x40u;
		cid |= (uint8_t)(c << 4);
		sam = am_for(s + 8, src);
	}
	if (sam == 0u) {
		memcpy(q, s, 16);
		q += 16;
	} else {
		q = addr_out(q, s, sam);
	}
	b1 |= (uint8_t)(sam << 4);

	if (d[0] == 0xffu) {
		static const uint8_t z[13];

		b1 |= 0x08u;
		if (d[1] == 0x02u && memcmp(d + 2, z, 13) == 0) {
			dam = 3;
			*q++ = d[15];
		} else if (memcmp(d + 2, z, 11) == 0) {
			dam = 2;
			*q++ = d[1];
			memcpy(q, d + 13, 3);
			q += 3;
		} else if (memcmp(d + 2, z, 9) == 0) {
			dam = 1;
			*q++ = d[1];
			memcpy(q, d + 11, 5);
			q += 5;
		} else {
			memcpy(q, d, 16);
			q += 16;
		}
	} else {
		if (memcmp(d, ll, 8) == 0) {
			dam = am_for(d + 8, dst);
		} else if ((c = tg_ctx_find(d)) >= 0) {
			b1 |= 0x04u;
			cid |= (uint8_t)c;
			dam = am_for(d + 8, dst);
		}
		if (dam == 0u) {
			memcpy(q, d, 16);
			q += 16;
		} else {
			q = addr_out(q, d, dam);
		}
	}
	b1 |= dam;

#if TG_MCAST
	if (hbh) { /* NHC extension header; the 6 MPL option bytes carry no padding */
		*q++ = (uint8_t)(0xe0u | (udp ? 1u : 0u));
		if (!udp) {
			*q++ = ip6[40];
		}
		*q++ = 6;
		memcpy(q, ip6 + 42, 6);
		q += 6;
	}
#endif
	if (udp) {
		uint16_t sp = get16(u), dp = get16(u + 2);

		if ((sp & 0xfff0u) == 0xf0b0u && (dp & 0xfff0u) == 0xf0b0u) {
			*q++ = 0xf3u;
			*q++ = (uint8_t)((sp & 0xfu) << 4 | (dp & 0xfu));
		} else if ((dp & 0xff00u) == 0xf000u) {
			*q++ = 0xf1u;
			memcpy(q, u, 2);
			q[2] = (uint8_t)dp;
			q += 3;
		} else if ((sp & 0xff00u) == 0xf000u) {
			*q++ = 0xf2u;
			*q++ = (uint8_t)sp;
			memcpy(q, u + 2, 2);
			q += 2;
		} else {
			*q++ = 0xf0u;
			memcpy(q, u, 4);
			q += 4;
		}
		memcpy(q, u + 6, 2);
		q += 2;
	}

	if (cid) {
		b1 |= 0x80u;
		out[0] = b0;
		out[1] = b1;
		out[2] = cid;
		return (uint8_t)(q - out);
	}
	/* no context byte: close the gap */
	memmove(out + 2, out + 3, (size_t)(q - out - 3));
	out[0] = b0;
	out[1] = b1;
	return (uint8_t)(q - out - 1);
}
