/* SPDX-License-Identifier: Apache-2.0 */
/*
 * MLE for a child: attach (Parent Request, Parent Response, Child ID Request,
 * Child ID Response), keep-alive and address registration (Child Update),
 * network data (Data Request and Response), and following the parent's key
 * sequence.
 *
 * Timings are OpenThread's (src/core/thread/mle.hpp) so a parent sees the
 * child it expects. The version claimed is Thread 1.1: a 1.2+ parent then
 * sends only 2006 frames and expects no CSL, link metrics or supervision TLV.
 */
#include "tg_int.h"

enum {
	C_ADV = 4,
	C_DREQ = 7,
	C_DRSP = 8,
	C_PREQ = 9,
	C_PRSP = 10,
	C_CIDREQ = 11,
	C_CIDRSP = 12,
	C_CUREQ = 13,
	C_CURSP = 14,
};

enum {
	T_SRC = 0,
	T_MODE = 1,
	T_TIMEOUT = 2,
	T_CHAL = 3,
	T_RESP = 4,
	T_LFC = 5,
	T_MFC = 8,
	T_ADDR16 = 10,
	T_LEADER = 11,
	T_NETDATA = 12,
	T_TLVREQ = 13,
	T_SCAN = 14,
	T_CONN = 15,
	T_MARGIN = 16,
	T_STATUS = 17,
	T_VERSION = 18,
	T_AREG = 19,
	T_ATS = 22,
};

#define PREQ_R_MS 750u   /* kParentRequestRouterTimeout */
#define PREQ_RE_MS 1250u /* kParentRequestReedTimeout */
#define CIDRSP_MS 1250u  /* kChildIdResponseTimeout */
#define RETX_MS 1000u    /* kUnicastRetxDelay */
#define KEEPALIVE_TRIES 4u
#define VERSION 2u /* Thread 1.1 */
#define NOISE_FLOOR (-100)

/* Network data flags, BorderRouterEntry (network_data_tlvs.hpp). */
#define BR_PREFERRED 0x2000u
#define BR_SLAAC 0x1000u
#define BR_ON_MESH 0x0100u

static uint8_t leader_raw[8];

static uint8_t mode_byte(void)
{
	return POLL_MS ? 0x00u : 0x08u; /* rx-on-when-idle; MTD; stable data only */
}

#define TLV_N (T_ATS + 1)

/* The shortest value of each TLV this child reads; shorter counts as absent. */
static const uint8_t tlv_min[TLV_N] = {
	[T_SRC] = 2, [T_CHAL] = 4, [T_RESP] = 8, [T_LFC] = 4, [T_MFC] = 4, [T_ADDR16] = 2,
	[T_LEADER] = 8, [T_CONN] = 7, [T_MARGIN] = 1, [T_STATUS] = 1, [T_VERSION] = 2,
};

/* One pass over a message's TLVs: v[type] is the value of the first one. */
static void tlvs(const uint8_t *p, uint16_t n, const uint8_t *v[TLV_N])
{
	uint32_t seen = 0;

	memset(v, 0, TLV_N * sizeof(v[0]));
	while (n >= 2u && 2u + p[1] <= n) {
		if (p[0] < TLV_N && !(seen & (1u << p[0]))) {
			seen |= 1u << p[0];
			v[p[0]] = p[1] >= tlv_min[p[0]] ? p + 2 : NULL;
		}
		n = (uint16_t)(n - 2u - p[1]);
		p += 2u + p[1];
	}
}

static uint8_t tlv_len(const uint8_t *v) { return v[-1]; }

static uint8_t *put(uint8_t *p, uint8_t type, const void *v, uint8_t len)
{
	p[0] = type;
	p[1] = len;
	memcpy(p + 2, v, len);
	return p + 2 + len;
}

static uint8_t *put8(uint8_t *p, uint8_t type, uint8_t v) { return put(p, type, &v, 1); }

static uint8_t *put16t(uint8_t *p, uint8_t type, uint16_t v)
{
	uint8_t b[2];

	put16(b, v);
	return put(p, type, b, 2);
}

static uint8_t *put32t(uint8_t *p, uint8_t type, uint32_t v)
{
	uint8_t b[4];

	put32(b, v);
	return put(p, type, b, 4);
}

static uint8_t *begin(uint8_t *m, uint8_t cmd)
{
	m[0] = 0;     /* 802.15.4 security suite */
	m[1] = 0x15u; /* level 5, key id mode 2; counter and key id at send */
	m[11] = cmd;
	return m + 12;
}

static int finish(uint8_t *m, uint8_t *end, const uint8_t dst[16])
{
	uint8_t src[16], a[42], n[13];
	uint32_t fc = tg_mle_fc_next();
	size_t len = (size_t)(end - m);

	putle32(m + 2, fc);
	put32(m + 6, tg.kseq);
	m[10] = (uint8_t)((tg.kseq & 0x7fu) + 1u);
	tg_lladdr(src, tg.ext);
	memcpy(a, src, 16);
	memcpy(a + 16, dst, 16);
	memcpy(a + 32, m + 1, 10);
	tg_nonce(n, tg.ext, fc);
	(void)tg_ccm(tg.mle_key, n, a, sizeof(a), m + 11, len - 11u, m + len, true);
	return tg_ip6_send_udp(src, dst, 255, TG_MLE_PORT, TG_MLE_PORT, m, (uint16_t)(len + 4u),
			       true);
}

/* ML-EID always, the off-mesh address once there is one. */
static uint8_t *areg(uint8_t *p, bool omr)
{
	uint8_t *v = p + 2;
	int c;

	*v++ = 0x80u; /* compressed, context 0 */
	memcpy(v, tg.iid, 8);
	v += 8;
	if (omr && tg.have_omr) {
		c = tg_ctx_find(tg.omr);
		if (c >= 0) {
			*v++ = (uint8_t)(0x80u | c);
		} else {
			*v++ = 0;
			memcpy(v, tg.omr, 8);
			v += 8;
		}
		memcpy(v, tg.iid, 8);
		v += 8;
	}
	p[0] = T_AREG;
	p[1] = (uint8_t)(v - p - 2);
	return v;
}

static void sed_expect_reply(void)
{
	if (POLL_MS) {
		tg.fast_polls = 10;
		tg_arm(T_POLL, 100);
	}
}

static void backoff(void)
{
	uint8_t r;

	tg.ast = A_IDLE;
	tg_disarm(T_POLL);
	tg_plat_random(&r, 1);
	tg_arm(T_MLE, (1000u << (tg.tries < 6u ? tg.tries : 6u)) + r * 4u);
	if (tg.tries < 255u) {
		tg.tries++;
	}
}

void tg_mle_start(void)
{
	uint8_t r;

	tg.role = TG_DETACHED;
	tg.par.valid = false;
	tg.cand.valid = false;
	tg.rloc = 0xfffeu;
	tg.omr_reg = false;
	tg.have_nd = false;
	tg.tries = 0;
	tg.txfail = 0;
	tg.ast = A_IDLE;
	tg_mac_reset();
	tg_disarm(T_POLL);
	tg_plat_radio_set(tg.chan, tg.pan, 0xfffeu, tg.ext);
	tg_plat_radio_rx(true);
	tg_plat_random(&r, 1);
	tg_arm(T_MLE, r % 50u); /* kAttachStartJitter */
	tg_plat_changed();
}

static void send_preq(bool reeds)
{
	static const uint8_t all_routers[16] = {0xffu, 0x02u, [15] = 2u};
	uint8_t m[64], *p = begin(m, C_PREQ);

	tg_plat_random(tg.chal, 8);
	p = put8(p, T_MODE, mode_byte());
	p = put(p, T_CHAL, tg.chal, 8);
	p = put8(p, T_SCAN, reeds ? 0xc0u : 0x80u);
	p = put16t(p, T_VERSION, VERSION);
	tg.cand.valid = false;
	tg.ast = reeds ? A_PREQ_RE : A_PREQ_R;
	tg_arm(T_MLE, reeds ? PREQ_RE_MS : PREQ_R_MS);
	(void)finish(m, p, all_routers);
}

static void send_cidreq(void)
{
	static const uint8_t req[2] = {T_ADDR16, T_NETDATA};
	uint8_t m[112], *p = begin(m, C_CIDREQ), dst[16];

	p = put(p, T_RESP, tg.cand.chal, tg.cand.chal_len);
	p = put32t(p, T_LFC, tg.mac_fc);
	p = put32t(p, T_MFC, tg.mle_fc);
	p = put8(p, T_MODE, mode_byte());
	p = put32t(p, T_TIMEOUT, TG_CHILD_TIMEOUT_S);
	p = put16t(p, T_VERSION, VERSION);
	p = areg(p, false); /* short enough not to need fragmenting */
	p = put(p, T_TLVREQ, req, 2);
	if (tg.have_ats) {
		p = put(p, T_ATS, tg.ats, 8);
	}
	tg_lladdr(dst, tg.cand.ext);
	tg.ast = A_CIDREQ;
	tg_arm(T_MLE, CIDRSP_MS);
	(void)finish(m, p, dst);
	if (POLL_MS) { /* a sleepy child's answer waits for its poll */
		tg.fast_polls = 12;
		tg_arm(T_POLL, 100);
	}
}

static void send_cupd(void)
{
	uint8_t m[96], *p = begin(m, C_CUREQ), dst[16];

	p = put8(p, T_MODE, mode_byte());
	p = put(p, T_LEADER, leader_raw, 8);
	p = areg(p, true);
	p = put32t(p, T_TIMEOUT, TG_CHILD_TIMEOUT_S);
	tg_lladdr(dst, tg.par.ext);
	if (tg.ast != A_CUPD) {
		tg.cupd_tries = 0;
	}
	tg.ast = A_CUPD;
	tg_arm(T_MLE, RETX_MS);
	(void)finish(m, p, dst);
	sed_expect_reply();
}

static void send_dreq(void)
{
	static const uint8_t req[1] = {T_NETDATA};
	uint8_t m[48], *p = begin(m, C_DREQ), dst[16];

	p = put(p, T_TLVREQ, req, 1);
	if (tg.have_ats) {
		p = put(p, T_ATS, tg.ats, 8);
	}
	tg_lladdr(dst, tg.par.ext);
	(void)finish(m, p, dst);
	sed_expect_reply();
}

static void keepalive_later(void)
{
	tg.ast = A_CHILD;
	tg_arm(T_MLE, TG_CHILD_TIMEOUT_S * 1000u - RETX_MS * KEEPALIVE_TRIES);
}

void tg_mle_timer(void)
{
	switch (tg.ast) {
	case A_IDLE:
		send_preq(false);
		break;
	case A_PREQ_R:
	case A_PREQ_RE:
		if (tg.cand.valid) {
			send_cidreq();
		} else if (tg.ast == A_PREQ_R) {
			send_preq(true);
		} else {
			backoff();
		}
		break;
	case A_CIDREQ:
		backoff();
		break;
	case A_CHILD:
		send_cupd();
		break;
	default: /* A_CUPD */
		if (++tg.cupd_tries >= KEEPALIVE_TRIES) {
			tg_mle_start(); /* the parent is gone */
		} else {
			send_cupd();
		}
		break;
	}
}

void tg_mle_tx_failed(void)
{
	if (tg.role == TG_CHILD && ++tg.txfail >= 3u && tg.ast == A_CHILD) {
		send_cupd(); /* is the parent still there? */
	}
}

void tg_mle_poll_failed(void)
{
	if (tg.role == TG_CHILD && ++tg.txfail >= KEEPALIVE_TRIES) {
		tg_mle_start();
	}
}

/* ---- network data ------------------------------------------------------ */

void tg_mle_netdata(const uint8_t *nd, uint8_t len)
{
	uint8_t omr[8], srp[16], best = 4, aseq = 0;
	uint16_t sport = 0;
	bool had = tg.have_omr, new_omr = false;

	memcpy(omr, tg.omr, 8);
	tg.nctx = 0;
	tg.have_omr = false;
	for (uint16_t i = 0; i + 2u <= len && i + 2u + nd[i + 1] <= len; i += 2u + nd[i + 1]) {
		uint8_t type = nd[i] >> 1, l = nd[i + 1];
		const uint8_t *v = nd + i + 2;

		if (!(nd[i] & 1u)) {
			continue; /* this child keeps stable data only */
		}
		if (type == 1u && l >= 2u && v[1] == 64u && l >= 10u) { /* Prefix, /64 */
			const uint8_t *s = v + 10;

			for (uint8_t k = 10; k + 2u <= l && k + 2u + s[1] <= l; k += 2u + s[1], s = v + k) {
				uint8_t st = s[0] >> 1, sl = s[1];

				if (!(s[0] & 1u)) {
					continue;
				}
				if (st == 3u && sl >= 2u && s[3] == 64u && tg.nctx < TG_CONTEXTS) {
					tg.ctx[tg.nctx].id = s[2] & 0x0fu;
					memcpy(tg.ctx[tg.nctx].prefix, v + 2, 8);
					tg.nctx++;
				}
				for (uint8_t e = 0; st == 2u && e + 4u <= sl; e += 4u) {
					uint16_t fl = get16(s + 2 + e + 2);

					if (!tg.have_omr && (fl & BR_SLAAC) && (fl & BR_ON_MESH) &&
					    (fl & BR_PREFERRED)) {
						memcpy(tg.omr, v + 2, 8);
						tg.have_omr = true;
					}
				}
			}
		} else if (type == 5u && l >= 3u && (v[0] & 0x80u)) { /* Thread service */
			uint8_t sid = v[0] & 0x0fu, sdl = v[1];
			const uint8_t *sd = v + 2;

			if (2u + sdl > l || sdl == 0u) {
				continue;
			}
			if (sd[0] == 0x5du && sdl >= 19u && best > 1u) {
				/* unicast, address in service data: preferred */
				memcpy(srp, sd + 1, 16);
				sport = get16(sd + 17);
				best = 1;
			} else if (sd[0] == 0x5cu && sdl >= 2u && best >= 2u &&
				   (best > 2u || (int8_t)(sd[1] - aseq) > 0)) {
				static const uint8_t aloc[6] = {0, 0, 0, 0xffu, 0xfeu, 0};

				memcpy(srp, tg.mlp, 8);
				memcpy(srp + 8, aloc, 6);
				put16(srp + 14, (uint16_t)(0xfc10u + sid));
				sport = 53;
				aseq = sd[1];
				best = 2;
			} else if (sd[0] == 0x5du && best > 3u) {
				/* unicast, address in some server's data */
				for (uint8_t k = (uint8_t)(2u + sdl); k + 2u <= l; k += 2u + v[k + 1]) {
					if ((v[k] >> 1) == 6u && v[k + 1] >= 20u) {
						memcpy(srp, v + k + 4, 16);
						sport = get16(v + k + 20);
						best = 3;
						break;
					}
				}
			}
		}
	}
	new_omr = tg.have_omr != had || (tg.have_omr && memcmp(omr, tg.omr, 8) != 0);
	if (best < 4u && (!tg.have_srp || sport != tg.srp_port || memcmp(srp, tg.srp_addr, 16))) {
		memcpy(tg.srp_addr, srp, 16);
		tg.srp_port = sport;
		tg.have_srp = true;
		tg_srp_kick(0);
	} else if (best == 4u) {
		tg.have_srp = false;
	}
	tg.have_nd = true;
	if (new_omr) {
		tg.omr_reg = false;
		if (tg.role == TG_CHILD) {
			send_cupd(); /* register the new address with the parent */
		}
		tg_plat_changed();
	}
}

/* Leader Data in any message from the parent; true if Network Data rode along. */
static void leader_seen(const uint8_t *const *v)
{
	const uint8_t *ld = v[T_LEADER], *nd = v[T_NETDATA];

	if (ld == NULL) {
		return;
	}
	if (nd != NULL) {
		tg.sver = ld[6];
		tg.part = get32(ld);
		memcpy(leader_raw, ld, 8);
		tg_mle_netdata(nd, tlv_len(nd));
	} else if (!tg.have_nd || get32(ld) != tg.part || (int8_t)(ld[6] - tg.sver) > 0) {
		send_dreq();
	}
}

/* ---- receive ----------------------------------------------------------- */

static void on_prsp(const uint8_t ext[8], const uint8_t *const *v, uint32_t ks)
{
	const uint8_t *resp = v[T_RESP], *src = v[T_SRC], *ver = v[T_VERSION], *ld = v[T_LEADER],
		      *lm = v[T_MARGIN], *conn = v[T_CONN], *lfc = v[T_LFC], *mfc = v[T_MFC],
		      *chal = v[T_CHAL];
	int margin = tg.rssi - NOISE_FLOOR;
	int8_t prio;

	if ((tg.ast != A_PREQ_R && tg.ast != A_PREQ_RE) || !resp || memcmp(resp, tg.chal, 8) ||
	    !src || !ver || get16(ver) < VERSION || !ld || !lm || !conn || !lfc || !chal ||
	    tlv_len(chal) > 8u) {
		return;
	}
	if (margin < 0) {
		margin = 0;
	}
	if (margin > lm[0]) {
		margin = lm[0]; /* two-way: the worse direction */
	}
	prio = (int8_t)((int8_t)conn[0] >> 6);
	if (tg.cand.valid && (prio < tg.cand.prio || (prio == tg.cand.prio && margin <= tg.cand.margin))) {
		return;
	}
	memcpy(tg.cand.ext, ext, 8);
	tg.cand.rloc = get16(src);
	tg.cand.mac_fc = get32(lfc);
	tg.cand.mle_fc = get32(mfc ? mfc : lfc);
	tg.cand.kseq = ks;
	tg.cand.prio = prio;
	tg.cand.margin = (uint8_t)margin;
	tg.cand.chal_len = tlv_len(chal);
	memcpy(tg.cand.chal, chal, tg.cand.chal_len);
	tg.cand.valid = true;
	if (ks > tg.kseq) {
		tg_set_kseq(ks); /* a Parent Response is authoritative */
	}
}

static void on_cidrsp(const uint8_t ext[8], const uint8_t *const *v, uint32_t ks, uint32_t fc)
{
	const uint8_t *src = v[T_SRC], *a16 = v[T_ADDR16], *ld = v[T_LEADER], *nd = v[T_NETDATA];

	if (tg.ast != A_CIDREQ || memcmp(ext, tg.cand.ext, 8) || !src || !a16 || !ld || !nd ||
	    (get16(src) >> 10) != (get16(a16) >> 10) || ks < tg.cand.kseq ||
	    (ks == tg.cand.kseq && fc < tg.cand.mle_fc)) {
		return;
	}
	if (ks > tg.kseq) {
		tg_set_kseq(ks);
	}
	tg.par = tg.cand;
	tg.par.rloc = get16(src);
	tg.par.kseq = ks;
	tg.par.mle_fc = fc + 1u;
	tg.cand.valid = false;
	tg.rloc = get16(a16);
	tg.role = TG_CHILD;
	tg.tries = 0;
	tg.txfail = 0;
	tg_plat_radio_set(tg.chan, tg.pan, tg.rloc, tg.ext);
	if (POLL_MS) {
		tg_plat_radio_rx(false);
		tg.fast_polls = 0;
		tg_arm(T_POLL, POLL_MS);
	}
	tg.sver = ld[6];
	tg.part = get32(ld);
	memcpy(leader_raw, ld, 8);
	tg.have_omr = false;
	tg_mle_netdata(nd, tlv_len(nd)); /* registers an off-mesh address if any */
	if (tg.ast != A_CUPD) {
		keepalive_later();
	}
	tg_plat_changed();
}

static void on_cursp(const uint8_t *const *v)
{
	if (v[T_STATUS]) {
		tg_mle_start(); /* not this parent's child any more */
		return;
	}
	if (tg.ast == A_CUPD) {
		bool was = tg.omr_reg;

		tg.omr_reg = tg.have_omr;
		keepalive_later();
		if (tg.omr_reg && !was) {
			tg_srp_kick(0);
			tg_plat_changed();
		}
	}
	tg.txfail = 0;
	leader_seen(v);
}

static void on_cureq(const uint8_t *const *v)
{
	const uint8_t *chal = v[T_CHAL];
	uint8_t m[112], *p = begin(m, C_CURSP), dst[16];

	if (v[T_STATUS]) {
		tg_mle_start();
		return;
	}
	leader_seen(v);
	p = put16t(p, T_SRC, tg.rloc);
	p = put8(p, T_MODE, mode_byte());
	p = put(p, T_LEADER, leader_raw, 8);
	p = areg(p, true);
	p = put32t(p, T_TIMEOUT, TG_CHILD_TIMEOUT_S);
	if (chal && tlv_len(chal) <= 8u) {
		p = put(p, T_RESP, chal, tlv_len(chal));
		p = put32t(p, T_LFC, tg.mac_fc);
		p = put32t(p, T_MFC, tg.mle_fc);
	}
	tg_lladdr(dst, tg.par.ext);
	(void)finish(m, p, dst);
}

void tg_mle_rx(const uint8_t src[16], const uint8_t dst[16], uint8_t *m, uint16_t n)
{
	uint8_t ext[8], a[42], nonce[13], mk[16], ak[16];
	const uint8_t *key = tg.mle_key, *v[TLV_N];
	uint32_t fc, ks;
	bool from_par;

	if (tg.role == TG_DISABLED || n < 17u || m[0] != 0u || m[1] != 0x15u) {
		return;
	}
	fc = le32(m + 2);
	ks = get32(m + 6);
	memcpy(ext, src + 8, 8);
	ext[0] ^= 0x02u;
	if (ks != tg.kseq) {
		tg_keys(ks, mk, ak);
		key = mk;
	}
	memcpy(a, src, 16);
	memcpy(a + 16, dst, 16);
	memcpy(a + 32, m + 1, 10);
	tg_nonce(nonce, ext, fc);
	if (tg_ccm(key, nonce, a, sizeof(a), m + 11, (size_t)(n - 15u), m + n - 4, false) != 0) {
		return;
	}
	n = (uint16_t)(n - 16u);
	from_par = tg.role == TG_CHILD && memcmp(ext, tg.par.ext, 8) == 0;
	if (from_par) {
		if (ks < tg.par.kseq || (ks == tg.par.kseq && fc < tg.par.mle_fc)) {
			return; /* replayed */
		}
		if (ks != tg.par.kseq) {
			tg.par.kseq = ks;
			tg.par.mac_fc = 0;
		}
		tg.par.mle_fc = fc + 1u;
		if (ks == tg.kseq + 1u) {
			tg_set_kseq(ks);
		}
	}
	tlvs(m + 12, n, v);
	switch (m[11]) {
	case C_PRSP:
		on_prsp(ext, v, ks);
		return;
	case C_CIDRSP:
		on_cidrsp(ext, v, ks, fc);
		return;
	default:
		break;
	}
	if (!from_par) {
		return;
	}
	switch (m[11]) {
	case C_CURSP:
		on_cursp(v);
		break;
	case C_CUREQ:
		on_cureq(v);
		break;
	case C_DRSP:
	case C_ADV:
		leader_seen(v);
		break;
	default:
		break;
	}
}
