/* SPDX-License-Identifier: ISC */
/*
 * IEEE 802.15.4 framing for a Thread child: 2006 frames, security level 5 with
 * key id mode 1, a ring of frames that are built and secured when queued, and
 * the data polls of a sleepy child.
 *
 * Frames go only to the parent or to broadcast, so the only secured sender
 * this ever has to verify is the parent.
 */
#include "tg_int.h"

#define PSDU_MAX 125u   /* 127 less the FCS */
#define RETRIES 3u      /* macMaxFrameRetries */
#define RX_WINDOW_MS 100u
#define FAST_POLL_MS 100u

#define FCF_SEC 0x0008u
#define FCF_PENDING 0x0010u
#define FCF_ACKREQ 0x0020u
#define FCF_PANC 0x0040u

struct txf {
	uint8_t len, tries;
	uint16_t tag; /* frames of one datagram share it; 0 for a poll */
	uint8_t f[PSDU_MAX];
};

static struct txf q[TG_TX_FRAMES];
static uint8_t q_head, q_n, seq;
static bool q_busy;
static uint16_t tag_next = 1;

void tg_mac_reset(void)
{
	q_n = q_busy ? 1u : 0u; /* the frame on air finishes on its own */
	tg.rx_window = false;
	tg.fast_polls = 0;
}

static void kick(void)
{
	if (!q_busy && q_n) {
		q_busy = true;
		if (tg_plat_radio_tx(q[q_head].f, q[q_head].len) != 0) {
			tg_radio_tx_done(TG_TX_BUSY, false);
		}
	}
}

static struct txf *slot(void)
{
	struct txf *t = &q[(q_head + q_n) % TG_TX_FRAMES];

	q_n++;
	t->tries = 0;
	return t;
}

/* The MAC header, auxiliary security header included. */
static uint8_t mhr(uint8_t *f, uint8_t type, const struct tg_maddr *dst, bool src_ext, bool sec,
		   uint32_t *fc)
{
	uint16_t fcf = type | FCF_PANC;
	uint8_t i = 5;

	if (!(dst->mode == 2 && dst->s == 0xffffu)) {
		fcf |= FCF_ACKREQ;
	}
	fcf |= dst->mode == 3 ? 0x0c00u : 0x0800u;
	fcf |= src_ext ? 0xc000u : 0x8000u;
	if (sec) {
		fcf |= FCF_SEC | 0x1000u; /* 2006 */
	}
	putle16(f, fcf);
	f[2] = seq++;
	putle16(f + 3, tg.pan);
	if (dst->mode == 3) {
		rev8(f + i, dst->e);
		i += 8;
	} else {
		putle16(f + i, dst->s);
		i += 2;
	}
	if (src_ext) {
		rev8(f + i, tg.ext);
		i += 8;
	} else {
		putle16(f + i, tg.rloc);
		i += 2;
	}
	if (sec) {
		*fc = tg_mac_fc_next();
		f[i] = 0x0d; /* level 5, key id mode 1 */
		putle32(f + i + 1, *fc);
		f[i + 5] = (uint8_t)((tg.kseq & 0x7fu) + 1u);
		i += 6;
	}
	return i;
}

static uint8_t seal(uint8_t *f, uint8_t hdr, uint8_t len, uint32_t fc)
{
	uint8_t n[13];

	tg_nonce(n, tg.ext, fc);
	(void)tg_ccm(tg.mac_key, n, f, hdr, f + hdr, (size_t)(len - hdr), f + len, true);
	return (uint8_t)(len + 4u);
}

static void sed_traffic(void)
{
	if (POLL_MS && tg.role == TG_CHILD) {
		tg.fast_polls = 5;
		tg_arm(T_POLL, FAST_POLL_MS);
	}
}

int tg_mac_send(const uint8_t *hdr, uint8_t hlen, const uint8_t *data, uint16_t dlen,
		uint16_t total, const struct tg_maddr *dst, bool src_ext, bool secure)
{
	uint32_t fc = 0;
	uint8_t mh = (uint8_t)(5u + (dst->mode == 3u ? 8u : 2u) + (src_ext ? 8u : 2u));
	uint8_t cap = (uint8_t)(PSDU_MAX - mh - (secure ? 10u : 0u));
	uint16_t uhdr = (uint16_t)(total - dlen); /* uncompressed bytes hdr stands for */
	uint16_t first, chunk, nfr, off;
	uint16_t tag = tag_next++;

	if (tag == 0u) {
		tag = tag_next++;
	}
	if (hlen + dlen <= cap) {
		struct txf *t;

		if (q_n == TG_TX_FRAMES) {
			return TG_E_BUSY;
		}
		t = slot();
		t->tag = tag;
		mh = mhr(t->f, 1, dst, src_ext, secure, &fc);
		memcpy(t->f + mh, hdr, hlen);
		memcpy(t->f + mh + hlen, data, dlen);
		t->len = (uint8_t)(mh + hlen + dlen);
		if (secure) {
			t->len = seal(t->f, mh, t->len, fc);
		}
		kick();
		sed_traffic();
		return TG_OK;
	}

	/* RFC 4944 fragments: offsets count uncompressed bytes in units of 8. */
	if (hlen + 12u > cap) {
		return TG_E_INVAL;
	}
	first = (uint16_t)(((uhdr + cap - 4u - hlen) & ~7u) - uhdr);
	chunk = (uint16_t)((cap - 5u) & ~7u);
	nfr = (uint16_t)(1u + (dlen - first + chunk - 1u) / chunk);
	if (nfr > TG_TX_FRAMES - q_n) {
		return TG_E_BUSY;
	}
	for (off = 0; off < dlen;) {
		struct txf *t = slot();
		uint8_t *p;
		uint16_t n;

		t->tag = tag;
		mh = mhr(t->f, 1, dst, src_ext, secure, &fc);
		p = t->f + mh;
		if (off == 0u) {
			put16(p, (uint16_t)(0xc000u | total));
			put16(p + 2, tag);
			memcpy(p + 4, hdr, hlen);
			p += 4u + hlen;
			n = first;
		} else {
			put16(p, (uint16_t)(0xe000u | total));
			put16(p + 2, tag);
			p[4] = (uint8_t)((uhdr + off) / 8u);
			p += 5;
			n = (uint16_t)(dlen - off < chunk ? dlen - off : chunk);
		}
		memcpy(p, data + off, n);
		p += n;
		off = (uint16_t)(off + n);
		t->len = (uint8_t)(p - t->f);
		if (secure) {
			t->len = seal(t->f, mh, t->len, fc);
		}
	}
	kick();
	sed_traffic();
	return TG_OK;
}

#if TG_SED
void tg_mac_poll(void)
{
	struct tg_maddr dst = {.mode = 2};
	struct txf *t;
	uint32_t fc;
	uint8_t mh;

	for (uint8_t i = 0; i < q_n; i++) {
		if (q[(q_head + i) % TG_TX_FRAMES].tag == 0u) {
			return; /* one already waiting */
		}
	}
	if (q_n == TG_TX_FRAMES) {
		return;
	}
	dst.s = tg.role == TG_CHILD ? tg.par.rloc : tg.cand.rloc;
	t = slot();
	t->tag = 0;
	mh = mhr(t->f, 3, &dst, tg.role != TG_CHILD, true, &fc);
	t->f[mh] = 0x04; /* Data Request; authenticated as header in a 2006 frame */
	t->len = seal(t->f, (uint8_t)(mh + 1u), (uint8_t)(mh + 1u), fc);
	kick();
}

static void window_open(void)
{
	tg.rx_window = true;
	tg_plat_radio_rx(true);
	tg_arm(T_POLL, RX_WINDOW_MS);
}

static void next_poll(void)
{
	uint32_t ms = POLL_MS;

	if (tg.fast_polls) {
		tg.fast_polls--;
		ms = FAST_POLL_MS;
	}
	tg_arm(T_POLL, ms);
}

void tg_mac_timer_poll(void)
{
	if (tg.rx_window) {
		tg.rx_window = false;
		if (tg.role == TG_CHILD) {
			tg_plat_radio_rx(false);
		}
	} else if (tg.role == TG_CHILD || tg.ast == A_CIDREQ) {
		tg_mac_poll();
	} else {
		return;
	}
	if (tg.role == TG_CHILD || tg.fast_polls) {
		next_poll();
	}
}
#else
void tg_mac_poll(void) {}
static void window_open(void) {}
static void next_poll(void) {}
#endif

void tg_radio_tx_done(int res, bool pending)
{
	struct txf *t = &q[q_head];
	bool ackreq = (le16(t->f) & FCF_ACKREQ) != 0u;
	uint16_t tag = t->tag;

	if (!q_busy) {
		return;
	}
	q_busy = false;
	if (res != TG_TX_OK && t->tries++ < RETRIES) {
		kick();
		return;
	}
	q_head = (uint8_t)((q_head + 1u) % TG_TX_FRAMES);
	q_n--;
	if (res != TG_TX_OK) {
		while (tag && q_n && q[q_head].tag == tag) {
			q_head = (uint8_t)((q_head + 1u) % TG_TX_FRAMES);
			q_n--;
		}
		if (ackreq) {
			if (tag) {
				tg_mle_tx_failed();
			} else {
				tg_mle_poll_failed();
			}
		}
	} else if (ackreq) {
		tg.txfail = 0;
		if (POLL_MS && pending && tg.role == TG_CHILD) {
			window_open();
		}
	}
	kick();
}

void tg_radio_rx(const uint8_t *in, uint8_t len, int8_t rssi)
{
	uint8_t f[PSDU_MAX];
	struct tg_maddr src = {0}, dst = {0};
	uint16_t fcf;
	uint8_t i = 3, ver, type, hdr, kidx = 0;
	uint32_t fc = 0;
	bool dpan = true, span, sec;

	if (len < 9u || len > PSDU_MAX) {
		return;
	}
	memcpy(f, in, len);
	fcf = le16(f);
	type = fcf & 7u;
	ver = (fcf >> 12) & 3u;
	dst.mode = (fcf >> 10) & 3u;
	src.mode = (fcf >> 14) & 3u;
	/* Header IEs are never sent to a Thread 1.1 child; neither is a frame
	 * without both addresses. */
	if ((type != 1u && type != 3u) || ver > 2u || (fcf & 0x0200u) || dst.mode < 2u ||
	    src.mode < 2u) {
		return;
	}
	if (ver == 2u && (fcf & 0x0100u)) {
		i = 2; /* sequence number suppressed */
	}
	span = !(fcf & FCF_PANC);
	if (ver == 2u && dst.mode == 3u && src.mode == 3u) {
		dpan = span;
		span = false;
	}
	/* The radio matched the PAN ID and destination (tg_plat_radio_set());
	 * the destination is kept for the IIDs 6LoWPAN derives from it. */
	if (dpan) {
		i += 2;
	}
	if (dst.mode == 2u) {
		dst.s = le16(f + i);
		i += 2;
	} else {
		rev8(dst.e, f + i);
		i += 8;
	}
	if (span) {
		i += 2;
	}
	if (src.mode == 2u) {
		src.s = le16(f + i);
		i += 2;
	} else {
		rev8(src.e, f + i);
		i += 8;
	}
	sec = (fcf & FCF_SEC) != 0u;
	if (sec) {
		if (i + 6u > len || f[i] != 0x0du) {
			return;
		}
		fc = le32(f + i + 1);
		kidx = f[i + 5];
		i += 6;
	}
	hdr = (uint8_t)(i + (type == 3u && ver < 2u));
	if (hdr + (sec ? 4u : 0u) > len) {
		return;
	}
	if (sec) {
		/* The parent, or while attaching the candidate: a Child ID
		 * Response too big for one frame arrives fragmented and secured. */
		struct tg_nbr *nb = tg.role == TG_CHILD ? &tg.par : tg.ast == A_CIDREQ ? &tg.cand : NULL;
		const uint8_t *from = src.mode == 3u ? src.e : nb ? nb->ext : NULL;
		uint8_t mle[16], mac[16], n[13];
		const uint8_t *key = tg.mac_key;
		uint32_t ks = tg.kseq;

		if (nb == NULL || (src.mode == 2u && src.s != nb->rloc) || memcmp(from, nb->ext, 8) != 0) {
			return;
		}
		if (kidx != (uint8_t)((ks & 0x7fu) + 1u)) {
			ks = kidx == (uint8_t)(((ks + 1u) & 0x7fu) + 1u) ? ks + 1u : ks - 1u;
			if (kidx != (uint8_t)((ks & 0x7fu) + 1u)) {
				return;
			}
			tg_keys(ks, mle, mac);
			key = mac;
		}
		tg_nonce(n, from, fc);
		len -= 4u;
		if (tg_ccm(key, n, f, hdr, f + hdr, (size_t)(len - hdr), f + len, false) != 0) {
			return;
		}
		if (ks < nb->kseq || (ks == nb->kseq && fc < nb->mac_fc)) {
			return; /* replayed */
		}
		nb->kseq = ks;
		nb->mac_fc = fc + 1u;
		if (nb == &tg.par && ks == tg.kseq + 1u) {
			tg_set_kseq(ks); /* the parent switched keys first */
		}
	}
	if (type == 3u) {
		return; /* nothing a child needs from MAC commands */
	}
	if (sec && POLL_MS) {
		if (fcf & FCF_PENDING) {
			tg.rx_window = false;
			tg_mac_poll();
		} else if (tg.rx_window) {
			tg.rx_window = false;
			tg_plat_radio_rx(false);
			next_poll();
		}
	}
	tg.rssi = rssi;
	tg_lowpan_rx(f + hdr, (uint8_t)(len - hdr), &src, &dst, sec);
}
