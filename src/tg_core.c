/* SPDX-License-Identifier: ISC */
/*
 * The stack's state, its deadlines, the dataset, keys and the persisted
 * counters.
 */
#include "tg_int.h"

struct tg_state tg;

/* What survives a reboot besides the dataset. */
struct tg_nv {
	uint8_t ext[8], iid[8];
	uint32_t kseq, mac_fc, mle_fc;
	uint8_t ktag[4]; /* which network key the counters ran under */
};

void tg_arm(uint8_t t, uint32_t ms)
{
	tg.due[t] = tg_plat_now() + ms;
	tg.armed |= (uint8_t)(1u << t);
}

void tg_disarm(uint8_t t)
{
	tg.armed &= (uint8_t)~(1u << t);
}

void tg_save_state(void)
{
	struct tg_nv nv;

	memcpy(nv.ext, tg.ext, 8);
	memcpy(nv.iid, tg.iid, 8);
	nv.kseq = tg.kseq;
	nv.mac_fc = tg.mac_fc_nv;
	nv.mle_fc = tg.mle_fc_nv;
	memcpy(nv.ktag, tg.ktag, 4);
	(void)tg_plat_save(TG_KV_STATE, &nv, sizeof(nv));
}

/* A counter is persisted TG_FC_AHEAD past its use, so a reboot never reuses one. */
uint32_t tg_mac_fc_next(void)
{
	uint32_t fc = tg.mac_fc++;

	if (tg.mac_fc >= tg.mac_fc_nv) {
		tg.mac_fc_nv = tg.mac_fc + TG_FC_AHEAD;
		tg_save_state();
	}
	return fc;
}

uint32_t tg_mle_fc_next(void)
{
	uint32_t fc = tg.mle_fc++;

	if (tg.mle_fc >= tg.mle_fc_nv) {
		tg.mle_fc_nv = tg.mle_fc + TG_FC_AHEAD;
		tg_save_state();
	}
	return fc;
}

/* MLE key || MAC key = HMAC-SHA-256(network key, key sequence || "Thread"). */
void tg_keys(uint32_t kseq, uint8_t mle[16], uint8_t mac[16])
{
	uint8_t m[10], h[32];

	put32(m, kseq);
	memcpy(m + 4, "Thread", 6);
	tg_plat_hmac(tg.key, m, sizeof(m), h);
	memcpy(mle, h, 16);
	memcpy(mac, h + 16, 16);
}

/* A new key sequence starts both frame counters again (as OpenThread does). */
void tg_set_kseq(uint32_t kseq)
{
	tg.kseq = kseq;
	tg_keys(kseq, tg.mle_key, tg.mac_key);
	tg.mac_fc = 0;
	tg.mle_fc = 0;
	tg.mac_fc_nv = TG_FC_AHEAD;
	tg.mle_fc_nv = TG_FC_AHEAD;
	tg_save_state();
}

struct ds {
	uint8_t chan;
	uint16_t pan;
	uint8_t xpan[8], key[16], mlp[8], ats[8];
	bool have_ats;
};

/* The meshcop TLVs this node needs; the rest ride along unread. */
static int parse(const uint8_t *d, size_t len, struct ds *o)
{
	uint8_t have = 0;

	o->have_ats = false;
	for (size_t i = 0; i + 2u <= len; i += 2u + d[i + 1]) {
		const uint8_t *v = d + i + 2;
		uint8_t l = d[i + 1];

		if (i + 2u + l > len) {
			return TG_E_INVAL;
		}
		switch (d[i]) {
		case 0: /* channel: page, then channel */
			if (l == 3u && v[0] == 0u && get16(v + 1) >= 11u && get16(v + 1) <= 26u) {
				o->chan = v[2];
				have |= 1u;
			}
			break;
		case 1:
			if (l == 2u) {
				o->pan = get16(v);
				have |= 2u;
			}
			break;
		case 2:
			if (l == 8u) {
				memcpy(o->xpan, v, 8);
				have |= 4u;
			}
			break;
		case 5:
			if (l == 16u) {
				memcpy(o->key, v, 16);
				have |= 8u;
			}
			break;
		case 7:
			if (l == 8u) {
				memcpy(o->mlp, v, 8);
				have |= 16u;
			}
			break;
		case 14:
			if (l == 8u) {
				memcpy(o->ats, v, 8);
				o->have_ats = true;
			}
			break;
		default:
			break;
		}
	}
	return have == 31u ? TG_OK : TG_E_INVAL;
}

static void adopt(const uint8_t *d, size_t len, const struct ds *o)
{
	uint8_t mle[16], tag[16];
	bool new_key;

	/* The key's fingerprint: four bytes of its sequence-0 MAC key. */
	memcpy(tg.key, o->key, 16);
	tg_keys(0, mle, tag);
	new_key = memcmp(tag, tg.ktag, 4) != 0;
	memcpy(tg.ktag, tag, 4);

	tg.chan = o->chan;
	tg.pan = o->pan;
	memcpy(tg.xpan, o->xpan, 8);
	memcpy(tg.key, o->key, 16);
	memcpy(tg.mlp, o->mlp, 8);
	memcpy(tg.ats, o->ats, 8);
	tg.have_ats = o->have_ats;
	tg.ds_len = (uint8_t)len;
	if (new_key) {
		/* Counters may start over only under a key they never ran under;
		 * and a new network's key sequence is learned from its parent. */
		tg_set_kseq(0);
	} else {
		tg_keys(tg.kseq, tg.mle_key, tg.mac_key);
	}
}

int tg_init(uint32_t poll_ms)
{
	struct tg_nv nv;

	memset(&tg, 0, sizeof(tg));
	tg.poll_ms = poll_ms;
	tg.rloc = 0xfffeu;
	if (tg_plat_load(TG_KV_STATE, &nv, sizeof(nv)) == (int)sizeof(nv)) {
		memcpy(tg.ext, nv.ext, 8);
		memcpy(tg.iid, nv.iid, 8);
		tg.kseq = nv.kseq;
		tg.mac_fc = tg.mac_fc_nv = nv.mac_fc;
		tg.mle_fc = tg.mle_fc_nv = nv.mle_fc;
		memcpy(tg.ktag, nv.ktag, 4);
	} else {
		tg_plat_random(tg.ext, 8);
		tg.ext[0] = (uint8_t)((tg.ext[0] | 0x02u) & ~0x01u); /* local, unicast */
		tg_plat_random(tg.iid, 8);
		tg.mac_fc_nv = tg.mle_fc_nv = TG_FC_AHEAD;
		tg_save_state();
	}
	return TG_OK;
}

int tg_start(const uint8_t *d, size_t len)
{
	struct ds o;

	memset(&o, 0, sizeof(o));
	if (len > TG_DATASET_MAX || parse(d, len, &o) != TG_OK) {
		return TG_E_INVAL;
	}
	adopt(d, len, &o);
	tg_mle_start();
	return TG_OK;
}

void tg_clear(void)
{
	tg.role = TG_DISABLED;
	tg.ds_len = 0;
	/* A removal outlives the detach: the SRP timer stays armed, finds no
	 * parent, and the removal goes once there is one again. */
	tg.armed = tg_srp_pending() ? (uint8_t)(tg.armed & (1u << T_SRP)) : 0u;
	tg.have_omr = tg.have_srp = tg.omr_reg = false;
	tg_mac_reset();
	tg_plat_radio_rx(false);
	tg_plat_changed();
}

enum tg_role tg_role(void)
{
	return (enum tg_role)tg.role;
}

bool tg_ready(void)
{
	return tg.role == TG_CHILD && tg.have_omr && tg.omr_reg;
}

const uint8_t *tg_xpanid(void)
{
	return tg.ds_len ? tg.xpan : NULL;
}

bool tg_omr(uint8_t out[16])
{
	if (tg.role != TG_CHILD || !tg.have_omr) {
		return false;
	}
	memcpy(out, tg.omr, 8);
	memcpy(out + 8, tg.iid, 8);
	return true;
}

bool tg_mleid(uint8_t out[16])
{
	if (!tg.ds_len) {
		return false;
	}
	tg_mladdr(out, tg.iid);
	return true;
}

uint32_t tg_process(void)
{
	uint32_t now = tg_plat_now(), next = UINT32_MAX;

	for (uint8_t t = 0; t < T_N; t++) {
		if ((tg.armed & (1u << t)) && (int32_t)(tg.due[t] - now) <= 0) {
			tg_disarm(t);
			switch (t) {
			case T_MLE:
				tg_mle_timer();
				break;
#if TG_SED
			case T_POLL:
				tg_mac_timer_poll();
				break;
#endif
			case T_REASM:
				tg_reasm_timeout();
				break;
#if TG_DNS
			case T_DNS:
				tg_dns_timer();
				break;
#endif
			default:
				tg_srp_timer();
				break;
			}
		}
	}
	now = tg_plat_now();
	for (uint8_t t = 0; t < T_N; t++) {
		if (tg.armed & (1u << t)) {
			int32_t d = (int32_t)(tg.due[t] - now);
			uint32_t w = d < 0 ? 0u : (uint32_t)d;

			next = w < next ? w : next;
		}
	}
	return next;
}
