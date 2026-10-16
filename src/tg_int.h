/* SPDX-License-Identifier: ISC */
/* tinygrid internals: the one state struct and the calls between layers. */
#pragma once

#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <string.h>

#ifndef TG_TX_FRAMES
/* A 1,232 B datagram is 13 fragments; three more for MLE and SRP alongside. */
#define TG_TX_FRAMES 16
#endif
#ifndef TG_CHILD_TIMEOUT_S
#define TG_CHILD_TIMEOUT_S 240u
#endif
#define TG_CONTEXTS 4
#define TG_PKT_MAX 1280u
#define TG_DATASET_MAX 254u
#define TG_MLE_PORT 19788u
#define TG_FC_AHEAD 1000u /* frame counters are persisted this far ahead */

static inline uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}
static inline void put32(uint8_t *p, uint32_t v)
{
	put16(p, (uint16_t)(v >> 16));
	put16(p + 2, (uint16_t)v);
}
static inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
static inline uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p + 2) << 16 | le16(p); }
static inline void putle16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}
static inline void putle32(uint8_t *p, uint32_t v)
{
	putle16(p, (uint16_t)v);
	putle16(p + 2, (uint16_t)(v >> 16));
}
/* On air an extended address is little-endian; everywhere else canonical. */
static inline void rev8(uint8_t *d, const uint8_t *s)
{
	for (int i = 0; i < 8; i++) {
		d[i] = s[7 - i];
	}
}

/* Deadlines, one each. */
enum { T_MLE, T_POLL, T_REASM, T_SRP, T_DNS, T_N };

/* Attach states, under TG_DETACHED and TG_CHILD. */
enum {
	A_IDLE,     /* waiting out a backoff */
	A_PREQ_R,   /* Parent Request to routers sent */
	A_PREQ_RE,  /* Parent Request to routers and REEDs sent */
	A_CIDREQ,   /* Child ID Request sent */
	A_CHILD,    /* attached, nothing outstanding */
	A_CUPD,     /* attached, Child Update Request outstanding */
};

struct tg_nbr {
	uint8_t ext[8];
	uint16_t rloc;
	uint32_t mac_fc, mle_fc, kseq;
	uint8_t chal[8], chal_len;
	int8_t prio;
	uint8_t margin;
	bool valid;
};

struct tg_state {
	/* dataset (the caller keeps the TLVs) */
	uint8_t ds_len;
	uint8_t chan;
	uint16_t pan;
	uint8_t xpan[8], key[16], mlp[8], ats[8];
	bool have_ats;

	/* persisted identity and counters (struct tg_nv) */
	uint8_t ext[8], iid[8];
	uint32_t kseq, mac_fc, mle_fc, mac_fc_nv, mle_fc_nv;
	uint8_t ktag[4];
	uint8_t mle_key[16], mac_key[16];

	/* role */
	uint8_t role, ast, tries, cupd_tries, txfail;
	uint16_t rloc;
	uint32_t poll_ms;
	uint8_t chal[8];
	struct tg_nbr par, cand;
	int8_t rssi; /* of the frame being processed */

	/* leader data and the network data distilled from it */
	uint32_t part;
	uint8_t sver;
	bool have_nd, omr_reg;
	struct {
		uint8_t id, prefix[8];
	} ctx[TG_CONTEXTS];
	uint8_t nctx;
	uint8_t omr[8];
	bool have_omr;
	uint8_t srp_addr[16];
	uint16_t srp_port;
	bool have_srp;

	uint32_t due[T_N];
	uint8_t armed;

	/* SED polling */
	uint8_t fast_polls;
	bool rx_window;

	/* reassembly; also the build buffer for SRP when idle */
	uint8_t pkt[TG_PKT_MAX];
	uint16_t r_size, r_tag, r_got;
	uint8_t r_src[8];
	bool r_busy;

	struct tg_udp *socks;
};

extern struct tg_state tg;

/* tg_core.c */
void tg_arm(uint8_t t, uint32_t ms);
void tg_disarm(uint8_t t);
void tg_save_state(void);
void tg_set_kseq(uint32_t kseq);
void tg_keys(uint32_t kseq, uint8_t mle[16], uint8_t mac[16]);
uint32_t tg_mac_fc_next(void);
uint32_t tg_mle_fc_next(void);

/* tg_sec.c */
int tg_ccm(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *a, size_t alen,
	   uint8_t *m, size_t mlen, uint8_t *tag, bool enc);
void tg_nonce(uint8_t n[13], const uint8_t ext[8], uint32_t fc);

/* tg_mac.c */
struct tg_maddr {
	uint8_t mode; /* 2 short, 3 extended */
	uint16_t s;
	uint8_t e[8]; /* canonical */
};
struct tg_frag;
int tg_mac_send(const uint8_t *hdr, uint8_t hlen, const uint8_t *data, uint16_t dlen,
		uint16_t total, const struct tg_maddr *dst, bool src_ext, bool secure);
void tg_mac_poll(void);
void tg_mac_reset(void);
void tg_mac_timer_poll(void);

/* tg_lowpan.c */
uint8_t tg_iphc(uint8_t *out, const uint8_t *ip6, const struct tg_maddr *src,
		const struct tg_maddr *dst);
void tg_lowpan_rx(uint8_t *p, uint8_t n, struct tg_maddr *src, struct tg_maddr *dst, bool sec);
void tg_reasm_timeout(void);

/* tg_ip6.c */
void tg_ip6_rx(uint8_t *pkt, uint16_t len, bool sec);
int tg_ip6_send_udp(const uint8_t src[16], const uint8_t dst[16], uint8_t hlim, uint16_t sport,
		    uint16_t dport, const uint8_t *data, uint16_t len, bool mle);
bool tg_is_ours(const uint8_t a[16]);
void tg_lladdr(uint8_t out[16], const uint8_t ext[8]);
void tg_mladdr(uint8_t out[16], const uint8_t iid[8]);
int tg_ctx_find(const uint8_t prefix[8]);
const uint8_t *tg_ctx_prefix(uint8_t id);
int tg_srp_send(const uint8_t *m, uint16_t n);
#define TG_DNS_CLIENT_PORT 49998u

/* tg_mle.c */
void tg_mle_rx(const uint8_t src[16], const uint8_t dst[16], uint8_t *m, uint16_t n);
void tg_mle_start(void);
void tg_mle_timer(void);
void tg_mle_tx_failed(void);
void tg_mle_poll_failed(void);
void tg_mle_netdata(const uint8_t *nd, uint8_t len);

/* tg_srp.c */
void tg_srp_timer(void);
void tg_srp_rx(const uint8_t *m, uint16_t n);
void tg_srp_kick(uint32_t delay_ms);

/* tg_dns.c */
void tg_dns_rx(const uint8_t *m, uint16_t n);
void tg_dns_timer(void);
