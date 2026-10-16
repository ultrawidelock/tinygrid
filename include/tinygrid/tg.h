/* SPDX-License-Identifier: ISC */
/**
 * @file tg.h — tinygrid: a Thread end device that never routes.
 *
 * It attaches as a child (rx-on, or sleepy and polling), keeps that link
 * alive, configures its addresses from the network data, and carries UDP and
 * SRP. Nothing else: no router role, no joiner or commissioner, no CSL, no
 * multicast beyond what MLE needs.
 *
 * One context owns the stack. Every function here and every callback it makes
 * runs on that context; a port with more than one thread serialises calls.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TG_OK 0
#define TG_E_INVAL (-1)  /* malformed input */
#define TG_E_STATE (-2)  /* not attached, or no dataset */
#define TG_E_BUSY (-3)   /* no room right now; try again */

enum tg_role {
	TG_DISABLED = 0, /* no dataset */
	TG_DETACHED,     /* has a dataset, looking for a parent */
	TG_CHILD,        /* attached */
};

/**
 * Load persisted state (identity, frame counters). Does not attach.
 *
 * @param poll_ms 0 for a receiver that is always on (MED); otherwise a sleepy
 *        child (SED) that polls its parent every @p poll_ms.
 */
int tg_init(uint32_t poll_ms);

/**
 * Adopt @p dataset (raw meshcop TLVs) and attach. The caller keeps the
 * dataset and hands it over again after a reboot.
 */
int tg_start(const uint8_t *dataset, size_t len);

/** Detach and drop the dataset. */
void tg_clear(void);

enum tg_role tg_role(void);

/** Attached, and the parent has acknowledged an off-mesh routable address. */
bool tg_ready(void);

/** The dataset's Extended PAN ID, or NULL without a dataset. */
const uint8_t *tg_xpanid(void);

/** The off-mesh routable (SLAAC) address, if the network offers one. */
bool tg_omr(uint8_t out[16]);

/** The mesh-local EID. False without a dataset. */
bool tg_mleid(uint8_t out[16]);

/**
 * Run whatever is due. Call after every radio event and when the time it
 * returned has passed.
 *
 * @return milliseconds until it next needs to run, UINT32_MAX for never.
 */
uint32_t tg_process(void);

/* ---- UDP --------------------------------------------------------------- */

struct tg_udp;
typedef void (*tg_udp_rx_fn)(struct tg_udp *sock, const uint8_t src[16], uint16_t sport,
			     const uint8_t dst[16], uint8_t *data, size_t len);

struct tg_udp {
	uint16_t port;
	tg_udp_rx_fn rx;
	struct tg_udp *next; /* owned by tinygrid */
};

/** Deliver datagrams for sock->port to sock->rx. @p sock must outlive it. */
void tg_udp_bind(struct tg_udp *sock);

/**
 * Send one datagram. @p src NULL picks the source the destination calls for.
 * The payload is copied before this returns.
 */
int tg_udp_send(const uint8_t *src, uint16_t sport, const uint8_t dst[16], uint16_t dport,
		const uint8_t *data, size_t len);

/* ---- SRP --------------------------------------------------------------- */

enum tg_srp_state {
	TG_SRP_IDLE = 0, /* not in the table */
	TG_SRP_ADD,      /* waiting to be registered */
	TG_SRP_REG,      /* registered */
	TG_SRP_DEL,      /* waiting to be removed */
};

/**
 * One service instance, owned by the caller until tinygrid reports it
 * TG_SRP_IDLE again. Names are single labels; @p type is the two labels
 * "_service._proto"; @p txt is DNS TXT rdata (length-prefixed strings).
 */
struct tg_srp_svc {
	const char *instance;
	const char *type;
	const char *const *subtypes;
	uint8_t nsub;
	uint16_t port;
	const uint8_t *txt;
	uint16_t txt_len;
	uint8_t state; /* enum tg_srp_state, owned by tinygrid */
	uint8_t sent;  /* owned by tinygrid: the state the update in flight carries */
	struct tg_srp_svc *next;
};

/** Name this host (a single label). Required before any service registers. */
int tg_srp_host(const char *label);

/** Register @p svc, alongside every other service, on the next update. */
int tg_srp_add(struct tg_srp_svc *svc);

/** Withdraw @p svc on the next update. */
int tg_srp_remove(struct tg_srp_svc *svc);

/**
 * Drop every service. With @p tell_server the host and its key are removed
 * from the server too; without, they are forgotten locally only.
 */
void tg_srp_reset(bool tell_server);

#ifdef __cplusplus
}
#endif
