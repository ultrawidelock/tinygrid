/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
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

/** Detach and drop the dataset. An SRP removal not yet answered is kept,
 * and sent once attached again. */
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

/** The IEEE 802.15.4 extended address, in canonical order. */
void tg_ext_addr(uint8_t out[8]);

/**
 * This node's unicast addresses, at most @p max: the off-mesh one, the ML-EID
 * and the RLOC while attached, then the link-local one. Returns how many.
 */
uint8_t tg_addrs(uint8_t (*out)[16], uint8_t max);

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
void tg_udp_unbind(struct tg_udp *sock);

/**
 * Send one datagram. @p src NULL picks the source the destination calls for.
 * The payload is copied before this returns. A realm-local multicast
 * destination (ff03::/16) goes out through the parent with an MPL option, and
 * repeats of one arriving are dropped.
 */
int tg_udp_send(const uint8_t *src, uint16_t sport, const uint8_t dst[16], uint16_t dport,
		const uint8_t *data, size_t len);

/* ---- DNS --------------------------------------------------------------- */

/** err is TG_OK with addr and port, or negative with addr NULL. */
typedef void (*tg_dns_fn)(void *ctx, int err, const uint8_t *addr, uint16_t port);

/**
 * Resolve "<instance>.<type>.default.service.arpa" to its SRV port and its
 * host's address, asking the network's DNS server (the SRP server's address,
 * port 53). One at a time: TG_E_BUSY while one is in flight. @p cb runs on
 * the stack's context.
 */
int tg_dns_resolve(const char *instance, const char *type, tg_dns_fn cb, void *ctx);

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
 *
 * Services of one lease share an update; each distinct lease is an update of
 * its own, shortest first, so the host is left on the longest. All of them
 * renew together, at 80% of the shortest lease granted.
 */
struct tg_srp_svc {
	const char *instance;
	const char *type;
	const char *const *subtypes;
	uint8_t nsub;
	uint16_t port;
	const uint8_t *txt;
	uint16_t txt_len;
	uint32_t lease_s; /* seconds; 0 for the default, CONFIG_TINYGRID_SRP_LEASE_S */
	uint8_t state; /* enum tg_srp_state, owned by tinygrid */
	uint8_t sent;  /* owned by tinygrid: the state the update in flight carries */
	struct tg_srp_svc *next;
};

/** Name this host (a single label). Required before any service registers. */
int tg_srp_host(const char *label);

/** Register @p svc, alongside every other service, on the next update. */
int tg_srp_add(struct tg_srp_svc *svc);

/** Withdraw @p svc on the next update: by name, with its subtypes. */
int tg_srp_remove(struct tg_srp_svc *svc);

/**
 * Drop every service. With @p tell_server each one is removed from the server
 * by name, subtypes included, and then the host and its key: a server may keep
 * the services of a host it removes, as Apple's border router does. The
 * services stay tinygrid's until each is reported TG_SRP_IDLE, and
 * tg_plat_changed() reports every answer. The removal waits for a parent and
 * a server, not for the off-mesh address: the server knows this host by its
 * key, from this boot or an earlier one. Without @p tell_server everything is
 * forgotten locally, at once.
 */
void tg_srp_reset(bool tell_server);

/** A removal, of a service or of the host, the server has not yet answered. */
bool tg_srp_pending(void);

/**
 * Forget the SRP key (ports/psa: tg/2 and the key in memory); the next update
 * registers under a new one. Call once tg_srp_reset(true) is answered: a
 * server keeps a name bound to its key until the key lease runs out. An
 * application that wipes the settings store on a factory reset, as the
 * door-lock does (tinytalk 0fc9948), loses the key with it and need not.
 */
void tg_srp_key_reset(void);

#ifdef __cplusplus
}
#endif
