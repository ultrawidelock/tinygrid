/* SPDX-License-Identifier: ISC */
/**
 * @file matter_thread_tinygrid.c — matter_thread.h on tinygrid, for tinytalk
 * and for ultrawidelock (whose seam adds resolve and a dataset dump).
 *
 * The same contract tinytalk's OpenThread port keeps (ports/zephyr/thread/
 * matter_thread_port.c), and the same records on the border router: one host,
 * one _matter._tcp instance per fabric with its _I subtype, and _matterc._udp
 * while a commissioning window is open. What differs is ownership: tinygrid
 * returns a removed service the moment the server confirms it, so there is no
 * second bank of buffers held by a client library.
 */
#if defined(CONFIG_ULTRAWIDELOCK_MATTER)
#include "matter_thread.h"

#include "matter_clusters.h" /* MATTER_SUPPORTED_FABRICS, XPANID_LEN */
#include "matter_fabric.h"   /* MATTER_INSTANCE_NAME_LEN */
#define VENDOR_ID CONFIG_ULTRAWIDELOCK_MATTER_VENDOR_ID
#define PRODUCT_ID CONFIG_ULTRAWIDELOCK_MATTER_PRODUCT_ID
#else
#include <tinytalk/matter_thread.h>

#include <tinytalk/matter_clusters.h> /* MATTER_SUPPORTED_FABRICS, XPANID_LEN */
#include <tinytalk/matter_fabric.h>   /* MATTER_INSTANCE_NAME_LEN */
#define VENDOR_ID CONFIG_TINYTALK_VENDOR_ID
#define PRODUCT_ID CONFIG_TINYTALK_PRODUCT_ID
#endif

#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <tinygrid/tg_zephyr.h>

#include <psa/crypto.h>
#include <zephyr/kernel.h>

#include <stdio.h>
#include <string.h>

#if !defined(CONFIG_ULTRAWIDELOCK_MATTER)
BUILD_ASSERT(MATTER_THREAD_API == 1, "matter_thread.h changed: review this adapter");
#endif

static K_SEM_DEFINE(s_changed, 0, 1);

/* ---- attach ------------------------------------------------------------ */

static void udp_rx(struct tg_udp *sock, const uint8_t src[16], uint16_t sport,
		   const uint8_t dst[16], uint8_t *data, size_t len);

static struct tg_udp s_sock = {.port = MATTER_OPERATIONAL_PORT, .rx = udp_rx};

int matter_thread_start(const uint8_t *dataset, size_t len)
{
	int rc;

	if (dataset == NULL || len == 0u) {
		return MATTER_E_INVAL;
	}
	tg_zephyr_lock();
	tg_udp_bind(&s_sock);
	rc = tg_start(dataset, len);
	tg_zephyr_unlock();
	return rc == TG_OK ? MATTER_OK : MATTER_E_INVAL;
}

int matter_thread_clear(void)
{
	matter_thread_advertise_reset();
	tg_zephyr_lock();
	tg_clear();
	tg_zephyr_unlock();
	return MATTER_OK;
}

bool matter_thread_attached_to(const uint8_t *xpanid)
{
	const uint8_t *x;
	bool same;

	if (xpanid == NULL) {
		return false;
	}
	tg_zephyr_lock();
	x = tg_xpanid();
	same = tg_role() == TG_CHILD && x != NULL &&
	       memcmp(x, xpanid, MATTER_THREAD_XPANID_LEN) == 0;
	tg_zephyr_unlock();
	return same;
}

/*
 * Attached is not reachable: a commissioner on Wi-Fi needs the off-mesh
 * routable address, and tg_ready() is true only once the parent has
 * acknowledged registering it.
 */
int matter_thread_wait_attached(uint32_t timeout_ms)
{
	int64_t start = k_uptime_get();

	for (;;) {
		uint32_t waited = (uint32_t)(k_uptime_get() - start);
		bool ready;

		tg_zephyr_lock();
		ready = tg_ready();
		tg_zephyr_unlock();
		if (ready) {
			return MATTER_OK;
		}
		if (waited >= timeout_ms) {
			return MATTER_E_TIMEOUT;
		}
		(void)k_sem_take(&s_changed, K_MSEC(timeout_ms - waited));
	}
}

/* ---- datagrams --------------------------------------------------------- */

static struct matter_thread_peer s_cur_peer;
static uint8_t s_reply[MATTER_THREAD_REPLY_MAX];

struct reply_to {
	const uint8_t *local, *peer;
	uint16_t port;
};

void matter_thread_peer_current(struct matter_thread_peer *out)
{
	if (out != NULL) {
		tg_zephyr_lock(); /* udp_rx() writes it under the lock */
		*out = s_cur_peer;
		tg_zephyr_unlock();
	}
}

static int reply_send(void *ctx, const uint8_t *msg, size_t len)
{
	const struct reply_to *r = ctx;

	/* From the address the request reached, so a commissioner behind a
	 * border router hears back on the same route. */
	return tg_udp_send(r->local, MATTER_OPERATIONAL_PORT, r->peer, r->port, msg, len) == TG_OK
		       ? MATTER_OK
		       : MATTER_E_STATE;
}

/* On tinygrid's thread with its lock held: the OpenThread-then-Matter order. */
static void udp_rx(struct tg_udp *sock, const uint8_t src[16], uint16_t sport,
		   const uint8_t dst[16], uint8_t *data, size_t len)
{
	struct reply_to r = {.local = dst[0] == 0xffu ? NULL : dst, .peer = src, .port = sport};

	ARG_UNUSED(sock);
	memcpy(s_cur_peer.addr, src, 16);
	s_cur_peer.port = sport;
	s_cur_peer.valid = true;
	(void)matter_thread_on_datagram(data, len, s_reply, sizeof(s_reply), reply_send, &r);
	s_cur_peer.valid = false;
}

int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len)
{
	int rc;

	if (peer == NULL || !peer->valid || msg == NULL || len == 0u) {
		return MATTER_E_STATE;
	}
	tg_zephyr_lock();
	rc = tg_udp_send(NULL, MATTER_OPERATIONAL_PORT, peer->addr, peer->port, msg, len);
	tg_zephyr_unlock();
	return rc == TG_OK ? MATTER_OK : MATTER_E_STATE;
}

/* ---- SRP --------------------------------------------------------------- */

/* "<16 hex of the ML-EID IID>": random, and stable while tinygrid's state
 * (tg/1) is. advertise_reset keeps it, since the host's removal goes out
 * under it. A factory reset that wipes the settings store draws a new IID and
 * a new SRP key together, so a new key never asks for a name the server still
 * holds under the old one. */
static char s_host[17];

/* One TXT string: length, then key=value. */
static uint16_t txt(uint8_t *p, const char *kv)
{
	size_t n = strlen(kv);

	p[0] = (uint8_t)n;
	memcpy(p + 1, kv, n);
	return (uint16_t)(n + 1u);
}

/* MRP intervals this node answers on (matter_mrp.h); the same for both. */
static const uint8_t s_mrp_txt[] = "\x07SII=500\x07SAI=300";

struct op {
	char want[MATTER_INSTANCE_NAME_LEN]; /* what Matter asked for; "" for nothing */
	uint16_t want_port;
	char inst[MATTER_INSTANCE_NAME_LEN];
	char sub[19]; /* "_I" + 16 hex + NUL */
	const char *subs[1];
	struct tg_srp_svc svc;
};
static struct op s_ops[MATTER_SUPPORTED_FABRICS];

static struct {
	bool want;
	bool loaded, stale; /* tg/3 read this boot; svc is the last boot's record */
	uint16_t disc, port;
	char inst[17], s_sub[5], l_sub[7];
	const char *subs[2];
	uint8_t txt[64];
	struct tg_srp_svc svc;
} s_comm;

/*
 * The window record, kept in tg/3 from the moment it is registered until the
 * window closes. Apple's border router keeps a commissionable record its node
 * never removed well past its lease, and removing the host does not take it
 * (tinytalk a029e57, 2026-10-16): a crash, power cut or reset with a window
 * open leaves one that Home dials over Thread instead of using BLE. So the
 * next boot registers that name again and removes it.
 */
struct comm_nv {
	char inst[16];
	uint16_t disc, port;
};

/* Register s_comm.inst as _matterc._udp. Lock held. */
static void comm_register(uint16_t disc, uint16_t port)
{
	uint16_t n = 0;
	char kv[24];

	(void)snprintf(s_comm.s_sub, sizeof(s_comm.s_sub), "_S%u",
		       (unsigned int)((disc >> 8) & 0x0fu));
	(void)snprintf(s_comm.l_sub, sizeof(s_comm.l_sub), "_L%u", (unsigned int)(disc & 0x0fffu));
	s_comm.subs[0] = s_comm.s_sub;
	s_comm.subs[1] = s_comm.l_sub;
	(void)snprintf(kv, sizeof(kv), "D=%u", (unsigned int)(disc & 0x0fffu));
	n += txt(s_comm.txt + n, kv);
	n += txt(s_comm.txt + n, "CM=2");
	(void)snprintf(kv, sizeof(kv), "VP=%u+%u", (unsigned int)VENDOR_ID,
		       (unsigned int)PRODUCT_ID);
	n += txt(s_comm.txt + n, kv);
	memcpy(s_comm.txt + n, s_mrp_txt, sizeof(s_mrp_txt) - 1u);
	n += sizeof(s_mrp_txt) - 1u;
	s_comm.svc = (struct tg_srp_svc){
		.instance = s_comm.inst,
		.type = "_matterc._udp",
		.subtypes = s_comm.subs,
		.nsub = 2,
		.port = port,
		.txt = s_comm.txt,
		.txt_len = n,
		.lease_s = CONFIG_TINYGRID_MATTER_COMM_LEASE_S,
	};
	(void)tg_srp_add(&s_comm.svc);
}

/* The last boot's record: removed once the server holds it again, then
 * forgotten. Lock held. */
static void comm_settle(void)
{
	if (!s_comm.stale) {
		return;
	}
	if (s_comm.svc.state == TG_SRP_REG) {
		(void)tg_srp_remove(&s_comm.svc);
	} else if (s_comm.svc.state == TG_SRP_IDLE) {
		s_comm.stale = false;
		(void)tg_plat_save(TG_KV_WINDOW, NULL, 0);
	}
}

static bool host_ready(void)
{
	uint8_t a[16];

	if (s_host[0] != '\0') {
		return true;
	}
	if (!tg_mleid(a)) {
		return false;
	}
	for (int i = 0; i < 8; i++) {
		(void)snprintf(s_host + 2 * i, 3, "%02X", a[8 + i]);
	}
	return tg_srp_host(s_host) == TG_OK;
}

/* Bring the registrations in line with what Matter wants. Lock held. */
static void reconcile(void)
{
	if (!host_ready()) {
		return;
	}
	for (size_t i = 0; i < MATTER_SUPPORTED_FABRICS; i++) {
		struct op *o = &s_ops[i];

		if (o->svc.state != TG_SRP_IDLE) {
			continue; /* registered, or on its way in or out */
		}
		/* A free slot takes the first wanted name nobody else holds. */
		for (size_t j = 0; j < MATTER_SUPPORTED_FABRICS; j++) {
			bool held = false;

			if (s_ops[j].want[0] == '\0') {
				continue;
			}
			for (size_t k = 0; k < MATTER_SUPPORTED_FABRICS; k++) {
				held |= s_ops[k].svc.state != TG_SRP_IDLE &&
					strcmp(s_ops[k].inst, s_ops[j].want) == 0;
			}
			if (held) {
				continue;
			}
			memcpy(o->inst, s_ops[j].want, sizeof(o->inst));
			o->sub[0] = '_';
			o->sub[1] = 'I';
			memcpy(o->sub + 2, o->inst, 16);
			o->sub[18] = '\0';
			o->subs[0] = o->sub;
			o->svc = (struct tg_srp_svc){
				.instance = o->inst,
				.type = "_matter._tcp",
				.subtypes = o->subs,
				.nsub = 1,
				.port = s_ops[j].want_port,
				.txt = s_mrp_txt,
				.txt_len = sizeof(s_mrp_txt) - 1u,
			};
			(void)tg_srp_add(&o->svc);
			break;
		}
	}
	if (!s_comm.loaded) {
		struct comm_nv nv;

		s_comm.loaded = true;
		if (tg_plat_load(TG_KV_WINDOW, &nv, sizeof(nv)) == (int)sizeof(nv) &&
		    s_comm.svc.state == TG_SRP_IDLE) {
			memcpy(s_comm.inst, nv.inst, sizeof(nv.inst));
			s_comm.inst[16] = '\0';
			s_comm.stale = true;
			comm_register(nv.disc, nv.port);
		}
	}
	if (s_comm.want && s_comm.svc.state == TG_SRP_IDLE) {
		uint8_t r[8];
		struct comm_nv nv = {.disc = s_comm.disc, .port = s_comm.port};

		if (psa_generate_random(r, sizeof(r)) != PSA_SUCCESS) {
			return;
		}
		for (int i = 0; i < 8; i++) {
			(void)snprintf(s_comm.inst + 2 * i, 3, "%02X", r[i]);
		}
		/* Kept before the server has it: a crash in between is the case. */
		memcpy(nv.inst, s_comm.inst, sizeof(nv.inst));
		(void)tg_plat_save(TG_KV_WINDOW, &nv, sizeof(nv));
		comm_register(s_comm.disc, s_comm.port);
	}
}

/* A registration finished coming or going: a freed slot may be wanted. */
void tg_zephyr_changed(void)
{
	comm_settle();
	reconcile();
	k_sem_give(&s_changed);
}

int matter_thread_advertise(const char *instance_name, uint16_t port)
{
	struct op *slot = NULL;

	if (instance_name == NULL || strlen(instance_name) < 16u ||
	    strlen(instance_name) >= MATTER_INSTANCE_NAME_LEN) {
		return MATTER_E_INVAL;
	}
	tg_zephyr_lock();
	for (size_t i = 0; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (strcmp(s_ops[i].want, instance_name) == 0) {
			slot = &s_ops[i];
			break;
		}
		if (s_ops[i].want[0] == '\0' && slot == NULL) {
			slot = &s_ops[i];
		}
	}
	if (slot == NULL) {
		tg_zephyr_unlock();
		return MATTER_E_NOSPACE;
	}
	(void)snprintf(slot->want, sizeof(slot->want), "%s", instance_name);
	slot->want_port = port;
	reconcile();
	tg_zephyr_unlock();
	return MATTER_OK;
}

int matter_thread_unadvertise(const char *instance_name)
{
	if (instance_name == NULL) {
		return MATTER_E_INVAL;
	}
	tg_zephyr_lock();
	for (size_t i = 0; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (strcmp(s_ops[i].want, instance_name) == 0) {
			s_ops[i].want[0] = '\0';
		}
		if (s_ops[i].svc.state != TG_SRP_IDLE && strcmp(s_ops[i].inst, instance_name) == 0) {
			(void)tg_srp_remove(&s_ops[i].svc);
		}
	}
	tg_zephyr_unlock();
	return MATTER_OK;
}

int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port)
{
	tg_zephyr_lock();
	if (!s_comm.want) {
		s_comm.want = true;
		s_comm.disc = discriminator;
		s_comm.port = port;
	}
	reconcile();
	tg_zephyr_unlock();
	return MATTER_OK;
}

int matter_thread_unadvertise_commissionable(void)
{
	tg_zephyr_lock();
	s_comm.want = false;
	(void)tg_srp_remove(&s_comm.svc);
	(void)tg_plat_save(TG_KV_WINDOW, NULL, 0);
	tg_zephyr_unlock();
	return MATTER_OK;
}

/*
 * Retract every name, then the host: the instance names are derived from
 * fabrics that just ceased to exist and will never be asked for again, so
 * nothing on the border router should keep vouching for them. The host goes
 * with a key lease of 0, so the server forgets its key; the key itself stays
 * in tg/2. The door-lock wipes the settings store on a factory reset
 * (tinytalk b37d675), which takes it; an application that does not calls
 * tg_srp_key_reset() once this is answered.
 */
void matter_thread_advertise_reset(void)
{
	tg_zephyr_lock();
	for (size_t i = 0; i < MATTER_SUPPORTED_FABRICS; i++) {
		s_ops[i].want[0] = '\0';
	}
	s_comm.want = false;
	s_comm.stale = s_comm.svc.state != TG_SRP_IDLE; /* tg/3 goes once it is removed */
	tg_srp_reset(true); /* each service stays tinygrid's until it is removed */
	tg_zephyr_unlock();
}

bool matter_thread_advertise_pending(void)
{
	bool pending;

	tg_zephyr_lock();
	pending = tg_srp_pending();
	tg_zephyr_unlock();
	return pending;
}

#if defined(CONFIG_ULTRAWIDELOCK_MATTER)
/* ---- ultrawidelock's additions ----------------------------------------- */

/* The dataset dump is a bench aid that depends on OpenThread; with tinygrid
 * there is nothing to print and nothing for the bench caller to retry. */
int matter_thread_dump_active_dataset(void)
{
	return 0;
}

#if defined(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT)
static struct {
	matter_thread_resolve_fn cb;
	void *ctx;
} s_res;

/* On tinygrid's thread. A NULL peer is an answer: not found. */
static void resolved(void *ctx, int err, const uint8_t *addr, uint16_t port)
{
	struct matter_thread_peer peer = {0};
	matter_thread_resolve_fn cb = s_res.cb;

	ARG_UNUSED(ctx);
	s_res.cb = NULL;
	if (err == TG_OK) {
		memcpy(peer.addr, addr, 16);
		peer.port = port;
		peer.valid = true;
	}
	if (cb != NULL) {
		cb(s_res.ctx, err == TG_OK ? &peer : NULL);
	}
}

int matter_thread_resolve(const char *instance_name, matter_thread_resolve_fn cb, void *ctx)
{
	int rc;

	if (instance_name == NULL || cb == NULL ||
	    strlen(instance_name) >= MATTER_INSTANCE_NAME_LEN) {
		return MATTER_E_INVAL;
	}
	tg_zephyr_lock();
	if (s_res.cb != NULL) {
		tg_zephyr_unlock();
		return MATTER_E_STATE;
	}
	s_res.cb = cb;
	s_res.ctx = ctx;
	rc = tg_dns_resolve(instance_name, "_matter._tcp", resolved, NULL);
	if (rc != TG_OK) {
		s_res.cb = NULL;
	}
	tg_zephyr_unlock();
	return rc == TG_OK ? MATTER_OK : MATTER_E_STATE;
}
#endif /* CONFIG_ULTRAWIDELOCK_MATTER_CLIENT */
#endif /* CONFIG_ULTRAWIDELOCK_MATTER */
