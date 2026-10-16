/* SPDX-License-Identifier: ISC */
/*
 * tg_plat.h on Zephyr and the nRF 802.15.4 radio driver, with nothing between:
 * no OpenThread, no IEEE 802.15.4 L2, no network stack. The driver shares the
 * radio with Bluetooth through MPSL on its own.
 *
 * One thread runs the stack. Driver callouts (radio interrupt context) only
 * queue: received frames into a small ring of the driver's own buffers, a
 * transmit result into two words.
 */
#include "tg_zephyr.h"

#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <nrf_802154.h>
#include <psa/crypto.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <stdio.h>
#include <string.h>

static K_MUTEX_DEFINE(s_lock);
static K_SEM_DEFINE(s_wake, 0, 1);

void tg_zephyr_lock(void)
{
	(void)k_mutex_lock(&s_lock, K_FOREVER);
}

void tg_zephyr_unlock(void)
{
	(void)k_mutex_unlock(&s_lock);
	k_sem_give(&s_wake);
}

__weak void tg_zephyr_changed(void) {}

void tg_plat_changed(void)
{
	tg_zephyr_changed();
}

uint32_t tg_plat_now(void)
{
	return k_uptime_get_32();
}

/* ---- persistence ------------------------------------------------------- */

struct ld {
	void *buf;
	size_t len;
	int got;
};

static int ld_cb(const char *name, size_t len, settings_read_cb rd, void *arg, void *param)
{
	struct ld *l = param;

	if (name != NULL && name[0] != '\0') {
		return 0; /* a deeper name, not this leaf */
	}
	if (len <= l->len) {
		ssize_t n = rd(arg, l->buf, len);

		l->got = n == (ssize_t)len ? (int)len : -1;
	}
	return 0;
}

int tg_plat_load(uint8_t key, void *buf, size_t len)
{
	char name[8];
	struct ld l = {.buf = buf, .len = len, .got = -1};

	(void)snprintf(name, sizeof(name), "tg/%u", key);
	return settings_load_subtree_direct(name, ld_cb, &l) == 0 ? l.got : -1;
}

int tg_plat_save(uint8_t key, const void *buf, size_t len)
{
	char name[8];

	(void)snprintf(name, sizeof(name), "tg/%u", key);
	return settings_save_one(name, buf, len) == 0 ? 0 : -1;
}

/* ---- radio ------------------------------------------------------------- */

#define RXQ CONFIG_NRF_802154_RX_BUFFERS

static struct {
	uint8_t *p;
	int8_t rssi;
} s_rxq[RXQ];
static uint8_t s_rx_head, s_rx_n;
static struct k_spinlock s_rx_lock;
static atomic_t s_tx_result = ATOMIC_INIT(-1);
static bool s_tx_pending_bit;
static uint8_t s_tx[1 + 127]; /* PHR, then the PSDU */

void tg_plat_radio_set(uint8_t channel, uint16_t pan, uint16_t short_addr, const uint8_t ext[8])
{
	uint8_t b[8];

	nrf_802154_channel_set(channel);
	b[0] = (uint8_t)pan;
	b[1] = (uint8_t)(pan >> 8);
	nrf_802154_pan_id_set(b);
	b[0] = (uint8_t)short_addr;
	b[1] = (uint8_t)(short_addr >> 8);
	nrf_802154_short_address_set(b);
	for (int i = 0; i < 8; i++) {
		b[i] = ext[7 - i]; /* the driver wants it little-endian */
	}
	nrf_802154_extended_address_set(b);
}

void tg_plat_radio_rx(bool on)
{
	nrf_802154_rx_on_when_idle_set(on);
	if (on) {
		(void)nrf_802154_receive();
	} else {
		(void)nrf_802154_sleep_if_idle();
	}
}

int tg_plat_radio_tx(const uint8_t *psdu, uint8_t len)
{
	const nrf_802154_transmit_csma_ca_metadata_t md = {
		/* Secured, counters and all, before it got here. */
		.frame_props = {.is_secured = (psdu[0] & 0x08u) != 0u, .dynamic_data_is_set = true},
		.tx_power = {.use_metadata_value = true, .power = CONFIG_TINYGRID_TX_POWER},
	};

	s_tx[0] = (uint8_t)(len + 2u); /* PHR counts the FCS the radio appends */
	memcpy(s_tx + 1, psdu, len);
	return nrf_802154_transmit_csma_ca_raw(s_tx, &md) == NRF_802154_TX_ERROR_NONE ? 0 : -1;
}

void nrf_802154_received_timestamp_raw(uint8_t *p, int8_t power, uint8_t lqi, uint64_t time)
{
	k_spinlock_key_t k = k_spin_lock(&s_rx_lock);
	bool kept = s_rx_n < RXQ;

	ARG_UNUSED(lqi);
	ARG_UNUSED(time);
	if (kept) {
		s_rxq[(s_rx_head + s_rx_n) % RXQ].p = p;
		s_rxq[(s_rx_head + s_rx_n) % RXQ].rssi = power;
		s_rx_n++;
	}
	k_spin_unlock(&s_rx_lock, k);
	if (!kept) {
		nrf_802154_buffer_free_raw(p);
	}
	k_sem_give(&s_wake);
}

void nrf_802154_transmitted_raw(uint8_t *frame, const nrf_802154_transmit_done_metadata_t *md)
{
	uint8_t *ack = md->data.transmitted.p_ack;

	ARG_UNUSED(frame);
	s_tx_pending_bit = ack != NULL && (ack[1] & 0x10u);
	if (ack != NULL) {
		nrf_802154_buffer_free_raw(ack);
	}
	atomic_set(&s_tx_result, TG_TX_OK);
	k_sem_give(&s_wake);
}

void nrf_802154_transmit_failed(uint8_t *frame, nrf_802154_tx_error_t err,
				const nrf_802154_transmit_done_metadata_t *md)
{
	ARG_UNUSED(frame);
	ARG_UNUSED(md);
	s_tx_pending_bit = false;
	atomic_set(&s_tx_result, err == NRF_802154_TX_ERROR_NO_ACK ||
					 err == NRF_802154_TX_ERROR_INVALID_ACK
				 ? TG_TX_NOACK
				 : TG_TX_BUSY);
	k_sem_give(&s_wake);
}

/* ---- the stack's thread ------------------------------------------------ */

static void run(void *a, void *b, void *c)
{
	uint32_t wait = UINT32_MAX;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);
	for (;;) {
		(void)k_sem_take(&s_wake, wait == UINT32_MAX ? K_FOREVER : K_MSEC(wait));
		tg_zephyr_lock();
		for (;;) {
			atomic_val_t r = atomic_set(&s_tx_result, -1);
			k_spinlock_key_t k;
			uint8_t *p = NULL;
			int8_t rssi = 0;

			if (r >= 0) {
				tg_radio_tx_done((int)r, s_tx_pending_bit);
			}
			k = k_spin_lock(&s_rx_lock);
			if (s_rx_n) {
				p = s_rxq[s_rx_head].p;
				rssi = s_rxq[s_rx_head].rssi;
				s_rx_head = (uint8_t)((s_rx_head + 1u) % RXQ);
				s_rx_n--;
			}
			k_spin_unlock(&s_rx_lock, k);
			if (p == NULL) {
				break;
			}
			if (p[0] >= 5u) {
				tg_radio_rx(p + 1, (uint8_t)(p[0] - 2u), rssi);
			}
			nrf_802154_buffer_free_raw(p);
		}
		wait = tg_process();
		(void)k_mutex_unlock(&s_lock);
	}
}

K_THREAD_STACK_DEFINE(s_stack, CONFIG_TINYGRID_STACK_SIZE);
static struct k_thread s_thread;

static int tg_zephyr_init(void)
{
	if (psa_crypto_init() != PSA_SUCCESS || settings_subsys_init() != 0) {
		return -EIO;
	}
	nrf_802154_init();
	nrf_802154_tx_power_set(CONFIG_TINYGRID_TX_POWER);
	(void)tg_init(CONFIG_TINYGRID_POLL_MS);
	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack), run, NULL, NULL,
			NULL, CONFIG_TINYGRID_THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "tinygrid");
	return 0;
}

SYS_INIT(tg_zephyr_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
