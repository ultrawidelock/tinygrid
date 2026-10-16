/* SPDX-License-Identifier: ISC */
/*
 * tg_plat.h's radio on Nordic's nRF 802.15.4 driver, which shares the radio
 * with Bluetooth through MPSL on its own. Driver callouts only queue:
 * received frames into a small ring of the driver's own buffers, a transmit
 * result into two words.
 */
#include "tg_zephyr_int.h"

#include <tinygrid/tg_plat.h>

#include <nrf_802154.h>

#include <string.h>

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
	k_sem_give(&tg_zephyr_wake);
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
	k_sem_give(&tg_zephyr_wake);
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
	k_sem_give(&tg_zephyr_wake);
}

int tg_zephyr_radio_init(void)
{
	nrf_802154_init();
	nrf_802154_tx_power_set(CONFIG_TINYGRID_TX_POWER);
	return 0;
}

void tg_zephyr_radio_poll(void)
{
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
}
