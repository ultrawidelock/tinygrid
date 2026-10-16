/* SPDX-License-Identifier: ISC */
/**
 * @file tg_plat.h — what a port provides to tinygrid, and the two radio
 * events it feeds back in.
 *
 * Everything here is called on the stack's context, and the port must call
 * tg_radio_rx() and tg_radio_tx_done() on that context too: a radio interrupt
 * queues, the stack's thread delivers.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Milliseconds, free running; wraps. */
uint32_t tg_plat_now(void);

void tg_plat_random(void *buf, size_t len);

/** One AES-128 block. Called often with the same key: cache it. */
void tg_plat_aes(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/** HMAC-SHA-256 with a 16-byte key. */
void tg_plat_hmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[32]);

/**
 * The SRP host key. pub is X || Y. sign hashes a || b with SHA-256 and
 * returns r || s. A port keeps the same key across reboots: a server binds
 * the host name to it.
 */
int tg_plat_srp_pub(uint8_t pub[64]);
int tg_plat_srp_sign(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
		     uint8_t sig[64]);

/** Persisted records. load returns the length read, or < 0 when absent. */
enum { TG_KV_STATE = 1, TG_KV_SRP = 2 /* a port's SRP key */ };
int tg_plat_load(uint8_t key, void *buf, size_t len);
int tg_plat_save(uint8_t key, const void *buf, size_t len);

/** Channel, PAN ID and addresses for frame filtering and auto-ACK. ext is
 * in canonical (big-endian) order. short_addr 0xfffe means none. */
void tg_plat_radio_set(uint8_t channel, uint16_t pan, uint16_t short_addr, const uint8_t ext[8]);

/** Receiver on (idle listening) or off (sleeping between polls). */
void tg_plat_radio_rx(bool on);

/**
 * Transmit one frame: the MAC header and payload, without the FCS. With an
 * ACK request in the frame the radio does CSMA-CA, waits for the ACK and
 * reports through tg_radio_tx_done(). Only one frame is ever outstanding.
 */
int tg_plat_radio_tx(const uint8_t *psdu, uint8_t len);

/** Something a user of tinygrid may care about changed (role, addresses, SRP). */
void tg_plat_changed(void);

enum { TG_TX_OK = 0, TG_TX_NOACK = 1, TG_TX_BUSY = 2 };

/** A frame without its FCS, past the radio's filter on the PAN ID and
 * destination address of tg_plat_radio_set() (as tg_phy_filter() does). */
void tg_radio_rx(const uint8_t *psdu, uint8_t len, int8_t rssi);

/** The frame passed to tg_plat_radio_tx() is done. @p pending: the ACK had
 * its frame-pending bit set. */
void tg_radio_tx_done(int result, bool pending);

#ifdef __cplusplus
}
#endif
