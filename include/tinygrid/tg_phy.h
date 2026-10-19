/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file tg_phy.h — what an 802.15.4 radio decides rather than does: which
 * frames to keep and which to ACK, the ACK itself, and CSMA-CA timing. For a
 * port that drives a radio without a vendor driver; the host port uses it
 * for the simulated radio.
 *
 * Frames here are the PSDU without the FCS.
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* 2.4 GHz O-QPSK: 16 us a symbol, 32 us an octet. */
#define TG_PHY_TURNAROUND_US 192u /* aTurnaroundTime: frame end to ACK start */
#define TG_PHY_BACKOFF_US 320u    /* aUnitBackoffPeriod */
#define TG_PHY_CCA_US 128u        /* 8 symbols */
#define TG_PHY_ACK_WAIT_US 864u   /* macAckWaitDuration, ACK included */
#define TG_PHY_CSMA_TRIES 5u      /* macMaxCSMABackoffs 4, plus the first */

struct tg_phy_addr {
	uint16_t pan, short_addr; /* short_addr 0xfffe: none */
	uint8_t ext[8];           /* as on air: little-endian */
};

/** The arguments of tg_plat_radio_set(); ext in canonical order. */
void tg_phy_addr_set(struct tg_phy_addr *a, uint16_t pan, uint16_t short_addr, const uint8_t ext[8]);

enum { TG_PHY_DROP = 0, TG_PHY_KEEP = 1, TG_PHY_ACK = 2 /* keep, and ACK it */ };

/** A received data or command frame: whether it is for this node. ACKs go
 * to tg_phy_ack_rx() instead. */
int tg_phy_filter(const struct tg_phy_addr *a, const uint8_t *f, uint8_t len);

/** The immediate ACK for sequence number @p seq; the radio appends the FCS. */
void tg_phy_ack(uint8_t ack[3], uint8_t seq);

/** Whether @p f is the ACK for the frame sent with @p seq; @p pending gets
 * its frame-pending bit. */
bool tg_phy_ack_rx(const uint8_t *f, uint8_t len, uint8_t seq, bool *pending);

/** The wait before CCA number @p nb (0 to TG_PHY_CSMA_TRIES - 1), from a
 * random @p rnd. */
uint32_t tg_phy_backoff_us(uint8_t nb, uint32_t rnd);

/** On air: preamble, SFD, PHR, @p len bytes and the FCS. */
uint32_t tg_phy_air_us(uint8_t len);

/** The longest a transmit can take, CSMA-CA and ACK wait included, radio
 * ramp-up not: what a port reserves the radio for. */
uint32_t tg_phy_tx_us_max(uint8_t len, bool ack);

#ifdef __cplusplus
}
#endif
