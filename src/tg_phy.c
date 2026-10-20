/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The logic half of an 802.15.4 radio for a Thread 1.1 child. It keeps what
 * tg_mac.c would keep (data and command frames with both addresses, no IEs)
 * and ACKs what a 2006 radio ACKs. A 2015 frame asking for an ACK wants an
 * enhanced one, which this radio cannot send, so it is dropped; a parent
 * talking to a 1.1 child never sends one.
 */
#include <tinygrid/tg_phy.h>

#include <string.h>

#define MIN_BE 3u /* macMinBE */
#define MAX_BE 5u /* macMaxBE */

void tg_phy_addr_set(struct tg_phy_addr *a, uint16_t pan, uint16_t short_addr, const uint8_t ext[8])
{
	a->pan = pan;
	a->short_addr = short_addr;
	for (int i = 0; i < 8; i++) {
		a->ext[i] = ext[7 - i];
	}
}

int tg_phy_filter(const struct tg_phy_addr *a, const uint8_t *f, uint8_t len)
{
	uint16_t fcf, s;
	uint8_t type, ver, dam, sam, i = 3;
	bool ar;

	if (len < 3u) {
		return TG_PHY_DROP;
	}
	fcf = (uint16_t)(f[0] | f[1] << 8);
	type = fcf & 7u;
	ver = (fcf >> 12) & 3u;
	dam = (fcf >> 10) & 3u;
	sam = (fcf >> 14) & 3u;
	ar = (fcf & 0x20u) != 0u;
	if ((type != 1u && type != 3u) || ver > 2u || (ver == 2u && ar) || (fcf & 0x0200u) ||
	    dam < 2u || sam < 2u) {
		return TG_PHY_DROP;
	}
	if (ver == 2u && (fcf & 0x0100u)) {
		i = 2; /* sequence number suppressed */
	}
	/* The destination PAN is there, except in a 2015 frame between two
	 * extended addresses with PAN ID compression. */
	if (!(ver == 2u && dam == 3u && sam == 3u && (fcf & 0x40u))) {
		if (i + 2u > len) {
			return TG_PHY_DROP;
		}
		s = (uint16_t)(f[i] | f[i + 1] << 8);
		if (s != a->pan && s != 0xffffu) {
			return TG_PHY_DROP;
		}
		i += 2;
	}
	if (dam == 2u) {
		if (i + 2u > len) {
			return TG_PHY_DROP;
		}
		s = (uint16_t)(f[i] | f[i + 1] << 8);
		if (s == 0xffffu) {
			return TG_PHY_KEEP; /* broadcast: never ACKed */
		}
		if (s != a->short_addr || s == 0xfffeu) {
			return TG_PHY_DROP;
		}
	} else if (i + 8u > len || memcmp(f + i, a->ext, 8) != 0) {
		return TG_PHY_DROP;
	}
	return ar ? TG_PHY_ACK : TG_PHY_KEEP;
}

void tg_phy_ack(uint8_t ack[3], uint8_t seq)
{
	ack[0] = 0x02; /* ACK, 2003 version, no frame pending */
	ack[1] = 0x00;
	ack[2] = seq;
}

bool tg_phy_ack_rx(const uint8_t *f, uint8_t len, uint8_t seq, bool *pending)
{
	if (len != 3u || (f[0] & 7u) != 2u || (f[1] >> 4 & 3u) > 1u || f[2] != seq) {
		return false;
	}
	*pending = (f[0] & 0x10u) != 0u;
	return true;
}

uint32_t tg_phy_backoff_us(uint8_t nb, uint32_t rnd)
{
	uint8_t be = (uint8_t)(MIN_BE + nb > MAX_BE ? MAX_BE : MIN_BE + nb);

	return (rnd & ((1u << be) - 1u)) * TG_PHY_BACKOFF_US;
}

uint32_t tg_phy_air_us(uint8_t len)
{
	return (6u + len + 2u) * 32u; /* 4 B preamble, SFD, PHR; 2 B FCS */
}

uint32_t tg_phy_tx_us_max(uint8_t len, bool ack)
{
	uint32_t t = tg_phy_air_us(len) + (ack ? TG_PHY_ACK_WAIT_US : 0u);

	for (uint8_t nb = 0; nb < TG_PHY_CSMA_TRIES; nb++) {
		t += tg_phy_backoff_us(nb, UINT32_MAX) + TG_PHY_CCA_US;
	}
	return t;
}
