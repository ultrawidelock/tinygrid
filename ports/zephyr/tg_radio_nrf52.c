/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tg_plat.h's radio on the nRF52 RADIO itself, in place of Nordic's 802.15.4
 * driver. The radio is borrowed from the Bluetooth controller one slot at a
 * time, Bluetooth first: a slot is 10 ms, extended while there is work, never
 * past 100 ms in a row, and ended as soon as there is none. Who lends it is
 * tg_slot.h's business: MPSL next to Nordic's controller, or the Zephyr
 * controller's own scheduler.
 *
 * Contexts. The provider calls in from the RADIO and slot timer interrupts at
 * the controller's radio priority, where no kernel call is allowed; poke_isr()
 * runs at that priority too, so nothing in this file preempts anything else in
 * it. The stack's thread hands over requests through the req_ variables and a
 * poke; the slot hands back frames through a ring and a transmit result, and
 * wakes the thread from a kernel-aware interrupt.
 *
 * The radio ends every operation DISABLED, and that one interrupt drives the
 * whole machine: a received frame disables the receiver (END_DISABLE), an
 * acknowledgement or a frame of ours ends with PHYEND_DISABLE, a busy channel
 * with CCABUSY_DISABLE. The Zephyr controller's radio interrupt hands over on
 * nothing else.
 *
 * Inside a slot TG_SLOT_TIMER counts microseconds from its start, one job a
 * channel:
 *   CC0  the one interrupt: the slot's guard, a backoff or ACK wait, a poke
 *   CC1  TXEN for an ACK, by PPI, 192 us after the frame it answers
 *   CC2  captured at every RADIO END, by PPI
 *   CC3  captured by now()
 */
#include "tg_slot.h"
#include "tg_zephyr_int.h"

#include <tinygrid/tg_phy.h>
#include <tinygrid/tg_plat.h>

#include <hal/nrf_radio.h>
#include <hal/nrf_timer.h>
#include <helpers/nrfx_gppi.h>
#include <zephyr/irq.h>

#include <string.h>

#define SLOT_US TG_SLOT_US
#define SLOTS_MAX 10u /* then end, so a waiting flash write gets its turn */
#define GUARD_US 300u /* extend this long before the end; MPSL needs 87 us */
#define TX_RAMP_US 40u
#define END_LATENCY_US 23u /* last bit on air to RADIO END, Nordic's figure */
#define ACK_AT_US (TG_PHY_TURNAROUND_US - TX_RAMP_US - END_LATENCY_US)
#define CCA_ED 18u /* -75 dBm, Nordic's default; 0 is -93 dBm on the nRF52833 */
#define RXQ 4u     /* a power of two */

#define POKE_IRQ SWI0_EGU0_IRQn
#define WAKE_IRQ SWI1_EGU1_IRQn
#define WAKE_PRIO 5
#if defined(CONFIG_ZERO_LATENCY_IRQS)
#define POKE_FLAGS IRQ_ZERO_LATENCY
#else
#define POKE_FLAGS 0
#endif

/* Thread to slot. */
static volatile bool req_rx, req_tx, req_cfg;
static volatile uint8_t req_chan = 11;
static struct tg_phy_addr req_addr = {.pan = 0xffffu, .short_addr = 0xfffeu};
static uint8_t s_tx[1 + 127]; /* PHR, PSDU; the radio appends the FCS */

/* Slot to thread. */
static struct {
	uint8_t f[1 + 127];
	int8_t rssi;
} s_rxq[RXQ];
static volatile uint8_t s_rx_head, s_rx_tail; /* the thread moves head, the slot tail */
static volatile int8_t s_tx_res = -1;
static volatile bool s_tx_pend;

/* The slot's own. */
enum op { OP_OFF, OP_RX, OP_ACK, OP_TX, OP_ACK_WAIT };
static enum op op;
static bool in_slot, tx_active, backoff, op_armed, poked;
static uint8_t nb, slots, chan = 11;
static uint32_t guard_at, op_at, rnd;
static struct tg_phy_addr addr = {.pan = 0xffffu, .short_addr = 0xfffeu};
static uint8_t *s_cur;              /* where the receiver writes */
static uint8_t s_ack[1 + 3];        /* PHR and our ACK */
static uint8_t s_spare[1 + 127];    /* ACKs we wait for; frames with no room */
static nrfx_gppi_handle_t ppi_end, ppi_ack;

static bool want(void)
{
	return req_rx || req_tx || tx_active;
}

bool tg_radio_wants_slot(void)
{
	return want();
}

static void wake(void)
{
	NVIC_SetPendingIRQ(WAKE_IRQ);
}

static uint32_t rand32(void)
{
	rnd ^= rnd << 13;
	rnd ^= rnd >> 17;
	rnd ^= rnd << 5;
	return rnd;
}

static uint32_t now(void)
{
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_CAPTURE3);
	return nrf_timer_cc_get(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL3);
}

/* CC0 to the earliest of the guard, the operation's deadline and a poke. */
static void rearm(void)
{
	uint32_t at = op_armed && (int32_t)(op_at - guard_at) < 0 ? op_at : guard_at, t = now();

	if (poked || (int32_t)(at - t) < 5) {
		at = t + 5u;
	}
	nrf_timer_event_clear(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE0);
	nrf_timer_cc_set(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL0, at);
}

/* slot_guard() in a few microseconds: requests changed, or the work ran out. */
static void soon(void)
{
	poked = true;
	rearm();
}

static void op_timer(uint32_t us)
{
	op_at = now() + us;
	op_armed = true;
	rearm();
}

/* ---- the radio --------------------------------------------------------- */

static void radio_init(void)
{
	const nrf_radio_packet_conf_t pc = {
		.lflen = 8,
		.plen = NRF_RADIO_PREAMBLE_LENGTH_32BIT_ZERO,
		.crcinc = true,
		.maxlen = 127,
	};

	/* Off and on: whatever Bluetooth left in the registers is gone. */
	nrf_radio_power_set(NRF_RADIO, false);
	nrf_radio_power_set(NRF_RADIO, true);
	nrf_radio_mode_set(NRF_RADIO, NRF_RADIO_MODE_IEEE802154_250KBIT);
	nrf_radio_packet_configure(NRF_RADIO, &pc);
	nrf_radio_modecnf0_set(NRF_RADIO, true, 0); /* fast ramp-up: 40 us */
	nrf_radio_crc_configure(NRF_RADIO, 2, NRF_RADIO_CRC_ADDR_IEEE802154, 0x11021u);
	nrf_radio_cca_configure(NRF_RADIO, NRF_RADIO_CCA_MODE_ED, CCA_ED, 0x14, 2);
	nrf_radio_frequency_set(NRF_RADIO, (uint16_t)(2405u + 5u * (chan - 11u)));
	nrf_radio_txpower_set(NRF_RADIO, (nrf_radio_txpower_t)(uint8_t)CONFIG_TINYGRID_TX_POWER);
	/* The one interrupt, and the one the Zephyr controller keeps enabled
	 * between its own events. */
	nrf_radio_int_enable(NRF_RADIO, NRF_RADIO_INT_DISABLED_MASK);
}

/* To DISABLED, at once: receive ramps down in no time, transmit in 6 us. */
static void radio_off(void)
{
	nrfx_gppi_conn_disable(ppi_ack);
	nrf_radio_shorts_set(NRF_RADIO, 0);
	if (nrf_radio_state_get(NRF_RADIO) != NRF_RADIO_STATE_DISABLED) {
		nrf_radio_task_trigger(NRF_RADIO, NRF_RADIO_TASK_DISABLE);
		while (nrf_radio_state_get(NRF_RADIO) != NRF_RADIO_STATE_DISABLED) {
		}
	}
	nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_DISABLED);
	op = OP_OFF;
}

static void rx_arm(void)
{
	s_cur = (uint8_t)(s_rx_tail - s_rx_head) < RXQ ? s_rxq[s_rx_tail % RXQ].f : s_spare;
	nrf_radio_packetptr_set(NRF_RADIO, s_cur);
	nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_END);
	nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_ADDRESS);
}

/* Listen, from DISABLED; a frame leaves the radio DISABLED again. */
static void rx_start(void)
{
	rx_arm();
	nrf_radio_shorts_set(NRF_RADIO, NRF_RADIO_SHORT_RXREADY_START_MASK |
						NRF_RADIO_SHORT_ADDRESS_RSSISTART_MASK |
						NRF_RADIO_SHORT_END_DISABLE_MASK);
	nrf_radio_task_trigger(NRF_RADIO, NRF_RADIO_TASK_RXEN);
	op = OP_RX;
}

/* Whatever the receiver should do with no frame of ours on the way. */
static void idle(void)
{
	if (op == OP_ACK) {
		return; /* ack_sent() comes back here */
	}
	if (req_rx && op != OP_RX) {
		radio_off();
		rx_start();
	} else if (!req_rx && op != OP_OFF) {
		radio_off();
	}
}

/* ---- transmit ---------------------------------------------------------- */

static void tx_done(int res, bool pending)
{
	op_armed = tx_active = backoff = false;
	s_tx_pend = pending;
	s_tx_res = (int8_t)res;
	wake();
	idle();
	if (!want()) {
		soon(); /* end the slot */
	}
}

static void backoff_start(void)
{
	backoff = true;
	op_timer(tg_phy_backoff_us(nb, rand32()));
	idle(); /* keep listening meanwhile, if the receiver is on */
}

static void busy(void)
{
	if (++nb < TG_PHY_CSMA_TRIES) {
		backoff_start();
	} else {
		tx_done(TG_TX_BUSY, false);
	}
}

/* Backoff over: CCA, and on a clear channel the frame. */
static void cca_tx(void)
{
	backoff = false;
	if (op == OP_ACK || (op == OP_RX && nrf_radio_event_check(NRF_RADIO, NRF_RADIO_EVENT_ADDRESS))) {
		busy(); /* we are hearing a frame, or answering one */
		return;
	}
	radio_off();
	nrf_radio_packetptr_set(NRF_RADIO, s_tx);
	nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_CCABUSY);
	nrf_radio_shorts_set(NRF_RADIO, NRF_RADIO_SHORT_RXREADY_CCASTART_MASK |
						NRF_RADIO_SHORT_CCABUSY_DISABLE_MASK |
						NRF_RADIO_SHORT_CCAIDLE_TXEN_MASK |
						NRF_RADIO_SHORT_TXREADY_START_MASK |
						NRF_RADIO_SHORT_PHYEND_DISABLE_MASK);
	nrf_radio_task_trigger(NRF_RADIO, NRF_RADIO_TASK_RXEN);
	op = OP_TX;
}

/* DISABLED after OP_TX: the channel was busy, or the frame went out. */
static void tx_disabled(void)
{
	op = OP_OFF;
	if (nrf_radio_event_check(NRF_RADIO, NRF_RADIO_EVENT_CCABUSY)) {
		nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_CCABUSY);
		busy();
	} else if (s_tx[1] & 0x20u) { /* ACK requested */
		nrf_radio_packetptr_set(NRF_RADIO, s_spare);
		nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_END);
		nrf_radio_shorts_set(NRF_RADIO, NRF_RADIO_SHORT_RXREADY_START_MASK |
							NRF_RADIO_SHORT_END_DISABLE_MASK);
		nrf_radio_task_trigger(NRF_RADIO, NRF_RADIO_TASK_RXEN);
		op = OP_ACK_WAIT;
		op_timer(TX_RAMP_US + TG_PHY_ACK_WAIT_US);
	} else {
		tx_done(TG_TX_OK, false);
	}
}

/* DISABLED after a frame while waiting for the ACK. */
static void ack_wait_end(void)
{
	bool pending;

	if (nrf_radio_crc_status_check(NRF_RADIO) && s_spare[0] >= 2u &&
	    tg_phy_ack_rx(s_spare + 1, (uint8_t)(s_spare[0] - 2u), s_tx[3], &pending)) {
		radio_off();
		tx_done(TG_TX_OK, pending);
	} else {
		nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_END);
		nrf_radio_task_trigger(NRF_RADIO, NRF_RADIO_TASK_RXEN); /* not it: wait on */
	}
}

static void tx_begin(void)
{
	req_tx = false;
	tx_active = true;
	nb = 0;
	backoff_start();
}

/* ---- receive ----------------------------------------------------------- */

/* DISABLED after a frame: the receiver is off until told otherwise. */
static void rx_end(void)
{
	uint32_t t = nrf_timer_cc_get(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL2); /* END, by PPI */
	uint8_t *b = s_cur, n = b[0];
	int keep = TG_PHY_DROP;

	/* With the ring full nothing is kept, and nothing ACKed: the parent
	 * would count it delivered. */
	if (b != s_spare && nrf_radio_crc_status_check(NRF_RADIO) && n >= 5u && n <= 127u) {
		keep = tg_phy_filter(&addr, b + 1, (uint8_t)(n - 2u));
	}
	op = OP_OFF;
	if (keep == TG_PHY_ACK) {
		s_ack[0] = 5; /* 3 B and the FCS */
		tg_phy_ack(s_ack + 1, b[3]);
		nrf_radio_packetptr_set(NRF_RADIO, s_ack);
		nrf_radio_shorts_set(NRF_RADIO, NRF_RADIO_SHORT_TXREADY_START_MASK |
							NRF_RADIO_SHORT_PHYEND_DISABLE_MASK);
		nrf_timer_event_clear(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE1);
		nrf_timer_cc_set(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL1, t + ACK_AT_US);
		nrfx_gppi_conn_enable(ppi_ack);
		op = OP_ACK;
		if ((int32_t)(t + ACK_AT_US - now()) < 2) {
			radio_off(); /* too late to answer: drop it, the parent sends again */
			keep = TG_PHY_DROP;
		}
	}
	if (keep != TG_PHY_DROP) {
		s_rxq[s_rx_tail % RXQ].rssi = (int8_t)-nrf_radio_rssi_sample_get(NRF_RADIO);
		s_rx_tail++;
		wake();
	}
	if (op == OP_OFF) {
		idle(); /* listen on */
	}
}

static void ack_sent(void)
{
	nrfx_gppi_conn_disable(ppi_ack);
	op = OP_OFF;
	idle();
}

/* ---- the slot ---------------------------------------------------------- */

static void apply(void)
{
	if (req_cfg) {
		req_cfg = false;
		addr = req_addr;
		if (chan != req_chan) {
			chan = req_chan;
			if (op == OP_RX) {
				radio_off();
			}
			nrf_radio_frequency_set(NRF_RADIO, (uint16_t)(2405u + 5u * (chan - 11u)));
		}
	}
	if (req_tx && !tx_active) {
		tx_begin();
	} else if (!tx_active) {
		idle();
	}
}

/* Our side of a slot ending, whoever ends it. */
static void slot_release(void)
{
	radio_off();
	nrfx_gppi_conn_disable(ppi_end);
	nrf_timer_int_disable(TG_SLOT_TIMER, NRF_TIMER_INT_COMPARE0_MASK);
	if (tx_active) {
		tx_active = false; /* starts over in the next slot */
		req_tx = true;
	}
	backoff = op_armed = in_slot = false;
}

static void slot_stop(void)
{
	slot_release();
	tg_slot_end();
}

void tg_radio_slot_stop(void)
{
	slot_release();
}

void tg_radio_slot_start(uint32_t us)
{
	in_slot = true;
	slots = 1;
	guard_at = us > 2u * GUARD_US ? us - GUARD_US : GUARD_US;
	op_armed = poked = false;
	op = OP_OFF;
	radio_init();
	nrfx_gppi_conn_enable(ppi_end);
	rearm();
	nrf_timer_int_enable(TG_SLOT_TIMER, NRF_TIMER_INT_COMPARE0_MASK);
	apply();
}

void tg_radio_slot_extended(uint32_t us)
{
	slots++;
	guard_at += us;
	rearm();
}

static void slot_guard(void)
{
	apply();
	if (!want()) {
		slot_stop();
	} else if ((int32_t)(guard_at - now()) > 0) {
		rearm();
	} else if (slots < SLOTS_MAX) {
		tg_slot_extend(SLOT_US);
	} else {
		slot_stop(); /* the provider asks for the next one */
	}
}

void tg_radio_timer_irq(void)
{
	if (!nrf_timer_event_check(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE0)) {
		return;
	}
	nrf_timer_event_clear(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE0);
	if (op_armed && (int32_t)(now() - op_at) >= 0) {
		op_armed = false;
		if (backoff) {
			cca_tx();
		} else if (op == OP_ACK_WAIT) {
			radio_off();
			tx_done(TG_TX_NOACK, false);
		}
	}
	poked = false;
	slot_guard();
}

void tg_radio_irq(void)
{
	if (!nrf_radio_event_check(NRF_RADIO, NRF_RADIO_EVENT_DISABLED)) {
		return;
	}
	nrf_radio_event_clear(NRF_RADIO, NRF_RADIO_EVENT_DISABLED);
	switch (op) {
	case OP_RX:
		rx_end();
		break;
	case OP_ACK_WAIT:
		ack_wait_end();
		break;
	case OP_TX:
		tx_disabled();
		break;
	case OP_ACK:
		ack_sent();
		break;
	default:
		break;
	}
}

/* ---- the thread's side ------------------------------------------------- */

ISR_DIRECT_DECLARE(poke_isr)
{
	if (in_slot) {
		soon();
	}
	return 0;
}

static K_SEM_DEFINE(s_tx_done, 0, 1);

static void wake_isr(const void *arg)
{
	ARG_UNUSED(arg);
	if (s_tx_res >= 0) {
		k_sem_give(&s_tx_done);
	}
	k_sem_give(&tg_zephyr_wake);
}

/* A slot if none is coming, else a word with the one there is. */
static void kick(void)
{
	if (tg_slot_pending()) {
		NVIC_SetPendingIRQ(POKE_IRQ);
	} else if (want()) {
		tg_slot_request();
	}
}

void tg_plat_radio_set(uint8_t channel, uint16_t pan, uint16_t short_addr, const uint8_t ext[8])
{
	tg_phy_addr_set(&req_addr, pan, short_addr, ext);
	req_chan = channel;
	req_cfg = true;
	kick();
}

void tg_plat_radio_rx(bool on)
{
	req_rx = on;
	kick();
}

int tg_plat_radio_tx(const uint8_t *psdu, uint8_t len, bool *pending)
{
	int8_t r;

	s_tx[0] = (uint8_t)(len + 2u);
	memcpy(s_tx + 1, psdu, len);
	req_tx = true;
	kick();
	while ((r = s_tx_res) < 0) {
		(void)k_sem_take(&s_tx_done, K_FOREVER);
	}
	s_tx_res = -1;
	*pending = s_tx_pend;
	return r;
}

void tg_zephyr_radio_poll(void)
{
	while (s_rx_head != s_rx_tail) {
		uint8_t *f = s_rxq[s_rx_head % RXQ].f;

		tg_radio_rx(f + 1, (uint8_t)(f[0] - 2u), s_rxq[s_rx_head % RXQ].rssi);
		s_rx_head++;
	}
}

int tg_zephyr_radio_init(void)
{
	tg_plat_random(&rnd, sizeof(rnd));
	rnd |= 1u;
	if (nrfx_gppi_conn_alloc(nrf_radio_event_address_get(NRF_RADIO, NRF_RADIO_EVENT_END),
				 nrf_timer_task_address_get(TG_SLOT_TIMER, NRF_TIMER_TASK_CAPTURE2),
				 &ppi_end) != 0 ||
	    nrfx_gppi_conn_alloc(nrf_timer_event_address_get(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE1),
				 nrf_radio_task_address_get(NRF_RADIO, NRF_RADIO_TASK_TXEN),
				 &ppi_ack) != 0) {
		return -EIO;
	}
	IRQ_DIRECT_CONNECT(POKE_IRQ, 0, poke_isr, POKE_FLAGS);
	irq_enable(POKE_IRQ);
	IRQ_CONNECT(WAKE_IRQ, WAKE_PRIO, wake_isr, NULL, 0);
	irq_enable(WAKE_IRQ);
	return tg_slot_init();
}
