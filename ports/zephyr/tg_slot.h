/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The slot provider under tg_radio_nrf52.c: who lends the RADIO, and for how
 * long. Two of them: MPSL timeslots next to Nordic's SoftDevice Controller
 * (tg_slot_mpsl.c), and the Zephyr Bluetooth controller's own scheduler
 * (tg_slot_zll.c). The radio calls down with tg_slot_*(); the provider calls
 * up with tg_radio_*(), always in the slot's interrupt context.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <hal/nrf_timer.h>

/* A slot, and what the radio asks for when it extends one. */
#define TG_SLOT_US 10000u

/* The slot's clock: 32 bits of microseconds from the start of the slot, the
 * provider's to start. MPSL hands over TIMER0 running; the Zephyr controller
 * keeps TIMER0 and TIMER1, so there it is TIMER2. */
#if defined(CONFIG_MPSL)
#define TG_SLOT_TIMER NRF_TIMER0
#else
#define TG_SLOT_TIMER NRF_TIMER2
#endif

/* ---- down: the radio to the provider ------------------------------------- */

/** Once, from the thread, after the radio's own setup. */
int tg_slot_init(void);

/** From the thread: a slot as soon as the scheduler allows. Nothing if one is
 * requested or running already. */
void tg_slot_request(void);

/** A slot is requested or running. */
bool tg_slot_pending(void);

/** In the slot: keep the radio another @p us. The provider answers with
 * tg_radio_slot_extended() or tg_radio_slot_stop(), at once or later. */
void tg_slot_extend(uint32_t us);

/** In the slot: give the radio back now. The provider asks for the next slot
 * itself while tg_radio_wants_slot(). */
void tg_slot_end(void);

/* ---- up: the provider to the radio --------------------------------------- */

/** The RADIO and TG_SLOT_TIMER are the radio's until tg_slot_end() or
 * tg_radio_slot_stop(); the timer runs from zero. */
void tg_radio_slot_start(void);

/** The extension asked for was granted. */
void tg_radio_slot_extended(uint32_t us);

/** The provider takes the radio back now: stop everything, no tg_slot_end(). */
void tg_radio_slot_stop(void);

/** The RADIO's DISABLED interrupt. */
void tg_radio_irq(void);

/** TG_SLOT_TIMER's COMPARE0 interrupt. */
void tg_radio_timer_irq(void);

/** Whether the radio has work for a slot. */
bool tg_radio_wants_slot(void);
