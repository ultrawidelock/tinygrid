/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tg_slot.h on MPSL timeslots, next to Nordic's SoftDevice Controller. One
 * session asks for the earliest 10 ms slot, Bluetooth first. MPSL calls slot()
 * from its RADIO and TIMER0 interrupts at the zero-latency priority; its
 * low-priority signals (blocked, cancelled, idle) come on its work queue with
 * its lock held, which is where a slot is requested again.
 */
#include "tg_slot.h"

#include <hal/nrf_radio.h>
#include <mpsl_timeslot.h>
#include <multithreading_lock.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

#include <errno.h>

BUILD_ASSERT(CONFIG_MPSL_TIMESLOT_SESSION_COUNT >= 1, "set CONFIG_MPSL_TIMESLOT_SESSION_COUNT=1");

static atomic_t s_sess; /* a slot is requested or running */
static mpsl_timeslot_session_id_t sid;
static mpsl_timeslot_signal_return_param_t ret;
static mpsl_timeslot_request_t s_req = {
	.request_type = MPSL_TIMESLOT_REQ_TYPE_EARLIEST,
	.params.earliest = {
		.hfclk = MPSL_TIMESLOT_HFCLK_CFG_XTAL_GUARANTEED,
		.priority = MPSL_TIMESLOT_PRIORITY_NORMAL,
		.length_us = TG_SLOT_US,
		.timeout_us = MPSL_TIMESLOT_EARLIEST_TIMEOUT_MAX_US,
	},
};

/* MPSL's lock held. */
static void request(void)
{
	if (tg_radio_wants_slot() && atomic_cas(&s_sess, 0, 1) &&
	    mpsl_timeslot_request(sid, &s_req) != 0) {
		atomic_set(&s_sess, 0);
	}
}

static mpsl_timeslot_signal_return_param_t *slot(mpsl_timeslot_session_id_t id, uint32_t signal)
{
	ARG_UNUSED(id);
	ret.callback_action = MPSL_TIMESLOT_SIGNAL_ACTION_NONE;
	switch (signal) {
	case MPSL_TIMESLOT_SIGNAL_START:
		/* MPSL starts it from zero at 1 MHz; 32 bits so 100 ms cannot wrap. */
		nrf_timer_task_trigger(NRF_TIMER0, NRF_TIMER_TASK_STOP);
		nrf_timer_bit_width_set(NRF_TIMER0, NRF_TIMER_BIT_WIDTH_32);
		nrf_timer_task_trigger(NRF_TIMER0, NRF_TIMER_TASK_START);
		/* MPSL routes the RADIO interrupt to slot() but leaves it
		 * disabled in the NVIC between Bluetooth events; the slot's
		 * owner enables it, as Nordic's driver does. */
		NVIC_ClearPendingIRQ(RADIO_IRQn);
		irq_enable(RADIO_IRQn);
		tg_radio_slot_start();
		break;
	case MPSL_TIMESLOT_SIGNAL_RADIO:
		tg_radio_irq();
		break;
	case MPSL_TIMESLOT_SIGNAL_TIMER0:
		tg_radio_timer_irq();
		break;
	case MPSL_TIMESLOT_SIGNAL_EXTEND_SUCCEEDED:
		tg_radio_slot_extended(TG_SLOT_US);
		break;
	case MPSL_TIMESLOT_SIGNAL_EXTEND_FAILED:
		tg_radio_slot_stop();
		tg_slot_end();
		break;
	/* The rest come on MPSL's work queue, its lock held. */
	case MPSL_TIMESLOT_SIGNAL_BLOCKED:
	case MPSL_TIMESLOT_SIGNAL_CANCELLED:
		(void)mpsl_timeslot_request(sid, &s_req);
		return NULL;
	case MPSL_TIMESLOT_SIGNAL_SESSION_IDLE:
		atomic_set(&s_sess, 0);
		request();
		return NULL;
	default:
		return NULL;
	}
	return &ret;
}

void tg_slot_extend(uint32_t us)
{
	ret.callback_action = MPSL_TIMESLOT_SIGNAL_ACTION_EXTEND;
	ret.params.extend.length_us = us;
}

void tg_slot_end(void)
{
	nrf_radio_int_disable(NRF_RADIO, NRF_RADIO_INT_DISABLED_MASK);
	irq_disable(RADIO_IRQn); /* as MPSL had it */
	ret.callback_action = MPSL_TIMESLOT_SIGNAL_ACTION_END;
}

bool tg_slot_pending(void)
{
	return atomic_get(&s_sess) != 0;
}

void tg_slot_request(void)
{
	(void)MULTITHREADING_LOCK_ACQUIRE();
	request();
	MULTITHREADING_LOCK_RELEASE();
}

int tg_slot_init(void)
{
	int err;

	(void)MULTITHREADING_LOCK_ACQUIRE();
	err = mpsl_timeslot_session_open(slot, &sid);
	MULTITHREADING_LOCK_RELEASE();
	return err == 0 ? 0 : -EIO;
}
