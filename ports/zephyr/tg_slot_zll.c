/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tg_slot.h on the Zephyr Bluetooth controller: tinygrid's radio is one more
 * event in the controller's own scheduler, with a ticker node of its own
 * (CONFIG_BT_CTLR_USER_EXT) and a place in the lower link layer's prepare
 * pipeline, like an advertiser or a connection.
 *
 * Bluetooth first, by construction. The node reserves no air time, so the
 * ticker never skips a Bluetooth event for it. A slot is not started while a
 * Bluetooth event runs (prepare() looks first and comes back later), and a
 * Bluetooth event falling due while a slot runs preempts it: is_abort_cb()
 * yields, abort_cb() stops the radio and the slot ends through the slot timer,
 * never from under the caller that aborted it. The flash driver's radio sync
 * aborts a slot the same way.
 *
 * Contexts. The ticker fires at the controller's ULL_HIGH priority; prepare()
 * and everything after it run at its radio (LLL) priority, where no kernel
 * call is allowed. The RADIO interrupt is the controller's, which hands over
 * on DISABLED and nothing else; the slot timer is TIMER2, with its interrupt
 * at the same priority.
 */
#include "tg_slot.h"

#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/atomic.h>

#include "hal/ccm.h"
#include "hal/radio.h"
#include "hal/ticker.h"
#include "util/memq.h"
#include "util/mayfly.h"
#include "ticker/ticker.h"
#include "pdu_df.h"
#include "lll/pdu_vendor.h"
#include "pdu.h"
#include "lll.h"
#include "lll_clock.h"
#include "lll/lll_vendor.h"
#include "lll/lll_internal.h"
#include "hci/hci_user_ext.h"
#include "hal/debug.h"

#define FIRST_US (EVENT_OVERHEAD_XTAL_US + 100u) /* the crystal, after a quiet spell */
#define GAP_US 500u                              /* between two slots of ours */
#define RETRY_US 2000u                           /* a Bluetooth event was running */
#define ABORT_US 20u                             /* from abort_cb() to the slot's end */

static void prepare(void *param);

/* The controller's view of this event: an upper half it counts prepares on,
 * and a lower half that points back at it. */
static struct ull_hdr s_ull;
static struct {
	struct lll_hdr hdr;
} s_lll = {.hdr.parent = &s_ull};
static struct lll_prepare_param s_prep;
static memq_link_t s_link;
static struct mayfly s_mfy = {0, 0, &s_link, &s_prep, prepare};

static atomic_t s_sess; /* a slot is requested or running */
static bool s_hf;       /* the HF clock is ours until the work runs out */
static bool s_aborting; /* the timer's next compare ends an aborted slot */

static void op_cb(uint32_t status, void *ctx)
{
	ARG_UNUSED(ctx);
	LL_ASSERT(status == TICKER_STATUS_SUCCESS);
}

static void ticker_cb(uint32_t ticks_at_expire, uint32_t ticks_drift, uint32_t remainder,
		      uint16_t lazy, uint8_t force, void *ctx)
{
	uint32_t ret;

	ARG_UNUSED(ticks_drift);
	ARG_UNUSED(ctx);
	s_ull.ref++;
	s_prep.ticks_at_expire = ticks_at_expire;
	s_prep.remainder = remainder;
	s_prep.lazy = lazy;
	s_prep.force = force;
	s_prep.defer = 0;
	s_prep.param = &s_lll;
	ret = mayfly_enqueue(TICKER_USER_ID_ULL_HIGH, TICKER_USER_ID_LLL, 0, &s_mfy);
	LL_ASSERT(!ret);
}

/* The slot's ticker, @p us from now, from ticker user @p user. */
static void arm(uint8_t user, uint32_t us)
{
	uint32_t ret;

	ret = ticker_start(TICKER_INSTANCE_ID_CTLR, user, TICKER_ID_USER_BASE,
			   ticker_ticks_now_get(), HAL_TICKER_US_TO_TICKS(us), TICKER_NULL_PERIOD,
			   TICKER_NULL_REMAINDER, TICKER_NULL_LAZY, TICKER_NULL_SLOT, ticker_cb, NULL,
			   op_cb, NULL);
	LL_ASSERT(ret == TICKER_STATUS_SUCCESS || ret == TICKER_STATUS_BUSY);
}

/* A slot, if the radio wants one and none is on the way. */
static bool request(uint8_t user)
{
	if (!tg_radio_wants_slot() || !atomic_cas(&s_sess, 0, 1)) {
		return false;
	}
	if (!s_hf) {
		s_hf = true;
		(void)lll_hfclock_on();
		arm(user, FIRST_US);
	} else {
		arm(user, GAP_US);
	}
	return true;
}

/* ---- the event, at the radio priority ---------------------------------- */

static void radio_isr(void *param)
{
	ARG_UNUSED(param);
	tg_radio_irq();
}

static void isr_none(void *param)
{
	ARG_UNUSED(param);
}

/* The slot is over and the controller has the radio: tell it, then the next
 * slot or the clock's release. */
static void done(void)
{
	struct event_done_extra *e;

	radio_isr_set(isr_none, NULL);
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_STOP);
	e = ull_event_done_extra_get();
	if (e) {
		e->type = EVENT_DONE_EXTRA_TYPE_NONE;
	}
	lll_done(NULL);
	atomic_set(&s_sess, 0);
	if (!request(TICKER_USER_ID_LLL) && s_hf) {
		s_hf = false;
		(void)lll_hfclock_off();
	}
}

ISR_DIRECT_DECLARE(timer_isr)
{
	if (s_aborting) {
		s_aborting = false;
		nrf_timer_event_clear(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE0);
		nrf_timer_int_disable(TG_SLOT_TIMER, NRF_TIMER_INT_COMPARE0_MASK);
		done();
	} else {
		tg_radio_timer_irq();
	}
	return 0;
}

static int prepare_cb(struct lll_prepare_param *p)
{
	ARG_UNUSED(p);
	radio_isr_set(radio_isr, NULL);
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_STOP);
	nrf_timer_mode_set(TG_SLOT_TIMER, NRF_TIMER_MODE_TIMER);
	nrf_timer_bit_width_set(TG_SLOT_TIMER, NRF_TIMER_BIT_WIDTH_32);
	nrf_timer_prescaler_set(TG_SLOT_TIMER, NRF_TIMER_FREQ_1MHz);
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_CLEAR);
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_START);
	tg_radio_slot_start();
	return 0;
}

/* Whatever comes next wins. */
static int is_abort_cb(void *next, void *curr, lll_prepare_cb_t *resume_cb)
{
	ARG_UNUSED(next);
	ARG_UNUSED(curr);
	ARG_UNUSED(resume_cb);
	return -ECANCELED;
}

static void abort_cb(struct lll_prepare_param *p, void *param)
{
	if (p) {
		/* Cancelled in the pipeline: nothing of ours was running. */
		lll_done(param);
		arm(TICKER_USER_ID_LLL, RETRY_US);
		return;
	}
	/* The controller takes the radio now. The done goes out from the
	 * timer's interrupt, once the caller is off the pipeline. */
	tg_radio_slot_stop();
	s_aborting = true;
	nrf_timer_task_trigger(TG_SLOT_TIMER, NRF_TIMER_TASK_CAPTURE3);
	nrf_timer_event_clear(TG_SLOT_TIMER, NRF_TIMER_EVENT_COMPARE0);
	nrf_timer_cc_set(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL0,
			 nrf_timer_cc_get(TG_SLOT_TIMER, NRF_TIMER_CC_CHANNEL3) + ABORT_US);
	nrf_timer_int_enable(TG_SLOT_TIMER, NRF_TIMER_INT_COMPARE0_MASK);
}

static void prepare(void *param)
{
	bool is_resume;
	int err;

	/* A Bluetooth event running, or one waiting behind it: look again
	 * later rather than preempt it. */
	if (!lll_is_done(NULL, &is_resume) || ull_prepare_dequeue_get()) {
		s_ull.ref--;
		arm(TICKER_USER_ID_LLL, RETRY_US);
		return;
	}
	err = lll_prepare(is_abort_cb, abort_cb, prepare_cb, 0, param);
	LL_ASSERT(!err || err == -EINPROGRESS);
}

/* ---- tg_slot.h ---------------------------------------------------------- */

void tg_slot_extend(uint32_t us)
{
	tg_radio_slot_extended(us);
}

void tg_slot_end(void)
{
	done();
}

bool tg_slot_pending(void)
{
	return atomic_get(&s_sess) != 0;
}

void tg_slot_request(void)
{
	(void)request(TICKER_USER_ID_THREAD);
}

int tg_slot_init(void)
{
	IRQ_DIRECT_CONNECT(TIMER2_IRQn, CONFIG_BT_CTLR_LLL_PRIO, timer_isr, 0);
	irq_enable(TIMER2_IRQn);
	return 0;
}

/* ---- the controller's user-extension hooks it links against ------------ */

int8_t hci_user_ext_get_class(struct node_rx_pdu *node_rx)
{
	ARG_UNUSED(node_rx);
	return 0; /* HCI_CLASS_NONE */
}

void hci_user_ext_encode_control(struct node_rx_pdu *node_rx, struct pdu_data *pdu_data,
				 struct net_buf *buf)
{
	ARG_UNUSED(node_rx);
	ARG_UNUSED(pdu_data);
	ARG_UNUSED(buf);
}
