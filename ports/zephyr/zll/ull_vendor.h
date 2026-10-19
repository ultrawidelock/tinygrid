/* SPDX-License-Identifier: ISC */
/*
 * The Zephyr Bluetooth controller's vendor hooks, which it includes under
 * CONFIG_BT_CTLR_USER_EXT. tinygrid's radio turns that on for a ticker node of
 * its own (tg_slot_zll.c); it has no proprietary PDUs or events, so every hook
 * is a no-op. The operation counts are the slot's: one ticker start from the
 * thread, one from the radio context.
 */
#pragma once

/* memq_link_t comes from the includer, which has util/memq.h (no guard of
 * its own) before this. */
#include <stdint.h>

#define TICKER_USER_THREAD_VENDOR_OPS 1
#define TICKER_USER_LLL_VENDOR_OPS 1

struct node_rx_hdr;
struct node_rx_event_done;

static inline int ull_user_init(void)
{
	return 0;
}

static inline int rx_demux_rx_proprietary(memq_link_t *link, struct node_rx_hdr *rx,
					  memq_link_t *tail, memq_link_t **head)
{
	(void)link;
	(void)rx;
	(void)tail;
	(void)head;
	return 0;
}

static inline void ull_proprietary_done(struct node_rx_event_done *evdone)
{
	(void)evdone;
}
