/* SPDX-License-Identifier: ISC */
/* Between tg_zephyr.c, which runs the stack, and the radio port under it. */
#pragma once

#include <zephyr/kernel.h>

/** Given whenever the stack's thread has something to do. */
extern struct k_sem tg_zephyr_wake;

/** Once, before the thread starts. */
int tg_zephyr_radio_init(void);

/** On the stack's thread with the lock held: hand queued frames to
 * tg_radio_rx(). */
void tg_zephyr_radio_poll(void);
