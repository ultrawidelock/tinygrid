/* SPDX-License-Identifier: ISC */
/*
 * tg_plat.h on Zephyr, minus the radio: time, settings, the lock and the one
 * thread that runs the stack. No OpenThread, no IEEE 802.15.4 L2, no network
 * stack. The radio port (tg_radio_*.c) only queues from its interrupts; this
 * thread delivers.
 */
#include "tg_zephyr_int.h"

#include <tinygrid/tg_zephyr.h>

#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <psa/crypto.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <stdio.h>

static K_MUTEX_DEFINE(s_lock);
K_SEM_DEFINE(tg_zephyr_wake, 0, 1);

void tg_zephyr_lock(void)
{
	(void)k_mutex_lock(&s_lock, K_FOREVER);
}

void tg_zephyr_unlock(void)
{
	(void)k_mutex_unlock(&s_lock);
	k_sem_give(&tg_zephyr_wake);
}

__weak void tg_zephyr_changed(void) {}

void tg_plat_changed(void)
{
	tg_zephyr_changed();
}

uint32_t tg_plat_now(void)
{
	return k_uptime_get_32();
}

/* ---- persistence ------------------------------------------------------- */

struct ld {
	void *buf;
	size_t len;
	int got;
};

static int ld_cb(const char *name, size_t len, settings_read_cb rd, void *arg, void *param)
{
	struct ld *l = param;

	if (name != NULL && name[0] != '\0') {
		return 0; /* a deeper name, not this leaf */
	}
	if (len <= l->len) {
		ssize_t n = rd(arg, l->buf, len);

		l->got = n == (ssize_t)len ? (int)len : -1;
	}
	return 0;
}

int tg_plat_load(uint8_t key, void *buf, size_t len)
{
	char name[8];
	struct ld l = {.buf = buf, .len = len, .got = -1};

	(void)snprintf(name, sizeof(name), "tg/%u", key);
	return settings_load_subtree_direct(name, ld_cb, &l) == 0 ? l.got : -1;
}

int tg_plat_save(uint8_t key, const void *buf, size_t len)
{
	char name[8];

	(void)snprintf(name, sizeof(name), "tg/%u", key);
	return settings_save_one(name, buf, len) == 0 ? 0 : -1;
}

/* ---- the stack's thread ------------------------------------------------ */

static void run(void *a, void *b, void *c)
{
	uint32_t wait = UINT32_MAX;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);
	for (;;) {
		(void)k_sem_take(&tg_zephyr_wake, wait == UINT32_MAX ? K_FOREVER : K_MSEC(wait));
		tg_zephyr_lock();
		tg_zephyr_radio_poll();
		wait = tg_process();
		(void)k_mutex_unlock(&s_lock);
	}
}

K_THREAD_STACK_DEFINE(s_stack, CONFIG_TINYGRID_STACK_SIZE);
static struct k_thread s_thread;

static int tg_zephyr_init(void)
{
	if (psa_crypto_init() != PSA_SUCCESS || settings_subsys_init() != 0 ||
	    tg_zephyr_radio_init() != 0) {
		return -EIO;
	}
	(void)tg_init(CONFIG_TINYGRID_POLL_MS);
	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack), run, NULL, NULL,
			NULL, CONFIG_TINYGRID_THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "tinygrid");
	return 0;
}

SYS_INIT(tg_zephyr_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
