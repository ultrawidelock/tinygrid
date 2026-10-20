/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * matter_thread.h answered by nothing, for size measurement only. Every result
 * comes from a volatile so link-time optimisation cannot fold the callers'
 * success paths away, and the receive path still reaches the core's
 * matter_thread_on_datagram(), so the measured floor keeps all of tinytalk.
 */
#include <tinytalk/matter_thread.h>

#include <string.h>

static volatile int s_ret;
static volatile bool s_rx;
static uint8_t s_buf[1280];

static int reply_send(void *ctx, const uint8_t *msg, size_t len)
{
	(void)ctx;
	(void)msg;
	(void)len;
	return s_ret;
}

int matter_thread_start(const uint8_t *dataset, size_t len)
{
	if (s_rx) {
		size_t n = len < sizeof(s_buf) ? len : sizeof(s_buf);

		memcpy(s_buf, dataset, n);
		(void)matter_thread_on_datagram(s_buf, n, s_buf, sizeof(s_buf), reply_send, NULL);
	}
	return s_ret;
}

int matter_thread_clear(void) { return s_ret; }
bool matter_thread_attached_to(const uint8_t *xpanid) { (void)xpanid; return s_ret != 0; }
int matter_thread_wait_attached(uint32_t timeout_ms) { (void)timeout_ms; return s_ret; }
int matter_thread_advertise(const char *instance_name, uint16_t port)
{
	(void)instance_name;
	(void)port;
	return s_ret;
}
int matter_thread_unadvertise(const char *instance_name) { (void)instance_name; return s_ret; }
int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port)
{
	(void)discriminator;
	(void)port;
	return s_ret;
}
int matter_thread_unadvertise_commissionable(void) { return s_ret; }
void matter_thread_peer_current(struct matter_thread_peer *out)
{
	memset(out, 0, sizeof(*out));
	out->valid = s_ret != 0;
}
int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len)
{
	(void)peer;
	(void)msg;
	(void)len;
	return s_ret;
}
void matter_thread_advertise_reset(void) { s_ret = s_ret; }

int matter_thread_interface(struct matter_thread_iface *out)
{
	memset(out, 0, sizeof(*out));
	return s_ret;
}

int matter_thread_scan(struct matter_thread_scan_result *out, uint8_t cap, uint8_t *n)
{
	(void)out;
	(void)cap;
	*n = 0u;
	return s_ret;
}
