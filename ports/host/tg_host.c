/* SPDX-License-Identifier: ISC */
/*
 * Host port: time, files for persistence, and a radio that speaks
 * OpenThread's simulation protocol, so a tinygrid node can join a network of
 * ot-cli-ftd nodes on one machine.
 *
 * The simulation radio (openthread examples/platforms/simulation) sends every
 * frame as one UDP datagram, [channel][PSDU with FCS], to 224.0.0.116 port
 * 9000 from port 9000 + node id, on 127.0.0.1. There is no hardware, so this
 * file does what a radio does: address filtering and ACKs (tg_phy.h), the
 * ACK wait, and holding what arrives during a transmit, four frames deep.
 */
#define _DEFAULT_SOURCE
#include "tg_host.h"

#include <tinygrid/tg.h>
#include <tinygrid/tg_phy.h>
#include <tinygrid/tg_plat.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT_BASE 9000
#define GROUP "224.0.0.116"
#define ACK_WAIT_MS 16u
#define HELD 4u

static int rx_fd = -1, tx_fd = -1, node;
static struct sockaddr_in group;
static const char *kv_dir = ".";

static uint8_t r_chan = 11;
static struct tg_phy_addr r_addr = {.pan = 0xffffu, .short_addr = 0xfffeu};
static bool r_on;

static bool ack_wait, ack_pend, in_tx;
static uint8_t ack_seq;

/* Frames that arrived while a transmit waited, for after it. */
static struct {
	uint8_t f[127], len;
} held[HELD];
static uint8_t held_head, held_n;

uint32_t tg_plat_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void kv_path(char *p, size_t n, uint8_t key)
{
	snprintf(p, n, "%s/tg-%d-%u.bin", kv_dir, node, key);
}

int tg_plat_load(uint8_t key, void *buf, size_t len)
{
	char p[512];
	FILE *f;
	size_t n;

	kv_path(p, sizeof(p), key);
	f = fopen(p, "rb");
	if (f == NULL) {
		return -1;
	}
	n = fread(buf, 1, len, f);
	fclose(f);
	return (int)n;
}

int tg_plat_save(uint8_t key, const void *buf, size_t len)
{
	char p[512];
	FILE *f;

	kv_path(p, sizeof(p), key);
	f = fopen(p, "wb");
	if (f == NULL) {
		return -1;
	}
	fwrite(buf, 1, len, f);
	fclose(f);
	return 0;
}


void tg_plat_radio_set(uint8_t channel, uint16_t pan, uint16_t short_addr, const uint8_t ext[8])
{
	r_chan = channel;
	tg_phy_addr_set(&r_addr, pan, short_addr, ext);
}

void tg_plat_radio_rx(bool on)
{
	r_on = on;
}

/* CRC-16/KERMIT, as the simulation computes the FCS. */
static uint16_t fcs(const uint8_t *p, size_t n)
{
	uint16_t c = 0;

	while (n--) {
		c ^= *p++;
		for (int i = 0; i < 8; i++) {
			c = (c & 1u) ? (uint16_t)((c >> 1) ^ 0x8408u) : (uint16_t)(c >> 1);
		}
	}
	return c;
}

static void trace(const char *dir, const uint8_t *f, uint8_t len)
{
	static int on = -1;

	if (on < 0) {
		on = getenv("TG_TRACE") != NULL;
	}
	if (on) {
		fprintf(stderr, "%u %s", tg_plat_now() % 100000u, dir);
		for (uint8_t i = 0; i < len; i++) {
			fprintf(stderr, "%02x", f[i]);
		}
		fprintf(stderr, "\n");
	}
}

static void sim_send(const uint8_t *psdu, uint8_t len)
{
	uint8_t m[1 + 127];
	uint16_t c = fcs(psdu, len);

	trace("tx ", psdu, len);

	m[0] = r_chan;
	memcpy(m + 1, psdu, len);
	m[1 + len] = (uint8_t)c;
	m[2 + len] = (uint8_t)(c >> 8);
	(void)sendto(tx_fd, m, (size_t)len + 3u, 0, (struct sockaddr *)&group, sizeof(group));
}

static void sim_rx(void);

int tg_plat_radio_tx(const uint8_t *psdu, uint8_t len, bool *pending)
{
	uint32_t due = tg_plat_now() + ACK_WAIT_MS;

	*pending = false;
	sim_send(psdu, len);
	if (!(psdu[0] & 0x20u)) {
		return TG_TX_OK;
	}
	ack_wait = in_tx = true;
	ack_seq = psdu[2];
	while (ack_wait) {
		int32_t d = (int32_t)(due - tg_plat_now());
		struct timeval tv;
		fd_set rs;

		if (d <= 0) {
			ack_wait = in_tx = false;
			return TG_TX_NOACK;
		}
		tv.tv_sec = 0;
		tv.tv_usec = d * 1000;
		FD_ZERO(&rs);
		FD_SET(rx_fd, &rs);
		if (select(rx_fd + 1, &rs, NULL, NULL, &tv) > 0) {
			sim_rx();
		}
	}
	in_tx = false;
	*pending = ack_pend;
	return TG_TX_OK;
}

static void sim_rx(void)
{
	uint8_t m[256];
	struct sockaddr_in from;
	socklen_t fl = sizeof(from);
	ssize_t n = recvfrom(rx_fd, m, sizeof(m), 0, (struct sockaddr *)&from, &fl);
	uint8_t *f = m + 1, len;
	bool pending;
	int keep;

	if (n < 6 || ntohs(from.sin_port) == PORT_BASE + node || m[0] != r_chan) {
		return;
	}
	len = (uint8_t)(n - 3); /* channel byte and FCS */
	trace("rx ", f, len);
	if ((f[0] & 7u) == 2u) { /* an ACK */
		if (ack_wait && tg_phy_ack_rx(f, len, ack_seq, &pending)) {
			ack_wait = false;
			ack_pend = pending;
		}
		return;
	}
	keep = r_on ? tg_phy_filter(&r_addr, f, len) : TG_PHY_DROP;
	if (keep == TG_PHY_DROP || (in_tx && held_n == HELD)) {
		return; /* with nowhere to hold it, not ACKed either */
	}
	if (keep == TG_PHY_ACK) {
		uint8_t a[3];

		tg_phy_ack(a, f[2]);
		sim_send(a, 3);
	}
	if (in_tx) {
		uint8_t i = (uint8_t)((held_head + held_n++) % HELD);

		memcpy(held[i].f, f, len);
		held[i].len = len;
		return;
	}
	tg_radio_rx(f, len, -20);
}

int tg_host_init(int node_id, const char *dir)
{
	struct sockaddr_in a;
	struct ip_mreq mreq;
	struct in_addr lo;
	int one = 1;

	node = node_id;
	kv_dir = dir;
	inet_pton(AF_INET, "127.0.0.1", &lo);
	memset(&group, 0, sizeof(group));
	group.sin_family = AF_INET;
	group.sin_port = htons(PORT_BASE);
	inet_pton(AF_INET, GROUP, &group.sin_addr);

	rx_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(rx_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt(rx_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	setsockopt(rx_fd, IPPROTO_IP, IP_MULTICAST_IF, &lo, sizeof(lo));
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr = group.sin_addr;
	mreq.imr_interface = lo;
	if (setsockopt(rx_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0 ||
	    bind(rx_fd, (struct sockaddr *)&group, sizeof(group)) != 0) {
		perror("sim rx socket");
		return -1;
	}

	tx_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr = lo;
	a.sin_port = htons((uint16_t)(PORT_BASE + node));
	setsockopt(tx_fd, IPPROTO_IP, IP_MULTICAST_IF, &lo, sizeof(lo));
	setsockopt(tx_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
	if (bind(tx_fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
		perror("sim tx socket");
		return -1;
	}
	return 0;
}

int tg_host_step(int extra_fd)
{
	uint32_t wait = tg_process();
	struct timeval tv;
	fd_set rs;
	int mx = rx_fd > extra_fd ? rx_fd : extra_fd;

	if (held_n) {
		uint8_t i = held_head;

		held_head = (uint8_t)((held_head + 1u) % HELD);
		held_n--;
		tg_radio_rx(held[i].f, held[i].len, -20);
		return 0;
	}
	if (wait > 1000u) {
		wait = 1000u;
	}
	tv.tv_sec = wait / 1000u;
	tv.tv_usec = (wait % 1000u) * 1000u;
	FD_ZERO(&rs);
	FD_SET(rx_fd, &rs);
	if (extra_fd >= 0) {
		FD_SET(extra_fd, &rs);
	}
	if (select(mx + 1, &rs, NULL, NULL, &tv) < 0) {
		return errno == EINTR ? 0 : -1;
	}
	if (FD_ISSET(rx_fd, &rs)) {
		sim_rx();
	}
	return extra_fd >= 0 && FD_ISSET(extra_fd, &rs) ? 1 : 0;
}
