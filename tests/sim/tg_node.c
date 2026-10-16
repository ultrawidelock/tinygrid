/* SPDX-License-Identifier: ISC */
/*
 * A tinygrid node for the simulation, driven by lines on stdin:
 *
 *   start <dataset hex>         tg_start()
 *   state                       role, ready, addresses
 *   udp <addr> <port> <text>    send from port 5540
 *   udpn <addr> <port> <n>      send n bytes from port 5540
 *   srp host <label>
 *   srp add <instance> <type> <port> [subtype|-] [lease s]
 *   srp del <instance>
 *   srp reset                   remove each service by name, then the host
 *   mcast <port> <text>         send to ff03::1 from port 5540
 *   resolve <instance> <type>   DNS-SD: SRV, then AAAA
 *   clear                       tg_clear()
 *
 * Port 5540 echoes whatever it receives. Events print as "ev ...".
 */
#include "tg_host.h"

#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <arpa/inet.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char line[4096];
static size_t line_len;

static void pr_addr(const char *what, const uint8_t a[16])
{
	char s[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, a, s, sizeof(s));
	printf("%s %s\n", what, s);
}

static void state(void)
{
	uint8_t a[16];

	printf("ev state role=%d ready=%d\n", tg_role(), tg_ready());
	if (tg_mleid(a)) {
		pr_addr("ev mleid", a);
	}
	if (tg_omr(a)) {
		pr_addr("ev omr", a);
	}
	fflush(stdout);
}

static void srp_states(void);

void tg_plat_changed(void)
{
	state();
	srp_states();
}

static void echo(struct tg_udp *s, const uint8_t src[16], uint16_t sport, const uint8_t dst[16],
		 uint8_t *d, size_t n)
{
	char a[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, src, a, sizeof(a));
	printf("ev udp from %s %u len %zu\n", a, sport, n);
	fflush(stdout);
	(void)tg_udp_send(dst, s->port, src, sport, d, n);
}

static struct tg_udp sock = {.port = 5540, .rx = echo};

static void resolved(void *ctx, int err, const uint8_t *addr, uint16_t port)
{
	(void)ctx;
	if (err == TG_OK) {
		char a[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, addr, a, sizeof(a));
		printf("ev dns ok %s %u\n", a, port);
	} else {
		printf("ev dns fail %d\n", err);
	}
	fflush(stdout);
}

#define NSVC 4
static struct tg_srp_svc svc[NSVC];
static char names[NSVC][64], types[NSVC][32], subs[NSVC][32];
static const char *subp[NSVC][1];
static char host[64];
static const uint8_t txt[] = {7, 'S', 'I', 'I', '=', '5', '0', '0'};

static void srp_states(void)
{
	for (int i = 0; i < NSVC; i++) {
		if (svc[i].instance) {
			printf("ev srp svc %s state %u\n", svc[i].instance, svc[i].state);
		}
	}
	printf("ev srp pending %d\n", tg_srp_pending());
	fflush(stdout);
}

static int hexval(char c)
{
	return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

static void cmd(char *l)
{
	char *v[7] = {0};
	int n = 0;

	for (char *t = strtok(l, " \t\r\n"); t && n < 7; t = strtok(NULL, " \t\r\n")) {
		v[n++] = t;
	}
	if (n == 0) {
		return;
	}
	if (!strcmp(v[0], "start") && n == 2) {
		static uint8_t ds[256];
		size_t k = strlen(v[1]) / 2u;

		for (size_t i = 0; i < k && i < sizeof(ds); i++) {
			ds[i] = (uint8_t)(hexval(v[1][2 * i]) << 4 | hexval(v[1][2 * i + 1]));
		}
		printf("ev start %d\n", tg_start(ds, k));
	} else if (!strcmp(v[0], "state")) {
		state();
	} else if ((!strcmp(v[0], "udp") || !strcmp(v[0], "udpn")) && n == 4) {
		static uint8_t buf[1300];
		uint8_t dst[16];
		size_t len;

		inet_pton(AF_INET6, v[1], dst);
		if (v[0][3] == 'n') {
			len = (size_t)atoi(v[3]);
			for (size_t i = 0; i < len && i < sizeof(buf); i++) {
				buf[i] = (uint8_t)i;
			}
		} else {
			len = strlen(v[3]);
			memcpy(buf, v[3], len);
		}
		printf("ev udp send %d\n", tg_udp_send(NULL, 5540, dst, (uint16_t)atoi(v[2]), buf, len));
	} else if (!strcmp(v[0], "srp") && n >= 2) {
		if (!strcmp(v[1], "host") && n == 3) {
			snprintf(host, sizeof(host), "%s", v[2]);
			printf("ev srp host %d\n", tg_srp_host(host));
		} else if (!strcmp(v[1], "add") && n >= 5) {
			for (int i = 0; i < NSVC; i++) {
				if (svc[i].state == TG_SRP_IDLE) {
					snprintf(names[i], sizeof(names[i]), "%s", v[2]);
					snprintf(types[i], sizeof(types[i]), "%s", v[3]);
					svc[i].instance = names[i];
					svc[i].type = types[i];
					svc[i].port = (uint16_t)atoi(v[4]);
					svc[i].txt = txt;
					svc[i].txt_len = sizeof(txt);
					svc[i].nsub = 0;
					svc[i].lease_s = n == 7 ? (uint32_t)atoi(v[6]) : 0u;
					if (n >= 6 && strcmp(v[5], "-") != 0) {
						snprintf(subs[i], sizeof(subs[i]), "%s", v[5]);
						subp[i][0] = subs[i];
						svc[i].subtypes = subp[i];
						svc[i].nsub = 1;
					}
					printf("ev srp add %d\n", tg_srp_add(&svc[i]));
					break;
				}
			}
		} else if (!strcmp(v[1], "del") && n == 3) {
			for (int i = 0; i < NSVC; i++) {
				if (svc[i].state != TG_SRP_IDLE && !strcmp(names[i], v[2])) {
					printf("ev srp del %d\n", tg_srp_remove(&svc[i]));
				}
			}
		} else if (!strcmp(v[1], "reset")) {
			tg_srp_reset(true);
			printf("ev srp reset\n");
		}
		for (int i = 0; i < NSVC; i++) {
			if (svc[i].instance) {
				printf("ev srp svc %s state %u\n", svc[i].instance, svc[i].state);
			}
		}
	} else if (!strcmp(v[0], "srpstate")) {
		for (int i = 0; i < NSVC; i++) {
			if (svc[i].instance) {
				printf("ev srp svc %s state %u\n", svc[i].instance, svc[i].state);
			}
		}
	} else if (!strcmp(v[0], "mcast") && n == 3) {
		static const uint8_t all[16] = {0xff, 0x03, [15] = 1};

		printf("ev mcast send %d\n",
		       tg_udp_send(NULL, 5540, all, (uint16_t)atoi(v[1]), (uint8_t *)v[2], strlen(v[2])));
	} else if (!strcmp(v[0], "resolve") && n == 3) {
		static char inst[64], type[32];

		snprintf(inst, sizeof(inst), "%s", v[1]);
		snprintf(type, sizeof(type), "%s", v[2]);
		printf("ev resolve %d\n", tg_dns_resolve(inst, type, resolved, NULL));
	} else if (!strcmp(v[0], "clear")) {
		tg_clear();
	} else if (!strcmp(v[0], "quit")) {
		exit(0);
	} else {
		printf("ev error unknown command\n");
	}
	fflush(stdout);
}

int main(int argc, char **argv)
{
	int id = argc > 1 ? atoi(argv[1]) : 2;
	uint32_t poll = argc > 2 ? (uint32_t)atoi(argv[2]) : 0u;
	const char *dir = argc > 3 ? argv[3] : ".";

	if (psa_crypto_init() != PSA_SUCCESS || tg_host_init(id, dir) != 0) {
		return 1;
	}
	tg_init(poll);
	tg_udp_bind(&sock);
	printf("ev up node %d poll %u\n", id, poll);
	fflush(stdout);
	for (;;) {
		int r = tg_host_step(STDIN_FILENO);

		if (r < 0) {
			return 1;
		}
		if (r == 1) {
			ssize_t k = read(STDIN_FILENO, line + line_len, sizeof(line) - 1 - line_len);
			char *nl;

			if (k <= 0) {
				return 0;
			}
			line_len += (size_t)k;
			line[line_len] = 0;
			while ((nl = strchr(line, '\n')) != NULL) {
				*nl = 0;
				cmd(line);
				memmove(line, nl + 1, line_len - (size_t)(nl + 1 - line) + 1);
				line_len -= (size_t)(nl + 1 - line);
			}
		}
	}
}
