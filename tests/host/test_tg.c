/* SPDX-License-Identifier: ISC */
/*
 * Host unit tests: Thread key derivation and MLE encryption against the
 * Thread specification's vectors (as OpenThread's thread-cert test_crypto.py
 * carries them), and AES-CCM* against PSA's own CCM on random inputs.
 * Interoperation itself is tests/sim/interop.py's job.
 */
#include "tg_int.h"

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int fails, checks;

#define CHECK(c)                                                                                  \
	do {                                                                                      \
		checks++;                                                                         \
		if (!(c)) {                                                                       \
			fails++;                                                                  \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                       \
		}                                                                                 \
	} while (0)

/* The platform, minus a radio. */
uint32_t tg_plat_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
int tg_plat_load(uint8_t key, void *buf, size_t len)
{
	(void)key;
	(void)buf;
	(void)len;
	return -1;
}
int tg_plat_save(uint8_t key, const void *buf, size_t len)
{
	(void)key;
	(void)buf;
	(void)len;
	return 0;
}
void tg_plat_radio_set(uint8_t channel, uint16_t pan, uint16_t short_addr, const uint8_t ext[8])
{
	(void)channel;
	(void)pan;
	(void)short_addr;
	(void)ext;
}
void tg_plat_radio_rx(bool on) { (void)on; }
int tg_plat_radio_tx(const uint8_t *psdu, uint8_t len)
{
	(void)psdu;
	(void)len;
	return 0;
}
void tg_plat_changed(void) {}

static const uint8_t netkey[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

static void test_keys(void)
{
	static const uint8_t mle0[16] = {0x54, 0x45, 0xf4, 0x15, 0x8f, 0xd7, 0x59, 0x12,
					 0x17, 0x58, 0x09, 0xf8, 0xb5, 0x7a, 0x66, 0xa4};
	static const uint8_t mac0[16] = {0xde, 0x89, 0xc5, 0x3a, 0xf3, 0x82, 0xb4, 0x21,
					 0xe0, 0xfd, 0xe5, 0xa9, 0xba, 0xe3, 0xbe, 0xf0};
	static const uint8_t mle1[16] = {0x8f, 0x4c, 0xd1, 0xa2, 0x7d, 0x95, 0xc0, 0x7d,
					 0x12, 0xdb, 0x89, 0x74, 0xbd, 0x61, 0x5c, 0x13};
	static const uint8_t mac1[16] = {0x9b, 0xe0, 0xd1, 0xaf, 0x7b, 0xd8, 0x73, 0x50,
					 0xde, 0xab, 0xcd, 0xd0, 0x7f, 0xeb, 0xb9, 0xd5};
	uint8_t mle[16], mac[16];

	memcpy(tg.key, netkey, 16);
	tg_keys(0, mle, mac); /* Thread 1.1 7.1.4.1 */
	CHECK(memcmp(mle, mle0, 16) == 0);
	CHECK(memcmp(mac, mac0, 16) == 0);
	tg_keys(1, mle, mac); /* 7.1.4.2 */
	CHECK(memcmp(mle, mle1, 16) == 0);
	CHECK(memcmp(mac, mac1, 16) == 0);
}

static void test_mle_vector(void)
{
	static const uint8_t ext[8] = {0x00, 0x35, 0xcc, 0x94, 0xd7, 0x7a, 0x07, 0xe8};
	static const uint8_t plain[28] = {0x04, 0x00, 0x02, 0x00, 0x00, 0x09, 0x0b, 0x8f, 0x80, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x01, 0xf1, 0x0b, 0x08,
					  0x65, 0x5e, 0x0f, 0x83, 0x40, 0xc7, 0x83, 0x31};
	static const uint8_t want[32] = {0x9a, 0x5a, 0x9a, 0x5b, 0xba, 0x25, 0x9c, 0x5e, 0x58, 0xa2,
					 0x7e, 0x75, 0x74, 0xef, 0x79, 0xbc, 0x4f, 0xa3, 0xf9, 0xae,
					 0xa8, 0x34, 0xf6, 0xf2, 0x37, 0x21, 0x93, 0x60, 0xe1, 0xb5,
					 0xa2, 0x53};
	uint8_t a[42] = {0}, n[13], m[32], mle[16], mac[16];
	uint32_t fc = 262165;

	memcpy(tg.key, netkey, 16);
	tg_keys(0, mle, mac);
	tg_lladdr(a, ext); /* fe80::235:cc94:d77a:7e8 */
	a[16] = 0xff;
	a[17] = 0x02;
	a[31] = 0x02;
	a[32] = 0x15;
	putle32(a + 33, fc);
	put32(a + 37, 0);
	a[41] = 1;
	tg_nonce(n, ext, fc);
	memcpy(m, plain, 28);
	tg_ccm(mle, n, a, sizeof(a), m, 28, m + 28, true);
	CHECK(memcmp(m, want, 32) == 0);
	CHECK(tg_ccm(mle, n, a, sizeof(a), m, 28, m + 28, false) == 0);
	CHECK(memcmp(m, plain, 28) == 0);
	m[3] ^= 1u;
	CHECK(tg_ccm(mle, n, a, sizeof(a), m, 28, m + 28, false) != 0);
}

/* AES-CCM* with a 4-byte tag, against PSA's CCM. */
static void test_ccm_vs_psa(void)
{
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 4);
	uint8_t key[16], n[13], a[48], m[140], c[144], ours[144];
	psa_key_id_t id;
	size_t olen;

	for (int i = 0; i < 300; i++) {
		size_t ml = (size_t)(i % 131), al = (size_t)((i * 7) % 47);

		psa_generate_random(key, 16);
		psa_generate_random(n, 13);
		psa_generate_random(a, al);
		psa_generate_random(m, ml);
		psa_set_key_type(&at, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&at, 128);
		psa_set_key_usage_flags(&at, PSA_KEY_USAGE_ENCRYPT);
		psa_set_key_algorithm(&at, alg);
		CHECK(psa_import_key(&at, key, 16, &id) == PSA_SUCCESS);
		CHECK(psa_aead_encrypt(id, alg, n, 13, a, al, m, ml, c, sizeof(c), &olen) == PSA_SUCCESS);
		psa_destroy_key(id);
		memcpy(ours, m, ml);
		tg_ccm(key, n, a, al, ours, ml, ours + ml, true);
		CHECK(olen == ml + 4u && memcmp(ours, c, olen) == 0);
	}
}

int main(void)
{
	if (psa_crypto_init() != PSA_SUCCESS) {
		return 1;
	}
	test_keys();
	test_mle_vector();
	test_ccm_vs_psa();
	printf("%d/%d checks passed\n", checks - fails, checks);
	return fails ? 1 : 0;
}
