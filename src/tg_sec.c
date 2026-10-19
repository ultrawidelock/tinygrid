/* SPDX-License-Identifier: Apache-2.0 */
/*
 * AES-CCM* as Thread uses it: 13-byte nonce, 2-byte length field and a 4-byte
 * tag (security level 5, ENC-MIC-32) for both MAC frames and MLE messages.
 * Built on the port's single-block AES so no CCM mode is needed from the
 * crypto library.
 */
#include "tg_int.h"

static void cbc(const uint8_t *key, uint8_t x[16], uint8_t *pos, const uint8_t *d, size_t n)
{
	uint8_t t[16];

	while (n--) {
		x[(*pos)++] ^= *d++;
		if (*pos == 16u) {
			tg_plat_aes(key, x, t);
			memcpy(x, t, 16);
			*pos = 0;
		}
	}
}

static void cbc_flush(const uint8_t *key, uint8_t x[16], uint8_t *pos)
{
	uint8_t t[16];

	if (*pos != 0u) {
		tg_plat_aes(key, x, t);
		memcpy(x, t, 16);
		*pos = 0;
	}
}

static void ctr(const uint8_t *key, const uint8_t nonce[13], uint8_t *m, size_t mlen)
{
	uint8_t a[16], s[16];

	a[0] = 1u;
	memcpy(a + 1, nonce, 13);
	for (size_t i = 0; i < mlen; i += 16u) {
		put16(a + 14, (uint16_t)(i / 16u + 1u));
		tg_plat_aes(key, a, s);
		for (size_t k = 0; k < 16u && i + k < mlen; k++) {
			m[i + k] ^= s[k];
		}
	}
}

int tg_ccm(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *a, size_t alen,
	   uint8_t *m, size_t mlen, uint8_t *tag, bool enc)
{
	uint8_t b[16], x[16], s[16], pos = 0;
	uint8_t l[2];
	uint8_t diff = 0;

	if (!enc) {
		ctr(key, nonce, m, mlen);
	}
	b[0] = (uint8_t)((alen ? 0x40u : 0u) | (((4u - 2u) / 2u) << 3) | (2u - 1u));
	memcpy(b + 1, nonce, 13);
	put16(b + 14, (uint16_t)mlen);
	tg_plat_aes(key, b, x);
	if (alen) {
		put16(l, (uint16_t)alen);
		cbc(key, x, &pos, l, 2);
		cbc(key, x, &pos, a, alen);
		cbc_flush(key, x, &pos);
	}
	cbc(key, x, &pos, m, mlen);
	cbc_flush(key, x, &pos);

	b[0] = 1u;
	put16(b + 14, 0);
	tg_plat_aes(key, b, s);
	for (int i = 0; i < 4; i++) {
		uint8_t u = x[i] ^ s[i];

		if (enc) {
			tag[i] = u;
		} else {
			diff |= u ^ tag[i];
		}
	}
	if (enc) {
		ctr(key, nonce, m, mlen);
	}
	return diff ? -1 : 0;
}

void tg_nonce(uint8_t n[13], const uint8_t ext[8], uint32_t fc)
{
	memcpy(n, ext, 8);
	put32(n + 8, fc);
	n[12] = 5u;
}
