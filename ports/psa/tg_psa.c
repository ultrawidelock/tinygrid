/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tg_plat.h's crypto on PSA Crypto: AES-ECB, HMAC-SHA-256 and the SRP host
 * key, all through calls a Matter node links anyway. HMAC is built on the
 * hash, since psa_mac_compute() would link PSA's MAC layer for this alone.
 *
 * The SRP key is volatile and its private half is kept in tg_plat_save() under
 * TG_KV_SRP, so no persistent-key storage is needed from the crypto library.
 */
#include <tinygrid/tg.h>
#include <tinygrid/tg_plat.h>

#include <psa/crypto.h>

#include <stdbool.h>
#include <string.h>

#ifndef TG_PSA_AES /* 0 when the port has its own tg_plat_aes() */
#define TG_PSA_AES 1
#endif

#if TG_PSA_AES
/* Two keys alternate all day (MLE and MAC); cache both. */
static struct {
	psa_key_id_t id;
	uint8_t key[16];
	bool used;
} aes[2];
static uint8_t aes_next;

void tg_plat_aes(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	size_t olen;
	int i;

	for (i = 0; i < 2; i++) {
		if (aes[i].used && memcmp(aes[i].key, key, 16) == 0) {
			break;
		}
	}
	if (i == 2) {
		i = aes_next;
		aes_next ^= 1u;
		if (aes[i].used) {
			(void)psa_destroy_key(aes[i].id);
			aes[i].used = false;
		}
		psa_set_key_type(&a, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&a, 128);
		psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
		psa_set_key_algorithm(&a, PSA_ALG_ECB_NO_PADDING);
		if (psa_import_key(&a, key, 16, &aes[i].id) != PSA_SUCCESS) {
			memset(out, 0, 16);
			return;
		}
		memcpy(aes[i].key, key, 16);
		aes[i].used = true;
	}
	if (psa_cipher_encrypt(aes[i].id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &olen) !=
	    PSA_SUCCESS) {
		memset(out, 0, 16);
	}
}
#endif

/* RFC 2104: SHA-256(key ^ opad || SHA-256(key ^ ipad || msg)). */
void tg_plat_hmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[32])
{
	uint8_t pad[64];
	size_t n;

	for (int outer = 0; outer < 2; outer++) {
		psa_hash_operation_t h = PSA_HASH_OPERATION_INIT;

		memset(pad, outer ? 0x5c : 0x36, sizeof(pad));
		for (int i = 0; i < 16; i++) {
			pad[i] ^= key[i];
		}
		if (psa_hash_setup(&h, PSA_ALG_SHA_256) != PSA_SUCCESS ||
		    psa_hash_update(&h, pad, sizeof(pad)) != PSA_SUCCESS ||
		    psa_hash_update(&h, outer ? out : msg, outer ? 32u : len) != PSA_SUCCESS ||
		    psa_hash_finish(&h, out, 32, &n) != PSA_SUCCESS) {
			(void)psa_hash_abort(&h);
			memset(out, 0, 32);
			return;
		}
	}
}

static psa_key_id_t srp_id;

static int srp_key(void)
{
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t priv[32];
	size_t n;
	int rc = -1;

	if (srp_id) {
		return 0;
	}
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&a, 256);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	if (tg_plat_load(TG_KV_SRP, priv, sizeof(priv)) == (int)sizeof(priv)) {
		rc = psa_import_key(&a, priv, sizeof(priv), &srp_id) == PSA_SUCCESS ? 0 : -1;
	} else if (psa_generate_key(&a, &srp_id) == PSA_SUCCESS) {
		rc = psa_export_key(srp_id, priv, sizeof(priv), &n) == PSA_SUCCESS &&
				     tg_plat_save(TG_KV_SRP, priv, sizeof(priv)) == 0
			     ? 0
			     : -1;
	}
	memset(priv, 0, sizeof(priv));
	if (rc != 0 && srp_id) {
		(void)psa_destroy_key(srp_id);
		srp_id = 0;
	}
	return rc;
}

void tg_srp_key_reset(void)
{
	if (srp_id) {
		(void)psa_destroy_key(srp_id);
		srp_id = 0;
	}
	(void)tg_plat_save(TG_KV_SRP, NULL, 0);
}

int tg_plat_srp_pub(uint8_t pub[64])
{
	uint8_t b[65];
	size_t n;

	if (srp_key() != 0 || psa_export_public_key(srp_id, b, sizeof(b), &n) != PSA_SUCCESS ||
	    n != 65u) {
		return -1;
	}
	memcpy(pub, b + 1, 64);
	return 0;
}

int tg_plat_srp_sign(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
		     uint8_t sig[64])
{
	psa_hash_operation_t h = PSA_HASH_OPERATION_INIT;
	uint8_t d[32];
	size_t n;

	if (srp_key() != 0 || psa_hash_setup(&h, PSA_ALG_SHA_256) != PSA_SUCCESS ||
	    psa_hash_update(&h, a, alen) != PSA_SUCCESS || psa_hash_update(&h, b, blen) != PSA_SUCCESS ||
	    psa_hash_finish(&h, d, sizeof(d), &n) != PSA_SUCCESS) {
		(void)psa_hash_abort(&h);
		return -1;
	}
	return psa_sign_hash(srp_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), d, sizeof(d), sig, 64, &n) ==
			       PSA_SUCCESS &&
		       n == 64u
		       ? 0
		       : -1;
}

void tg_plat_random(void *buf, size_t len)
{
	if (psa_generate_random(buf, len) != PSA_SUCCESS) {
		memset(buf, 0, len);
	}
}
