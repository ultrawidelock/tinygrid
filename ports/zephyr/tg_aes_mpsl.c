/* SPDX-License-Identifier: ISC */
/*
 * tg_plat_aes() on the ECB peripheral, through the MPSL call the Bluetooth
 * controller links anyway: no key import and no PSA call per block, which
 * matters with each frame sealed one block at a time.
 */
#include <tinygrid/tg_plat.h>

#include <mpsl_ecb.h>

void tg_plat_aes(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	mpsl_ecb_block_encrypt_extended(key, in, out, MPSL_ECB_NO_FLAGS); /* big-endian, as AES */
}
