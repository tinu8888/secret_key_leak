/*
 * dlsca_masked_aes.h - first-order Boolean-masked AES-128 for Cortex-M0 (US3 defense).
 *
 * Portable C (no platform assembly), so it builds on the ChipWhisperer-Nano's STM32F0
 * (Cortex-M0) where the kit's ANSSI/RIOUBSAES masked AES will not (those need Cortex-M4/AVR).
 *
 * Masking scheme: every state byte is carried as (data ^ mask) with the mask tracked in a
 * parallel array. Linear steps (ShiftRows, MixColumns, AddRoundKey) are applied to the mask
 * array too; SubBytes uses a per-encryption recomputed masked S-box table. The real value of
 * any state byte never appears unmasked, so a first-order CPA/CNN attack on a single sample
 * sees noise. See README.md for the scheme write-up and its limits.
 */
#ifndef DLSCA_MASKED_AES_H
#define DLSCA_MASKED_AES_H

#include <stdint.h>

/* Seed the software mask PRNG (no hardware RNG on STM32F0). */
void masked_aes_seed(uint32_t seed);

/* Set the 16-byte AES-128 key (expands round keys internally). */
void masked_aes_key(const uint8_t *key);

/* Encrypt one 16-byte block in place (pt -> ciphertext), masked end to end. */
void masked_aes_enc(uint8_t *block);

#endif /* DLSCA_MASKED_AES_H */
