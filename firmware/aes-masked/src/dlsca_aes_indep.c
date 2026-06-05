/*
 * dlsca_aes_indep.c - adapt the masked AES to the ChipWhisperer simpleserial-aes interface.
 *
 * simpleserial-aes.c calls aes_indep_init / _key / _enc (+ pre/post trigger + mask hooks).
 * Building with CRYPTO_TARGET=NONE means the kit links NO crypto, so these symbols come from
 * here, routing to our portable first-order masked AES. The 'k'/'p' protocol and the GPIO
 * trigger (raised around aes_indep_enc in simpleserial-aes.c) are therefore byte-for-byte
 * identical to the unprotected build, so the US1/US2 host attacks run unchanged.
 */
#include <stdint.h>
#include "dlsca_masked_aes.h"

/* Default key matches the kit's aes-independant.h FIPS-197 test key (overwritten by 'k'). */
void aes_indep_init(void)
{
    /* Seed the mask PRNG. On STM32F0 there is no hardware RNG; SCA101-style firmware can
     * mix in a SysTick/counter value here for per-power-up variation. Fixed default keeps
     * the build deterministic until that wiring is added (documented in README.md). */
    masked_aes_seed(0xC0FFEE11u);
}

void aes_indep_key(uint8_t *key)
{
    masked_aes_key(key);
}

void aes_indep_enc(uint8_t *pt)
{
    masked_aes_enc(pt); /* in place: pt -> ciphertext */
}

void aes_indep_enc_pretrigger(uint8_t *pt)
{
    (void)pt;
}

void aes_indep_enc_posttrigger(uint8_t *pt)
{
    (void)pt;
}

void aes_indep_mask(uint8_t *m, uint8_t len)
{
    (void)m;
    (void)len; /* masks are generated internally by the software PRNG, not host-supplied */
}
