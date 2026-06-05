/*
 * dlsca_masked_aes.c - first-order Boolean-masked AES-128, portable C (Cortex-M0 friendly).
 *
 * Correctness invariant (proved by the host test against the FIPS-197 vector):
 *   at every step the working byte ms[i] equals (true_state[i] ^ mask[i]); the unmask at the
 *   end recovers the standard AES ciphertext. Linearity of ShiftRows/MixColumns/AddRoundKey
 *   lets us push the mask array through them unchanged in form; SubBytes is handled by a
 *   masked S-box table MSbox[x ^ Min] = Sbox[x] ^ Mout rebuilt with fresh (Min, Mout) each
 *   encryption. The plaintext is masked BEFORE the first AddRoundKey, so p ^ k is never clear.
 *
 * Security note (honest): masks come from a software xorshift PRNG because the STM32F0 has no
 * hardware RNG. Mask quality is therefore only as good as the PRNG + its seeding; the on-target
 * capture + a re-run of the first-order attack is the real test of whether the leak is gone.
 */
#include "dlsca_masked_aes.h"

/* --------------------------------------------------------------------------------------
 * AES constant tables.
 * ------------------------------------------------------------------------------------ */
static const uint8_t SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[10] = {
  0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* --------------------------------------------------------------------------------------
 * Software PRNG for masks (xorshift32). No HW RNG on STM32F0; documented limitation.
 * ------------------------------------------------------------------------------------ */
static uint32_t prng_state = 0x1234abcdu;

void masked_aes_seed(uint32_t seed)
{
    prng_state = seed ? seed : 0xa5a5a5a5u; /* avoid the zero fixed point */
}

static uint8_t prng_byte(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return (uint8_t)(x & 0xff);
}

/* --------------------------------------------------------------------------------------
 * Key schedule (standard AES-128, not part of the masked path: keys are public structure).
 * ------------------------------------------------------------------------------------ */
static uint8_t round_keys[176]; /* 11 round keys x 16 bytes */

void masked_aes_key(const uint8_t *key)
{
    for (int i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }
    for (int i = 16; i < 176; i += 4) {
        uint8_t t0 = round_keys[i - 4];
        uint8_t t1 = round_keys[i - 3];
        uint8_t t2 = round_keys[i - 2];
        uint8_t t3 = round_keys[i - 1];
        if ((i % 16) == 0) {
            uint8_t tmp = t0;            /* RotWord + SubWord + Rcon */
            t0 = SBOX[t1] ^ RCON[(i / 16) - 1];
            t1 = SBOX[t2];
            t2 = SBOX[t3];
            t3 = SBOX[tmp];
        }
        round_keys[i + 0] = round_keys[i - 16 + 0] ^ t0;
        round_keys[i + 1] = round_keys[i - 16 + 1] ^ t1;
        round_keys[i + 2] = round_keys[i - 16 + 2] ^ t2;
        round_keys[i + 3] = round_keys[i - 16 + 3] ^ t3;
    }
}

/* --------------------------------------------------------------------------------------
 * GF(2^8) helpers and AES linear layers (applied to both data and the mask array).
 * ------------------------------------------------------------------------------------ */
static uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

static void add_round_key(uint8_t *ms, int round)
{
    const uint8_t *rk = &round_keys[round * 16];
    for (int i = 0; i < 16; i++) {
        ms[i] ^= rk[i]; /* mask array unchanged: AddRoundKey is data-only */
    }
}

/* ShiftRows applied identically to whatever array is passed (data or mask). */
static void shift_rows(uint8_t *s)
{
    uint8_t t;
    /* row 1: shift left by 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* row 2: shift left by 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3: shift left by 3 */
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

/* MixColumns is GF(2)-linear, so applying it to the mask array tracks the mask exactly. */
static void mix_columns(uint8_t *s)
{
    for (int c = 0; c < 4; c++) {
        uint8_t *col = &s[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        col[0] ^= all ^ xtime((uint8_t)(a0 ^ a1));
        col[1] ^= all ^ xtime((uint8_t)(a1 ^ a2));
        col[2] ^= all ^ xtime((uint8_t)(a2 ^ a3));
        col[3] ^= all ^ xtime((uint8_t)(a3 ^ a0));
    }
}

/* --------------------------------------------------------------------------------------
 * Masked encryption.
 * ------------------------------------------------------------------------------------ */
void masked_aes_enc(uint8_t *block)
{
    uint8_t ms[16];      /* masked state: ms[i] = true_state[i] ^ mask[i] */
    uint8_t mask[16];    /* current mask of each state byte */
    uint8_t msbox[256];  /* masked S-box: msbox[x ^ Min] = SBOX[x] ^ Mout */

    /* Fresh randomness for this encryption. */
    uint8_t min = prng_byte();
    uint8_t mout = prng_byte();
    for (int x = 0; x < 256; x++) {
        msbox[(uint8_t)(x ^ min)] = (uint8_t)(SBOX[x] ^ mout);
    }

    /* Mask the plaintext BEFORE the first AddRoundKey (so p ^ k is never in the clear). */
    for (int i = 0; i < 16; i++) {
        mask[i] = prng_byte();
        ms[i] = (uint8_t)(block[i] ^ mask[i]);
    }

    add_round_key(ms, 0);

    for (int round = 1; round <= 10; round++) {
        /* Masked SubBytes: remask each byte to Min, table-lookup, mask becomes Mout. */
        for (int i = 0; i < 16; i++) {
            ms[i] ^= (uint8_t)(mask[i] ^ min); /* now masked by Min; still no clear value */
            ms[i] = msbox[ms[i]];              /* = SBOX[true] ^ Mout */
            mask[i] = mout;
        }
        shift_rows(ms);
        shift_rows(mask);
        if (round != 10) {
            mix_columns(ms);
            mix_columns(mask);
        }
        add_round_key(ms, round);
    }

    /* Unmask -> standard AES ciphertext (public output). */
    for (int i = 0; i < 16; i++) {
        block[i] = (uint8_t)(ms[i] ^ mask[i]);
    }
}
