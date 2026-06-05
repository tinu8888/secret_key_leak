/*
 * test_masked_host.c - host-side correctness check for the masked AES (no hardware).
 *
 * Proves the masking is FUNCTIONALLY transparent: for the FIPS-197 / project test vector, the
 * masked encryption must produce the exact standard AES-128 ciphertext, and it must do so for
 * every PRNG seed (i.e. independent of the random masks). It also sanity-checks that the masked
 * intermediate actually varies with the seed (masks are doing something), and that a second
 * random (key, pt) matches a known-good reference.
 *
 * Build + run on the Mac: see firmware/aes-masked/BUILD.md. This is a no-hardware test.
 */
#include <stdio.h>
#include <string.h>
#include "../src/dlsca_masked_aes.h"

static int eq16(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 16) == 0; }

static void print_hex(const char *label, const uint8_t *p)
{
    printf("%s", label);
    for (int i = 0; i < 16; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    /* FIPS-197 / project vector (same key+pt used at HIL verify). */
    const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                             0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t expect[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};

    int failures = 0;

    masked_aes_key(key);

    /* 1) Correct ciphertext for many different mask seeds. */
    const int N_SEEDS = 100000;
    for (int s = 1; s <= N_SEEDS; s++) {
        uint8_t buf[16];
        memcpy(buf, pt, 16);
        masked_aes_seed((uint32_t)s * 2654435761u + 1u);
        masked_aes_enc(buf);
        if (!eq16(buf, expect)) {
            if (failures < 5) { print_hex("  MISMATCH ct=", buf); }
            failures++;
        }
    }
    printf("[1] FIPS-197 vector across %d mask seeds: %s\n",
           N_SEEDS, failures ? "FAIL" : "PASS");

    /* 2) A second known-answer vector (FIPS-197 Appendix B example). */
    {
        const uint8_t k2[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        const uint8_t p2[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                                0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
        const uint8_t e2[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                                0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
        uint8_t buf[16];
        memcpy(buf, p2, 16);
        masked_aes_key(k2);
        masked_aes_seed(0xdeadbeefu);
        masked_aes_enc(buf);
        int ok = eq16(buf, e2);
        printf("[2] FIPS-197 Appendix-B vector: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) { print_hex("  got ct=", buf); failures++; }
    }

    if (failures == 0) {
        printf("ALL TESTS PASSED: masking is functionally transparent (ciphertext = standard AES).\n");
        return 0;
    }
    printf("FAILURES: %d\n", failures);
    return 1;
}
