/*
 * masked_cli.c - run the masked AES once on host and print the ciphertext (no hardware).
 *
 * Lets the Python masking test suite drive the REAL masked C implementation
 * on arbitrary inputs and compare against a reference AES.
 *
 *   usage:  masked_cli <key-hex-32> <plaintext-hex-32> <seed-uint32>
 *   prints: 32 hex chars (the 16-byte ciphertext), newline.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/dlsca_masked_aes.h"

static int hex16(const char *s, uint8_t *out)
{
    if (strlen(s) != 32) return -1;
    for (int i = 0; i < 16; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <key-hex32> <pt-hex32> <seed-uint32>\n", argv[0]);
        return 2;
    }
    uint8_t key[16], block[16];
    if (hex16(argv[1], key) || hex16(argv[2], block)) {
        fprintf(stderr, "key and plaintext must each be 32 hex chars\n");
        return 2;
    }
    uint32_t seed = (uint32_t)strtoul(argv[3], NULL, 10);

    masked_aes_seed(seed);
    masked_aes_key(key);
    masked_aes_enc(block);   /* in place: plaintext -> ciphertext */

    for (int i = 0; i < 16; i++) printf("%02x", block[i]);
    printf("\n");
    return 0;
}
