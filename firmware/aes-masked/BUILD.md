# Building the Cortex-M0 first-order masked AES (US3 on the CW-Nano)

This is the **own-implementation** path that unblocks the masking defense on the existing
ChipWhisperer-Nano (STM32F0 / Cortex-M0), without buying a Cortex-M4 board. The kit's masked
AES (ANSSI / RIOUBSAES / KNARFRANK) is hand-written for Cortex-M4/AVR and will not build for
the M0; a portable C masked AES has no such restriction. Source lives in `src/`.

## What is here

| File | Role |
|------|------|
| `src/dlsca_masked_aes.c/.h` | portable first-order Boolean-masked AES-128 (the countermeasure) |
| `src/dlsca_aes_indep.c` | shim mapping it onto the kit `aes_indep_*` interface (same protocol/trigger) |
| `test/test_masked_host.c` | host correctness test (no hardware) |

## Masking scheme (one paragraph)

Each state byte is carried as `(data XOR mask)` with the mask tracked in a parallel array.
The linear layers (AddRoundKey, ShiftRows, MixColumns) are applied to the mask array as well,
so the relation holds for free through them. SubBytes uses a per-encryption recomputed masked
S-box `MSbox[x XOR Min] = Sbox[x] XOR Mout` with fresh `(Min, Mout)`. The plaintext is masked
**before** the first AddRoundKey, so `plaintext XOR key` never appears in the clear. At the end
the mask is stripped and the standard AES ciphertext comes out. This means the host CPA/CNN
attacks run unchanged; only the on-chip leakage differs.

**Randomness / honest limit:** masks come from a software `xorshift32` PRNG because the STM32F0
has no hardware RNG. Mask quality is only as good as that PRNG and its seeding. The real test
is on-target: capture masked traces and re-run the first-order attack (US3). If the key still
falls, the masking (or its randomness) is flawed; if it does not, the defense holds. We report
whichever happens.

## Step 1 - host correctness (no hardware, done)

```bash
cc -O2 -Wall -Wextra -std=c11 src/dlsca_masked_aes.c test/test_masked_host.c -o /tmp/test_masked
/tmp/test_masked
```

Result (recorded): the masked AES reproduces the FIPS-197 vector
`69c4e0d8…b4c55a` (key `000102…0f`, pt `001122…ff`) across **100,000 random mask seeds**, and a
second FIPS-197 Appendix-B vector also matches. Masking is functionally transparent.

## Step 2 - Cortex-M0 fit-check (no hardware, done)

Standalone cross-compile for the M0 ISA and size, vs the kit's unprotected tiny-AES:

```bash
arm-none-eabi-gcc -mcpu=cortex-m0 -mthumb -Os -ffunction-sections -fdata-sections -Wall \
  -c src/dlsca_masked_aes.c -o /tmp/masked_m0.o && arm-none-eabi-size /tmp/masked_m0.o
```

| Crypto (Cortex-M0, -Os) | text (flash) | data | bss | notes |
|-------------------------|-------------:|-----:|----:|-------|
| **masked (this code)**  | 888 | 4 | 176 | bss = `round_keys[176]`; enc uses ~300 B stack (`msbox[256]`+state) |
| unprotected tiny-AES    | 1052 | 523 | 200 | kit baseline for comparison |

Conclusion: the masked crypto **builds for the Cortex-M0** and its static footprint is
comparable to (slightly smaller than) the unprotected AES. The only new run-time cost is ~300
bytes of transient stack for the masked S-box + state during one encryption. The "M0 can't do
masking" worry does not apply; it was only the kit's M4/AVR assembly that could not build.

## Step 3 - full flashable hex via the kit (build is non-gated; FLASH is gated)

Wire the shim into the kit's `simpleserial-aes` with **no kit crypto** (`CRYPTO_TARGET=NONE`),
adding our two source files so they supply the `aes_indep_*` symbols:

```bash
export CW_FW_DIR=$HOME/chipwhisperer/firmware/mcu
make -C "$CW_FW_DIR/simpleserial-aes" \
  PLATFORM=CWNANO CRYPTO_TARGET=NONE \
  EXTRA_SRC="dlsca_masked_aes.c dlsca_aes_indep.c" \
  EXTRA_VPATH="$(pwd)/src" EXTRA_INC="$(pwd)/src"
```

> Command-line `SRC=` does not append in the kit Makefile, so in practice this was built via a
> tiny wrapper makefile in the `simpleserial-aes` dir (`SRC += dlsca_masked_aes.c dlsca_aes_indep.c`
> plus `VPATH`/`EXTRAINCDIRS` pointing back to `src/`, then `include Makefile`). Non-gated (compile only).

Result (recorded): the full firmware links and fits the CW-Nano's STM32F0 comfortably:

| Whole firmware (PLATFORM=CWNANO) | Used | Capacity | Percent |
|----------------------------------|------|----------|---------|
| ROM (flash) | 5864 B | 32 KB | **17.90%** |
| RAM | 1872 B | 4 KB | **45.70%** |

For comparison the unprotected build is ROM 18.41% / RAM 58.98%; the masked build is actually
smaller in both, because our S-box stays `const` in flash instead of being copied to RAM. The
artifact is `simpleserial-aes-CWNANO-masked.hex`, sha256
`9e6090554f31faf2e51611dfd20efd8fd1d33aacef4672c6e5717dd69cf40927` (5863 bytes flashed). Record
the sha256 before any flash.

## Step 4 - on-target (each step human-approved)

1. flash `simpleserial-aes-CWNANO.hex` to the Nano  *(approval: flash)*
2. HIL verify: key `000102…0f` + pt `001122…ff` -> ciphertext `69c4e0d8…b4c55a`  *(approval: HIL)*
3. capture masked fixed-key + random-key trace sets  *(approval: bulk capture)*
4. re-run CPA + CNN on the masked traces (no hardware) -> the US3 before/after result
