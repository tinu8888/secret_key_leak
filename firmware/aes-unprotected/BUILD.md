# BUILD.md: toolchain-free reference for building `aes-unprotected`

This mirrors the `Makefile` as plain steps, for when the kit makefile must be driven directly
inside the ChipWhisperer firmware tree (its makefiles use relative paths to the HAL, crypto,
and `Makefile.inc`, so building in-tree is the most robust path on some SDK layouts).

> ⚠️ Every step here is **approval-gated** (human-approved). Do not perform the toolchain
> install or the build + flash + HIL verify until approved and logged in `notes/approvals.md`,
> and the exact board is recorded in `notes/hardware.md`.

## Prerequisites (all gated)

- ARM toolchain installed and pinned: `arm-none-eabi-gcc` on PATH. Record the version.
- ChipWhisperer SDK installed, provides the `firmware/mcu` tree (`CW_FW_DIR`).
- Exact `PLATFORM` known and recorded, e.g. `CW308_STM32F4`, `CWLITEARM`, `CWNANO`.

## Steps

```bash
# 0. Locate the kit firmware tree (depends on how chipwhisperer was installed):
#    pip install:  python -c "import chipwhisperer, os; print(os.path.dirname(chipwhisperer.__file__))"
#                  then look for the sibling firmware/ tree, OR clone the repo for firmware sources.
#    git clone:    <repo>/firmware/mcu
export CW_FW_DIR=/path/to/chipwhisperer/firmware/mcu
export PLATFORM=CW308_STM32F4          # your exact target

# 1. Build the UNPROTECTED simpleserial-aes (TINYAES128C = unprotected C AES). ⚠️ approval-gated
make -C "$CW_FW_DIR/simpleserial-aes" PLATFORM=$PLATFORM CRYPTO_TARGET=TINYAES128C

# 2. The artifact:
ls "$CW_FW_DIR/simpleserial-aes/simpleserial-aes-$PLATFORM.hex"

# 3. Copy it next to this firmware config for provenance, and record its sha256 +
#    the toolchain/SDK versions in notes/setup-verified.md.
cp "$CW_FW_DIR/simpleserial-aes/simpleserial-aes-$PLATFORM.hex" .
shasum -a 256 "simpleserial-aes-$PLATFORM.hex"
```

## Flash + verify (HIL)

Flashing is done from the host via `cw.program_target(...)` (see `src/dlsca/capture.py`'s
`program()`), which is **approval-gated** and records `firmware_hash`. After flashing, send a
known (key, plaintext) and assert the test-vector ciphertext (FIPS-197):

- key `000102030405060708090a0b0c0d0e0f`, plaintext `00112233445566778899aabbccddeeff`
- expected ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a`

Confirm the trigger-aligned capture window around round 1 before bulk capture.
