# `aes-unprotected`: baseline target firmware

The unprotected AES-128 target used to prove the power-analysis leak (CPA control, then the
CNN headline). It is the ChipWhisperer-kit `simpleserial-aes` example built **without**
masking, exposing the standard simpleserial command/response and a GPIO capture trigger.

This directory is **build configuration + documentation only**. It deliberately does NOT
vendor the ChipWhisperer firmware sources. Those ship with the kit (the `chipwhisperer`
repo / pip package's `firmware/` tree) and are pinned by the SDK version recorded at
bring-up (`notes/hardware.md`). See **"How this builds"** below.

> ⚠️ **Approval gate (human-approved).** Nothing here is built or flashed automatically.
> Installing the ARM toolchain, building, and flashing are each separate, human-approved
> steps logged in `notes/approvals.md`. Do not run `make` until the toolchain is approved
> and installed and the exact board is recorded in `notes/hardware.md`.

## What this references (CW firmware sources)

Built from the ChipWhisperer-supplied sources, not copies in this repo:

- `simpleserial-aes/simpleserial-aes.c`: the example app. Handles the simpleserial
  `'k'` (set key) and `'p'` (encrypt plaintext) commands, raises the trigger, runs AES,
  returns the ciphertext.
- `crypto/`: the kit's tiny-AES / `aes-independant` C implementation (unprotected AES-128).
- `simpleserial/`: the simpleserial transport layer.
- `hal/`: the hardware abstraction layer for the chosen `PLATFORM` (e.g. STM32F4 on a
  CW308 UFO, or a CW-Lite/Nano single-part target).

The exact SDK version (`chipwhisperer` package or git SHA) is the single source of truth and
is recorded in `notes/hardware.md` at bring-up so the build is reproducible.

## GPIO trigger (capture alignment)

`simpleserial-aes` raises the trigger GPIO (`trigger_high()`) immediately **before** the
first AES round and lowers it (`trigger_low()`) immediately **after** encryption. Captures
therefore align to the start of round 1, which is where the first-round S-box leakage the
CPA/CNN target lives (first-round `S-box(plaintext XOR key)`). Do not change this trigger
placement: the host attack code and the simpleserial protocol assume it, and the masked
variant (`firmware/aes-masked`) must keep identical trigger semantics so attacks re-run
unchanged.

## How this builds (ARM toolchain, `arm-none-eabi-gcc`)

The ChipWhisperer firmware uses its own makefiles that expect to live inside the kit's
`firmware/mcu/` tree (they pull in `Makefile.inc`, the HAL, and crypto from relative paths).
Two supported ways to build, both gated on the approved toolchain and a recorded board:

### Option A (recommended): build in the kit tree, drive it from here

Point this `Makefile` at the kit's `simpleserial-aes` source via `CW_FW_DIR` and `PLATFORM`,
then `make` (after approval):

```bash
# Set ONCE for your machine, after the toolchain and board are recorded. Examples:
#   CW_FW_DIR = path to <chipwhisperer>/firmware/mcu  (the kit firmware tree)
#   PLATFORM  = your exact target, e.g. CW308_STM32F4 or CWLITEARM or CWNANO
make PLATFORM=CW308_STM32F4 CRYPTO_TARGET=TINYAES128C   # ⚠️ approval-gated build
```

The `Makefile` in this directory copies/links the unprotected `simpleserial-aes` target out
of `CW_FW_DIR` and invokes the kit makefile with the chosen `PLATFORM`/`CRYPTO_TARGET`,
emitting `simpleserial-aes-<PLATFORM>.hex` here for flashing.

### Option B: build directly in the kit example dir

If you prefer the upstream flow, build in the kit and copy the artifact back:

```bash
make -C "$CW_FW_DIR/simpleserial-aes" PLATFORM=<PLATFORM> CRYPTO_TARGET=TINYAES128C
```

Then record the produced `.hex` path in `notes/setup-verified.md`.

> If Option A's in-tree wiring proves brittle for a given SDK layout, treat this README's
> Option B as the canonical procedure and keep the `Makefile` as a thin convenience wrapper.
> The build steps are also mirrored in `BUILD.md` as a toolchain-free reference.

## Verification (HIL, simpleserial protocol)

After an **approved** flash: send a known (key, plaintext) over simpleserial and assert the
returned ciphertext equals the AES-128 test vector. For the FIPS-197 vector key `000102...0f`,
plaintext `00112233...ff`, the expected ciphertext is `69c4e0d86a7b0430d8cdb78070b4c55a`.
Confirm trace alignment around the trigger before bulk capture.

## Host detected at authoring time (informational)

- Host: macOS (Apple Silicon, arm64), Homebrew prefix `/opt/homebrew`.
- `arm-none-eabi-gcc` was already present on PATH at authoring; its exact version MUST still
  be recorded and frozen in `notes/hardware.md`. Presence of a compiler does not waive the
  approval gate. Confirming/pinning the toolchain is itself the approved action.
