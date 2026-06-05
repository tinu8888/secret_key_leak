# `aes-masked`: first-order Boolean-masked AES target firmware (US3 defense)

The masking countermeasure for Part 2. It is the **same** ChipWhisperer `simpleserial-aes`
example as `firmware/aes-unprotected/`, built with a masked AES implementation
(`CRYPTO_TARGET=MASKEDAES`) instead of the unprotected `TINYAES128C`. It MUST present the
**identical** simpleserial command/response and GPIO trigger semantics. Only the internal AES
leakage differs, so the US1/US2 attacks (CPA + CNN) re-run **unchanged** across the unprotected
and masked targets (the simpleserial protocol stays identical). This directory is build
configuration + documentation only; it does not vendor CW sources (they come from `CW_FW_DIR`).

> ⚠️ **Approval gate (human-approved).** Building is a non-gated compile. **Flashing** the
> result and **capturing** masked traces are each separate, human-approved hardware steps,
> logged in `notes/approvals.md`. Do not flash from here.

## Same protocol / trigger as the unprotected build

- simpleserial `'k'` (set 16-byte key) and `'p'` (encrypt 16-byte plaintext), unchanged.
- Trigger GPIO raised at the start of the AES round and lowered after encryption, unchanged.
- Returns the 16-byte ciphertext; a known (key, plaintext) must still yield the AES-128
  test vector (the masking is internal: shares recombine to the correct ciphertext).
- Because the host contract is identical, `src/dlsca` and the attack notebooks need **no**
  changes; only the captured leakage differs. This is the whole point of the before/after
  comparison (US3, the 10× budget bar).

## How this builds (CW_FW_DIR wiring)

Same wrapper pattern as `../aes-unprotected/`:

```bash
export CW_FW_DIR=$HOME/chipwhisperer/firmware/mcu   # the kit MCU firmware tree
make show                                                   # safe: prints resolved config
# Build (non-gated compile). NOTE the platform/impl constraint in "Status" below:
make PLATFORM=<masked-capable target> CRYPTO_TARGET=MASKEDAES CRYPTO_OPTIONS=<impl>
# -> simpleserial-aes-<PLATFORM>.hex copied here; record its sha256 before flashing.
```

The wrapper invokes the kit's own `simpleserial-aes` makefile, which routes
`CRYPTO_TARGET=MASKEDAES` to `crypto/Makefile.maskedaes`.

## Status update: UNBLOCKED via an own first-order masked AES (build + fit-check done)

The original blocker was specifically the **kit's** masked AES (below). The fix is to use our
own portable C masked AES (`src/`), which has no Cortex-M4/AVR dependency:

- **Functionally correct:** reproduces the FIPS-197 ciphertext across 100,000 random mask seeds
  plus a second known-answer vector (host test, no hardware).
- **Builds and fits on the Cortex-M0:** cross-compiles for `cortex-m0`; static footprint
  (text 888 / bss 176) is comparable to or smaller than the unprotected tiny-AES, plus ~300 B
  transient stack per encryption.

See **`BUILD.md`** for the scheme, the exact numbers, the kit-integration recipe (Step 3,
non-gated hex build), and the gated on-target steps (Step 4). The kit-path blocker is retained
below for the record.

## Original blocker: the KIT's masked AES does not build for CW-Nano / STM32F0

**The kit masked build was attempted and does NOT compile for the CW-Nano's STM32F0
(Cortex-M0).** The kit's `crypto/Makefile.maskedaes` only offers masked implementations that
this target can't use:

| `CRYPTO_OPTIONS` impl | Targets supported | Available in this SDK clone? |
|-----------------------|-------------------|------------------------------|
| `ANSSI` (SecAESSTM32 / secAES-ATmega8515) | **Cortex-M4** (stm32f3/f4/l4/l5, k82f, nrf52840, …) or **AVR** | source dir absent |
| `RIOUBSAES` (masked-bit-sliced-aes-128) | larger cores | source dir absent |
| `KNARFRANK` (Higher-Order-Masked-AES-128) | larger cores | source dir absent |

Exact errors observed building for `PLATFORM=CWNANO` (clone `v6.0.0b-80-g7d0e0b85`):

```
# CRYPTO_TARGET=MASKEDAES (no CRYPTO_OPTIONS):
crypto/Makefile.maskedaes:81: *** Unsupported implementation for masked AES crypto: AES128C.  Stop.

# CRYPTO_TARGET=MASKEDAES CRYPTO_OPTIONS=ANSSI:
crypto/Makefile.maskedaes:62: *** Unsupported platform/hal for ANSSI masked AES crypto.  Stop.
```

The STM32F0 is a **Cortex-M0**; the ANSSI masked AES requires Cortex-M4 (or AVR), and the
bit-sliced/higher-order implementations' source directories are not present in this clone
(`crypto/` here has only `avrcryptolib`, `mbedtls`, `micro-ecc`, `tiny-AES128-C`).

### Options to unblock (need a human decision, do not improvise)

1. **Use a Cortex-M4 target** for the masking part (e.g. CW308 UFO + STM32F4): then
   `make PLATFORM=CW308_STM32F4 CRYPTO_TARGET=MASKEDAES CRYPTO_OPTIONS=ANSSI` builds the ANSSI
   masked AES. This changes the board for US3 vs US1/US2 (record it in `notes/hardware.md`).
2. **Add a Cortex-M0-compatible first-order Boolean-masked AES** to the kit tree (a documented
   reference masked S-box/state for STM32F0) and wire a new `CRYPTO_OPTIONS`/Makefile entry.
   This is the from-scratch firmware effort anticipated as the fallback; it must keep the
   identical simpleserial + trigger semantics.
3. **Initialize the kit's masked-AES submodules** if they are git submodules in the upstream
   repo (the ANSSI/bit-sliced sources may simply be uninitialized), but ANSSI would still be
   Cortex-M4-only, so this alone does not unblock STM32F0.

Until one of these is chosen, the masked `.hex` for CWNANO cannot be produced, and flashing
and capturing masked traces are blocked on the build.

## Verification (HIL, once a masked .hex exists)

After an **approved** flash: send a known (key, plaintext) and assert the returned ciphertext
equals the AES-128 FIPS-197 vector (`69c4e0d8…b4c55a` for key `000102…0f`, plaintext
`00112233…ff`). Masking must not change the ciphertext. Then confirm the trigger-aligned
window matches the unprotected capture so the unchanged attacks line up.
