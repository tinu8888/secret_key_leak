# Hardware and host record

Recorded at bring-up (Phase 0.1 to 0.2). The exact board and host pin
the reproducibility chain.

## Target

Detected at bring-up (2026-05-31) via `cw.scope()` under the pinned `.venv`.

| Field | Value |
|-------|-------|
| Board / scope | **ChipWhisperer-Nano** (CWNANO), capture fw 0.65.0, SN `533332005147394b3330333231333033` |
| Target MCU | **STM32F0** (integrated single-part Nano target; HAL platform `STM32F0_NANO` / `PLATFORM=CWNANO`) |
| Programmer | Built-in CW STM32 serial bootloader (`cw.program_target`), **gated** |
| Trigger GPIO | Raised by `simpleserial-aes` at AES round start; confirmed at flash time |
| Build PLATFORM / CRYPTO_TARGET | `PLATFORM=CWNANO`; unprotected `CRYPTO_TARGET=TINYAES128C` (builds ✅). Masked `CRYPTO_TARGET=MASKEDAES` does **NOT** build for this target (see below). |
| Current target firmware | Unprotected `simpleserial-aes` (TINYAES128C) flashed + verified (FIPS-197 vector match); used for US1/US2. |
| **Masked-AES reference usable on this board?** | **NO, corrected 2026-05-31.** An earlier bring-up surface check saw the `CRYPTO_TARGET=MASKEDAES` Makefile option and wrongly assumed a one-line variant build. On a real build attempt for `PLATFORM=CWNANO` it FAILS: `Makefile.maskedaes:81 *** Unsupported implementation ... AES128C` and (with `CRYPTO_OPTIONS=ANSSI`) `:62 *** Unsupported platform/hal for ANSSI masked AES`. The kit's masked AES (ANSSI / RIOUBSAES / KNARFRANK) targets **Cortex-M4** (STM32F3/F4) or AVR; the Nano's **STM32F0 is Cortex-M0**, unsupported. The masked-AES source dirs (`SecAESSTM32`, etc.) aren't even present in the clone. So **US3 (masking defense) is BLOCKED on the CW-Nano.** Unblock paths in `firmware/aes-masked/README.md`: (1) use a Cortex-M4 target (CW308+STM32F4, ANSSI masked AES), or (2) author a Cortex-M0 first-order masked AES. **Decision (2026-05-31): defer US3, proceed to US4 content** with the US1+US2 attack story; revisit the defense when an M4 target is available. **Update (2026-06-02): US3 unblocked on the Nano without new hardware** by writing an own portable first-order masked AES in C (`firmware/aes-masked/src/`): it is functionally correct (FIPS-197 vector across 100k mask seeds) and builds + fits for Cortex-M0 (text 888 / bss 176, ~300 B stack/enc), comparable to the unprotected tiny-AES. See `firmware/aes-masked/BUILD.md`. **US3 COMPLETE (2026-06-02):** masked hex flashed + HIL-verified on the Nano (ciphertext `69c4e0d8…b4c55a`), masked fixed-key + random-key sets captured (N=5000 each), and CPA + CNN re-run on them both FAIL at 5000 traces (`traces_to_rank0=None`, mean key rank ~100) vs unprotected CPA 100 / CNN 12. Result in `results/us3_defense_ge.png`. (Also fixed a `capture.connect()` bug: it wasn't calling `scope.default_setup()`, so the Nano flashed but didn't clock/run the target after a program cycle.) |

## Host

| Field | Value |
|-------|-------|
| Machine | Apple Silicon Mac (arm64) |
| Host arch | arm64 |
| macOS version | macOS 26.5 (Darwin 25.5.0) |
| Python | 3.9.5 (in pinned 3.9 to 3.11 range), in `.venv` |
| Compute device for CNN | mps (torch reports `mps.is_available() == True`) |

## Toolchain versions

Recorded at toolchain install/pin. Full freeze in `notes/requirements.lock.txt`
(written at install time; re-frozen at closeout). Captured under the project `.venv`.

| Component | Version | Source |
|-----------|---------|--------|
| arm-none-eabi-gcc | 14.3.1 (Arm GNU Toolchain 14.3.Rel1, Build arm-14.174) | Homebrew, `/opt/homebrew/bin/arm-none-eabi-gcc` (pre-existing; confirmed/pinned, not reinstalled) |
| libusb | 1.0.30 | Homebrew (pre-existing; confirmed current via `brew upgrade`) |
| chipwhisperer (SW) | 5.7.0 | pip into `.venv` (pinned in `requirements.txt`) |
| numpy | 1.26.4 | pip into `.venv` |
| scipy | 1.13.1 | pip into `.venv` |
| matplotlib | 3.8.4 | pip into `.venv` |
| torch | 2.2.2 | pip into `.venv` (arm64 wheel, no wheel issues) |
| jupyterlab | 4.1.6 | pip into `.venv` |
| pytest | 7.4.4 | pip into `.venv` |
| pip | 26.0.1 | upgraded in `.venv` before install |

**Host test suite under `.venv`:** `./.venv/bin/pytest -q` → **36 passed, 0 failed** (exit 0)
on Python 3.9.5 / arm64, after the pinned install. Confirms the host math layer runs under the
pinned interpreter.

> Status (board attached, 2026-05-31): the **Target** table above is filled (bring-up,
> flash + verify), the verified bring-up baseline is recorded in
> `notes/setup-verified.md`, and the masked-AES-reference question is answered (corrected
> 2026-05-31: not usable on the CW-Nano, so US3 is deferred). All gated steps were approved
> separately and logged in `notes/approvals.md`.
