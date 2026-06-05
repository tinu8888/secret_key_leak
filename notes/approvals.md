# Hardware-action approval log

Per-action human approval is mandatory for every step that flashes firmware, installs
software/toolchains, claims a USB/debug device, or drives power/GPIO.
Approval is **per-action**: consent to flash once is not consent to flash again. Each gated
function records the matching `approval_ref` (e.g. `notes/approvals.md#2026-05-31-flash-unprotected`)
into the capture manifest so datasets are auditable.

## Log

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| (example) | install toolchain | `brew install libusb`, ARM gcc, `pip install -r requirements.txt` | OK / versions in hardware.md |
| 2026-05-31 | confirm/pin USB lib | `brew install`/`upgrade libusb` | OK, already 1.0.30, current; not reinstalled. No global brew upgrade run. |
| 2026-05-31 | confirm/pin ARM toolchain | confirm `arm-none-eabi-gcc`; install only if missing | OK, present at `/opt/homebrew/bin/arm-none-eabi-gcc`, 14.3.1 (Arm 14.3.Rel1). Already installed; no install performed. |
| 2026-05-31 | create Python venv | `python3 -m venv .venv` (host Python 3.9.5, in 3.9 to 3.11) | OK, `.venv` created, Python 3.9.5. |
| 2026-05-31 | install pinned deps into `.venv` | `pip install -r requirements.txt` (chipwhisperer 5.7.0, numpy 1.26.4, scipy 1.13.1, matplotlib 3.8.4, torch 2.2.2, jupyterlab 4.1.6, pytest 7.4.4) | OK, all pins satisfied; arm64 torch wheel installed cleanly. pip upgraded to 26.0.1. Versions in `notes/hardware.md`, freeze in `notes/requirements.lock.txt`. `pytest -q` → 36 passed under `.venv`. |
| 2026-05-31 | scope detect + 1 trace over USB | Claim USB, `cw.scope()` detect, capture+plot ONE trace. NOT approved: flash, bulk capture. | OK, board = **CW-Nano** (STM32F0 target), fw 0.65.0, claimed cleanly (no DeviceClaimError). One 5000-sample trace captured (ADC 7.5 MHz) → `results/bringup_trace.png`. Target has **no AES firmware** (`'p'` → "Target did not ack"), so the trace is an untriggered ADC-readiness capture; **did NOT flash**. Masked-AES reference assumed available (`CRYPTO_TARGET=MASKEDAES`); this was later corrected (not usable on the CW-Nano, see `notes/hardware.md`). Baseline in `notes/setup-verified.md` + `notes/hardware.md`. Stopped before flash/bulk capture. |
| 2026-05-31 | build unprotected AES (non-gated compile) | `make` `simpleserial-aes` `PLATFORM=CWNANO CRYPTO_TARGET=TINYAES128C` from `$HOME/chipwhisperer/firmware/mcu` | OK, clean build (exit 0), CWNANO Built-in Target (STM32F030), ROM 18.41% / RAM 58.98%. Artifact `firmware/aes-unprotected/simpleserial-aes-CWNANO.hex`, sha256 `ee9e2630f97037960f24a82b75968cacf623ae6b25395383228ab6d6dc55ec8a`. No hardware touched. |
| 2026-05-31 | editable install of own package into `.venv` | `pip install -e . --no-deps` (project package `dlsca`, declared in `pyproject.toml`) so the Jupyter kernel resolves `dlsca`. | OK, installed in editable mode, **no new dependencies** (`--no-deps`), no hardware touched. Reversible (`pip uninstall dlsca`). Logged for completeness though it touches no toolchain/USB/firmware; 36-test host suite still passes under `.venv`. |

### 2026-05-31-flash-unprotected

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-05-31 | ⚠️ flash + HIL verify `aes-unprotected` | Flash `simpleserial-aes-CWNANO.hex` to the CW-Nano STM32F0 via `capture.program(approved=True)`; one triggered HIL capture to verify the AES-128 test vector; one aligned trace plot. NOT approved: bulk capture. | **OK.** Programmer detected STM32F04xxx, programmed 6031 bytes, "Verified flash OK". firmware_hash = `sha256:ee9e2630f97037960f24a82b75968cacf623ae6b25395383228ab6d6dc55ec8a` (matches built hex). HIL verify with key `000102…0f`, plaintext `00112233…ff`: got ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a` == expected FIPS-197 → **MATCH**. One triggered (round-1 aligned) 5000-sample trace → `results/aes_unprotected_trace.png`. Programmed once only (no retry-loop). Stopped before bulk capture. |

### 2026-05-31-capture-unprotected

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-05-31 | ⚠️ bulk capture (unprotected) | Drive the flashed CW-Nano to capture a fixed-key attack set (N=5000, fixed key `000102…0f`, random plaintexts) → `traces/unprotected_fixedkey.npz`, and a random-key profiling set (N=5000) → `traces/unprotected_randomkey.npz`, with manifests. NOT approved: anything beyond capture. | **OK, both sets complete.** (a) `traces/unprotected_fixedkey.npz`: N=5000, 5000 samples, fixed key `000102030405060708090a0b0c0d0e0f`, random plaintexts, ADC 7.5 MHz; `dataset.validate` ok=True (fixed-key invariant holds). (b) `traces/unprotected_randomkey.npz`: N=5000, 5000 samples, random keys+plaintexts (seed=1); `dataset.validate` ok=True, fixed_key=False, role random-key. Each ~100 MB + manifest. Fixed-key set captured first (CPA priority); random-key set captured after the CPA MVP in a separate process; **scope disconnected** after. No retry-loop. |

### 2026-06-02-flash-masked

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-06-02 | flash + HIL verify `aes-masked` (own Cortex-M0 first-order masked AES) | User: "you can test on hw is connected"; scope chosen = **flash + verify only** (not bulk capture / not attack). Claim USB, flash `firmware/aes-masked/simpleserial-aes-CWNANO-masked.hex` (sha256 `9e6090554f31faf2e51611dfd20efd8fd1d33aacef4672c6e5717dd69cf40927`) to the CW-Nano STM32F0 via `capture.program(approved=True)`; one triggered HIL capture to verify the AES-128 test vector. NOT approved: bulk capture, attack re-run. | **PARTIAL.** Flash succeeded and byte-verified: programmer detected STM32F04xxx, "Verified flash OK, 5863 bytes", flashed firmware_hash = `sha256:9e6090554f31faf2e51611dfd20efd8fd1d33aacef4672c6e5717dd69cf40927` (matches built hex). **Functional HIL verify did NOT complete:** the target did not ack simpleserial `set_key` right after programming (`Target did not ack` / `Device failed to ack`); a follow-up `nrst` reset + reconnect then hit `Timeout in cwnano capture()` (no trigger). SS_VER confirmed `SS_VER_1_1` (same as the working unprotected build), so not a protocol mismatch. Most likely a post-programming target serial/reset state needing a physical power-cycle (replug). Stopped before any further flash. Ciphertext NOT yet confirmed on-chip. Next: user replug + retry verify (no re-flash), or approve a diagnostic re-flash of the known-good unprotected hex to confirm the rig still talks. **RESOLVED 2026-06-02:** root cause was `capture.connect()` not calling `scope.default_setup()` (the Nano was flashing the target but not (re)starting its 7.5 MHz clock after program/reset cycles, so the target never ran). After adding `scope.default_setup()` + an nRST low->high reset, the masked hex (`9e609055…0927`) re-flashed and the HIL verify PASSED on the first capture: key `000102…0f`, pt `001122…ff` -> ct `69c4e0d86a7b0430d8cdb78070b4c55a` (FIPS-197 MATCH), 5000-sample trace. **Masked AES confirmed running correctly on the CW-Nano; output unchanged.** Stopped before bulk capture (not approved). |

### 2026-06-02-diagnose-unprotected

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-06-02 | diagnostic re-flash of known-good unprotected hex | After masked flash byte-verified but serial verify failed (no ack) even post-replug + reset-free retry, user approved re-flashing `firmware/aes-unprotected/simpleserial-aes-CWNANO.hex` (sha256 `ee9e2630f97037960f24a82b75968cacf623ae6b25395383228ab6d6dc55ec8a`) and re-running the HIL verify, to isolate rig vs. masked-firmware. | **Re-flash OK, verify FAILED -> RIG ISSUE, masked firmware exonerated.** Unprotected hex re-flashed + byte-verified ("Verified flash OK, 6031 bytes", hash `ee9e2630…ec8a`). But the HIL verify on this KNOWN-GOOD firmware (the one that captured 5000 traces in the bulk run) ALSO fails identically: `Device failed to ack` then `Timeout in cwnano capture()` (no trigger). Since the same firmware that worked during bulk capture now fails, the masked firmware is **not** the cause; the target is flashing but not responding on serial (CW-Nano generates the target clock -> symptom = target not being clocked/run, a stuck board/session state). Next: full power-cycle (replug) and re-verify unprotected; if good, re-flash masked and verify. |

### 2026-06-02-capture-masked

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-06-02 | bulk capture (masked) | User: "go ahead with the full US3 result". Drive the masked-flashed CW-Nano to capture a fixed-key attack set (N=5000, key `000102…0f`, random plaintexts) -> `traces/masked_fixedkey.npz` and a random-key profiling set (N=5000) -> `traces/masked_randomkey.npz`, with manifests; then run CPA + CNN on the masked traces (no hardware) for the US3 before/after result. | **Capture OK, both sets.** `traces/masked_fixedkey.npz` (N=5000, fixed key `000102…0f`, random plaintexts; `validate` ok=True, fixed_key=True; 279s) and `traces/masked_randomkey.npz` (N=5000, random keys; `validate` ok=True, fixed_key=False; 448s), ~100 MB each + manifests, firmware_hash `9e609055…0927`. Every captured ciphertext matched AES128(pt,key) (capture_trace verifies inline), confirming the masked firmware encrypts correctly throughout. Scope disconnected after. No retry-loop. Attacks (CPA + CNN) run separately on saved traces (no hardware). |

### 2026-06-04-live-roundtrip-masked

| Date | Action | What was approved | Result |
|------|--------|-------------------|--------|
| 2026-06-04 | live masked encrypt + host decrypt roundtrip (on fresh data) | User: "go ahead and run this, i have connected the hardware". Connect the CW-Nano (currently running the masked firmware), capture ~16 fresh masked encryptions with random plaintexts (fixed key `000102…0f`), confirm each on-chip ciphertext is correct AES, then decrypt each on the host and confirm it returns the original plaintext. Small live verification, not a bulk capture. | **PASS.** Connected via the fixed `capture.connect()` (default_setup), reset, ran 16 live masked encryptions with random plaintexts (fixed key `000102…0f`). On-chip ciphertext correct (== reference AES): 16/16. Host decrypt (`dlsca.aes_ref.aes128_decrypt_block`) recovered the original plaintext: 16/16. Confirms on real silicon that the masked chip's output is valid AES and the original data is fully recoverable. Scope disconnected after. |

<!--
How to add an entry:
  1. A human explicitly authorizes the exact action (not "approve all").
  2. Add a row above. For an action you need to reference later, give it a unique anchor
     heading, for example: ### 2026-05-31-flash-unprotected
  3. Pass approval_ref="notes/approvals.md#2026-05-31-flash-unprotected" to the gated
     capture.py function (connect, program, or campaign).
-->
