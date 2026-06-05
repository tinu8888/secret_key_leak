# Verified baseline

The recorded build, flash, capture, and plot baseline. A feature is not
"done" until it runs against real traces from the actual hardware. Recorded
during US1 bring-up before any attack work.

## Bring-up checklist (Phase 0)

- [x] ChipWhisperer detected from Python (`cw.scope()` returns a handle). CW-Nano, fw 0.65.0.
- [x] One power trace captured and plotted (`results/bringup_trace.png`). Untriggered ADC
      readiness capture (no AES firmware on target yet; see note below).
- [x] `aes-unprotected` built and flashed. Build (`PLATFORM=CWNANO`, `TINYAES128C`) plus
      flash (6031 bytes, "Verified flash OK"), 2026-05-31.
- [x] Known (key, plaintext) returns the correct AES-128 test-vector ciphertext over serial.
      Got `69c4e0d86a7b0430d8cdb78070b4c55a` == FIPS-197, MATCH.
- [x] Trace alignment confirmed around the first-round S-box (trigger fires at round start).
      Triggered capture returns only on trigger; AES round structure visible in
      `results/aes_unprotected_trace.png`.

## Verified baseline record

| Item | Result | Date | Notes |
|------|--------|------|-------|
| Scope detected | ✅ PASS | 2026-05-31 | `cw.scope()` → **CWNano**, fw 0.65.0, SN `533332005147394b3330333231333033`. USB claimed cleanly under `.venv` (chipwhisperer 5.7.0); no DeviceClaimError. |
| Single trace captured | ✅ PASS (untriggered) | 2026-05-31 | 5000 samples, ADC clk 7.5 MHz, plotted → `results/bringup_trace.png`. **Untriggered** capture (no firmware raising the trigger), so it proves arm/ADC/readout readiness, not AES alignment. |
| Firmware flashed | ✅ PASS | 2026-05-31 | **Build + flash.** Built `simpleserial-aes-CWNANO.hex` (`PLATFORM=CWNANO CRYPTO_TARGET=TINYAES128C`, ROM 18.41%/RAM 58.98%) from `$HOME/chipwhisperer/firmware/mcu`. Flashed via `capture.program(approved=True)` → STM32F04xxx detected, 6031 bytes, "Verified flash OK". `firmware_hash = sha256:ee9e2630f97037960f24a82b75968cacf623ae6b25395383228ab6d6dc55ec8a`. Programmed once (no retry-loop). |
| Test-vector ciphertext match | ✅ PASS | 2026-05-31 | key `000102030405060708090a0b0c0d0e0f`, plaintext `00112233445566778899aabbccddeeff` → got `69c4e0d86a7b0430d8cdb78070b4c55a` == expected (FIPS-197 C.1). MATCH via `capture.capture_trace` (which asserts ciphertext internally). |
| Alignment / SNR around S-box | ✅ PASS | 2026-05-31 | One **triggered** 5000-sample capture (trigger fires at AES round start; `capture_trace` returns only on trigger). AES round structure clearly visible (vs the flat untriggered bring-up trace) → `results/aes_unprotected_trace.png`. POI windowing for CPA/CNN is tuned later on the bulk set (bulk capture not yet approved). |

### Bring-up notes

- **Board:** ChipWhisperer-**Nano** (single-part; integrated **STM32F0** = `STM32F0_NANO`
  target on the CWNANO platform). No CW308/UFO carrier; no separate target module.
- **USB:** claimed first try via the pinned env (`./.venv/bin/python`, chipwhisperer 5.7.0).
  No replug/release needed. (Note: `scope` warns fw 0.65.0 is one minor behind 0.66.0,
  cosmetic; upgrading scope fw would itself be a separate gated action, not done.)
- **Scope config at capture:** `adc.samples=5000`, `adc.clk_freq=7.5 MHz`, trigger `int`.
- **Target firmware state:** none responsive at bring-up. The encryption-over-serial check and the
  aligned/triggered trace are deferred to the build+flash and capture steps, each gated.
- **Toolchain readiness for flash:** local CW firmware tree present at
  `$HOME/chipwhisperer/firmware/mcu` (clone `v6.0.0b-80-g7d0e0b85`) with
  `simpleserial-aes/` + `crypto/`; `arm-none-eabi-gcc` 14.3.1 on PATH. The
  `firmware/aes-unprotected/Makefile` should point `CW_FW_DIR` here, `PLATFORM=CWNANO`,
  `CRYPTO_TARGET=TINYAES128C`.

## AES-128 test vector (FIPS-197 Appendix B / C.1)

```
key        = 000102030405060708090a0b0c0d0e0f
plaintext  = 00112233445566778899aabbccddeeff
ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a
```

## US1 MVP result: CPA full-key recovery (2026-05-31)

- **Capture:** `traces/unprotected_fixedkey.npz`, N=5000, 5000 samples, fixed key
  `000102…0f`, random plaintexts, ADC 7.5 MHz, `dataset.validate` ok. Also
  `traces/unprotected_randomkey.npz`, N=5000, random keys+plaintexts (seed=1),
  `dataset.validate` ok (profiling set for US2). SNR/alignment figure
  `results/snr_unprotected.png`: 8 overlaid traces align tightly; per-sample variance shows
  clear data-dependent round bursts.
- **CPA:** HW-model CPA (`dlsca.cpa.run`) recovered **all 16 key bytes (rank 0)**:
  recovered `000102030405060708090a0b0c0d0e0f` == known. **`traces_to_rank0 = 100`** (full key
  from just 100 traces; GE flat at 0 thereafter). Byte-0 correct candidate correlation peaks
  ≈0.81 around samples 500 to 900 (first-round S-box), towering over all 255 wrong candidates.
  Artifacts: `results/cpa_aes-unprotected.json`, `results/cpa_corr_peak.png`,
  `results/cpa_ge_curve.png`.
- **Reproduction:** a fresh `./.venv/bin/python` process, saved `.npz` only (no scope),
  fixed seed 0, recovers the identical key.

### Env note (reproducibility)

The notebooks import `from dlsca import ...`. Made the package importable from the Jupyter
kernel via an editable install into the project `.venv`: `pip install -e . --no-deps`
(declared in `pyproject.toml`, `packages.find where=["src"]`; no new pinned deps). This is the
standard way notebooks resolve the project package; pytest already uses `pythonpath=["src"]`.
`notebooks/02_cpa_baseline.ipynb` also self-chdirs to the repo root so relative `traces/` and
`results/` paths resolve regardless of the kernel's launch directory (runs top-to-bottom).
