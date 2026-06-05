# Recovering an AES-128 key from power: the CPA baseline (US1)

A full walkthrough of the project's first milestone: pulling a secret AES-128 key out of a
microcontroller using nothing but its **power consumption**, with a classical Correlation
Power Analysis (CPA) attack. This is the "it definitely leaks" control that the later
deep-learning attack (US2) and the masking defense (US3) build on.

- **Status:** Done and reproducible.
- **Hardware used:** ChipWhisperer-Nano with its onboard STM32F0 target.
- **Headline:** the full 16-byte key was recovered from about 100 power traces.

---

## 1. The goal, and why

A chip running AES does more than compute the ciphertext. While it works, its instantaneous
power draw depends on the data it is handling. That dependency is a *side channel*, a leak.
The goal of this milestone was to prove, on hardware we own, that the leak is real and
exploitable:

> Capture power traces from a target running unprotected AES-128, and recover the full secret
> key from those traces alone, without ever being told the key.

Why start with CPA rather than the neural network that headlines the project? Because of a
project rule ("Measure, Don't Claim"): a classical control has to
prove the leak exists *before* we trust a deep-learning model. CPA is well understood and
hard to fool yourself with, so if CPA recovers the key, we know the capture pipeline and the
leak are sound. Only then is a CNN result believable.

This milestone also sets up everything the rest of the project reuses: a verified capture
setup, saved trace datasets with metadata, and a tested analysis library.

## 2. Result at a glance

| What | Value |
|------|-------|
| Target firmware | unprotected `simpleserial-aes` (TINYAES128C), verified against the FIPS-197 test vector before capture |
| Known key (on the chip) | `000102030405060708090a0b0c0d0e0f` |
| **Recovered key (from power)** | **`000102030405060708090a0b0c0d0e0f`**, all 16 bytes, rank 0 |
| Traces needed for the full key | **~100** (`traces_to_rank0 = 100`) |
| Leakage model | Hamming weight of the first-round S-box output |
| Reproducible from saved traces, no hardware | Yes (fixed random seed) |

Artifacts produced (in `results/`): `cpa_aes-unprotected.json` (the machine-readable result),
`cpa_corr_peak.png` (the correct key candidate towering over the 255 wrong ones),
`cpa_ge_curve.png` (guessing entropy vs. number of traces), and `snr_unprotected.png`.

## 3. How the attack works (the short version)

AES encrypts by first XOR-ing each plaintext byte with a key byte, then passing the result
through a fixed lookup table called the **S-box**. CPA attacks that S-box output:

1. **Pick a key-byte guess** (0 to 255). For every captured trace we know the plaintext, so
   for a guess `k` we can compute the intermediate value `Sbox(plaintext_byte ⊕ k)`.
2. **Model the power** that value would cause. A common, effective model is its **Hamming
   weight**, the number of 1-bits, because moving more 1s around a bus burns more power.
3. **Correlate** that model against the measured power at each sample point, across all
   traces. For the *wrong* key guess the model is uncorrelated noise. For the *right* guess
   it lines up with reality and the correlation spikes.
4. The guess with the highest correlation peak is the recovered key byte. Repeat for all 16
   bytes and you have the full key.

The success metric is **guessing entropy / key rank vs. number of traces**: as we feed in
more traces, the correct key's rank drops to 0 (top of the list). Here that happened by about
100 traces. The unprotected target leaks very strongly.

## 4. How it was achieved

The work followed a careful, host-first flow with a hard hardware-safety rule throughout.

- **Host-first, hardware-second.** The entire analysis library (`src/dlsca/`), meaning the
  leakage models, CPA math, the key-ranking / guessing-entropy engine, and dataset I/O, was
  written and unit-tested **against synthetic traces** before any hardware was touched. 36
  tests pass off-hardware. So when real traces arrived, the attack code was already trusted.
- **A verified baseline before capturing en masse.** We brought the board up, flashed the
  AES firmware, and confirmed it encrypts correctly (its ciphertext matched the published
  AES test vector) *before* trusting any trace. Build, flash, verify, capture, in that order.
- **Every physical action was human-approved.** Installing the toolchain, claiming the USB
  device, flashing firmware, and running captures each required explicit approval and is
  logged in [`notes/approvals.md`](../notes/approvals.md). Pure analysis on saved data is not
  gated, which keeps the fast inner loop friction-free and is exactly why the result is
  reproducible from saved files.
- **Everything pinned and seeded.** A single Python environment (`.venv`) with pinned
  versions, captured traces saved alongside their metadata (a JSON manifest), and one fixed
  random seed make the result repeatable.

The recovered-key result was confirmed twice: once by the run that produced
`results/cpa_aes-unprotected.json`, and again by an independent re-run from the saved `.npz`
in a fresh process.

## 5. What's in the repo

```text
firmware/aes-unprotected/   # the AES target build (Makefile + built .hex)
src/dlsca/                   # the analysis library (importable, unit-tested)
  leakage.py                #   AES S-box, Hamming-weight + identity labels
  dataset.py                #   .npz trace I/O + manifest + AES check
  preprocess.py             #   point-of-interest window + standardize
  cpa.py                    #   Correlation Power Analysis
  attack.py                 #   key rank + guessing entropy -> AttackResult
  capture.py                #   ChipWhisperer capture (approval-gated)
  seeds.py                  #   one-call reproducible seeding
notebooks/
  00_bringup.ipynb          #   scope detect + one trace (hardware)
  01_capture.ipynb          #   bulk capture -> traces/*.npz (hardware)
  02_cpa_baseline.ipynb     #   the CPA attack (runs from saved traces)
tests/                      # pytest suite (host-only, no hardware)
traces/                     # .npz datasets + manifests (.npz git-ignored; large)
results/                    # the recovered key + figures
notes/                      # hardware, verified baseline, approval log
```

## 6. Prerequisites

- **macOS** (Apple Silicon or Intel). This was run on Apple Silicon (arm64).
- **Python 3.9 to 3.11.**
- **To reproduce from saved traces (Path A):** just Python, no hardware.
- **To capture from scratch (Path B):** a ChipWhisperer (this used a CW-Nano) and the ARM
  embedded toolchain (`arm-none-eabi-gcc`) plus `libusb`. You also need a local clone of the
  ChipWhisperer firmware sources for the build, since the pip package doesn't bundle them.

## 7. One-time setup

```bash
cd side-channel-attack
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt      # pinned: chipwhisperer, numpy, scipy, matplotlib, torch, jupyterlab, pytest
pip install -e . --no-deps           # make the `dlsca` package importable (no new deps)
```

> ⚠️ On a fresh machine, `pip install` is an install step, which under this project's rules is
> a human-approved action. Record it in `notes/approvals.md` as we did.

Verify the environment with the test suite (next section).

## 8. Running it

### Path A: reproduce the key recovery from saved traces (no hardware)

This is the fast, hardware-free path. It needs the trace file `traces/unprotected_fixedkey.npz`.
That file is about 100 MB and is **not** committed to git (only its manifest is). Get it by
either copying it from the machine that captured it, or by running Path B to capture your own.

**Option 1, the notebook:**

```bash
source .venv/bin/activate
jupyter lab        # open notebooks/02_cpa_baseline.ipynb and Run All
```

**Option 2, a few lines of Python (this is exactly what the notebook does):**

```python
from dlsca import dataset, cpa, attack

ts = dataset.load("unprotected_fixedkey")        # loads traces/unprotected_fixedkey.npz
known = ts.keys[0]                               # the fixed key (same on every row)

res = cpa.run(
    ts.traces, ts.plaintexts, known_key=known,
    firmware="aes-unprotected", dataset="unprotected_fixedkey",
)

print("known    :", bytes(known).hex())
print("recovered:", bytes(res["recovered_key"]).hex())
print("all 16 correct:", all(res["correct"]),
      "| traces_to_rank0:", res["traces_to_rank0"])

attack.save_result(res)                          # writes results/cpa_aes-unprotected.json
```

**What to expect:**

```text
known    : 000102030405060708090a0b0c0d0e0f
recovered: 000102030405060708090a0b0c0d0e0f
all 16 correct: True | traces_to_rank0: 100
```

If `recovered == known` and `all 16 correct` is `True`, the attack succeeded: you read the
chip's secret key out of its power consumption.

### Path B: full capture on your own ChipWhisperer (hardware, approval-gated)

Each ⚠️ step touches hardware and should be done deliberately (and, in this project, approved
and logged). Run the notebooks in order:

1. ⚠️ **Bring-up,** `notebooks/00_bringup.ipynb`: detect the scope over USB and capture one
   trace. Record the exact board in `notes/hardware.md`.
2. ⚠️ **Flash:** build `firmware/aes-unprotected` and program it to the target, then verify
   it returns the correct AES test-vector ciphertext over serial. Build command used here:
   ```bash
   make -C firmware/aes-unprotected \
        PLATFORM=CWNANO CRYPTO_TARGET=TINYAES128C \
        CW_FW_DIR=/path/to/chipwhisperer/firmware/mcu
   ```
3. ⚠️ **Capture,** `notebooks/01_capture.ipynb`: capture a fixed-key set (random plaintexts)
   into `traces/unprotected_fixedkey.npz`, plus a random-key profiling set for later.
4. **Attack:** run Path A on your freshly captured traces.

## 9. Manual testing and what to expect

### a) Run the unit tests (no hardware)

```bash
source .venv/bin/activate
pytest -q
```

Expect **36 passed**. These verify the parts that have to be correct independent of hardware:

- `test_leakage.py`: the S-box matches FIPS-197; Hamming weight is in 0 to 8; identity labels are in 0 to 255.
- `test_dataset.py`: trace save/load round-trips; a mismatched-length dataset is rejected; a
  deliberately corrupted ciphertext is caught by `validate`.
- `test_preprocess.py`: windowing and standardization round-trip.
- `test_cpa.py`: CPA recovers the key on **synthetic** Hamming-weight leakage.
- `test_attack.py`: key rank reaches 0 with enough traces, guessing entropy trends to 0, and
  a byte that never recovers reports `traces_to_rank0 = null` (so "not recovered" is honest).

### b) Sanity-check the captured data

```python
from dlsca import dataset
ts = dataset.load("unprotected_fixedkey")
print(ts.n_traces, "traces ×", ts.n_samples, "samples")
print(dataset.validate(ts))     # checks shapes, AES(plaintext,key)==ciphertext, fixed-key invariant
```

Expect `5000 traces × 5000 samples` and a validation report with `ok: True`. The `validate`
step recomputes AES from each plaintext and key and checks it equals the stored ciphertext.
If that passes, the dataset is internally consistent and was captured from a correctly
working target.

### c) Verify the headline result

Open `results/cpa_aes-unprotected.json`. You should see `recovered_key == known_key`,
`correct` all `true`, and `traces_to_rank0: 100`. Look at `results/cpa_corr_peak.png`: the
correct key byte's correlation curve (the highlighted one) peaks far above the cloud of 255
wrong guesses. That visual gap *is* the leak.

### d) Confirm reproducibility (the no-hardware guarantee)

Re-run Path A in a brand new shell. With the fixed seed you should get the identical
recovered key and identical `traces_to_rank0`. Matching results across a fresh process is the
reproducibility check.

## 10. Reproducibility and safety notes

- **Pinned and seeded.** Exact dependency versions are in `requirements.txt` /
  `notes/requirements.lock.txt`; one seed (`dlsca.seeds.set_all`) drives all randomness.
- **Data has provenance.** Every `.npz` ships with a manifest recording the board, scope
  config, firmware hash, seed, and the approval reference for the capture.
- **Large files stay out of git.** The 100 MB `.npz` are git-ignored. The committed manifests
  and firmware hash document exactly what they contain, so they're reproducible by re-capture.
- **Hardware safety is non-negotiable.** Only the operator's own hardware was used, with
  self-generated test keys. Every flash, install, USB, and capture action was explicitly
  approved and logged in `notes/approvals.md`. This is research and defense, not an attack on
  anyone else's device.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `connect()` raises `DeviceClaimError` | Another process holds the USB device. Close other ChipWhisperer sessions, replug, retry. |
| "Target did not ack" on capture | No (or wrong) firmware on the target. Flash `aes-unprotected` first and verify the test vector. |
| `ValueError` about a numeric string in `capture_trace` | Pass key/plaintext as a uint8 array/list, not a raw `bytes` object. (`capture.py` now converts bytes automatically.) |
| `import dlsca` fails in Jupyter | Run `pip install -e . --no-deps` inside `.venv` so the kernel can find the package. |
| CPA doesn't reach rank 0 | Capture more traces, and check trace alignment around the first round (`results/snr_unprotected.png`). |

## 12. What's next

- **US2, the deep-learning attack (DLSCA):** train a CNN (identity / 256-class model) on the
  random-key profiling set already captured, recover the key, and compare its trace budget to
  CPA's ~100. This is the project's "AI" headline.
- **US3, the defense:** flash a first-order **masked** AES (the kit ships one as
  `CRYPTO_TARGET=MASKEDAES`) and show the same attacks no longer reach rank 0 within 10× the
  trace budget, which quantifies the countermeasure.
- **Content:** a two-part writeup (attack, then defense) drawn from the `results/` figures.

---

*Part of an AI + embedded + hardware-security series. This document covers the CPA baseline.*
