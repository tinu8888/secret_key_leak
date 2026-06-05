# Run and test it, step by step

Follow these in order from the repo root. Each step shows the command and what you should see.
Most steps need no hardware. The few that need the captured power traces or the board are marked.

Tip: in a normal terminal, run the commands directly. Inside a Claude Code session, you can put
`! ` in front of a command to run it and see the output here, for example `! pytest -q`.

## 0. Check prerequisites

```bash
python3 --version      # need 3.9, 3.10, or 3.11
cc --version           # any C compiler (cc, clang, or gcc) for the masked-firmware tests
```

## 1. One-time setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt && pip install -e . --no-deps
```
You should see the packages install and finish without errors.

## 2. Run the whole test suite

```bash
pytest -q
```
Expect a row of dots and a line like `50 passed` (a few may show as `skipped` if the large
power-trace files are not on your machine; that is fine, see the note at the bottom).

## 3. See the two halves in detail

The data is recoverable (correctness):
```bash
pytest tests/test_masked_correctness.py -v
```
Expect 4 passing tests: masked encrypt equals standard AES, the decrypt roundtrip returns the
original data, the output does not depend on the mask, and masked equals unprotected.

The key does not leak (safety):
```bash
pytest tests/test_masked_safety.py -v
```
Expect 7 passing tests: CPA fails, the CNN fails, first-order leakage is gone, the same attack
code recovers the unprotected key but fails on the masked one, the captured ciphertexts decrypt
back, and the masks are fresh.

## 4. The headline verdict (safe and recoverable in one file)

```bash
python scripts/us3_verdict.py
cat results/masking_verdict.json
```
Expect `"verdict": "PASS - data protected AND fully recoverable"`.

## 5. Prove the masked AES is correct at the C level (no hardware)

```bash
cc -O2 -std=c11 firmware/aes-masked/src/dlsca_masked_aes.c \
   firmware/aes-masked/test/test_masked_host.c -o /tmp/test_masked
/tmp/test_masked
```
Expect `ALL TESTS PASSED`: the masked AES reproduces the standard ciphertext across 100,000
random masks.

Run one masked encryption by hand and watch the mask not change the output:
```bash
cc -O2 -std=c11 firmware/aes-masked/src/dlsca_masked_aes.c \
   firmware/aes-masked/test/masked_cli.c -o /tmp/masked_cli
/tmp/masked_cli 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff 1
/tmp/masked_cli 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff 2
```
Both print the same ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a`, even with different mask
seeds (1 and 2).

## 6. Reproduce the defense result (needs the saved power traces)

```bash
python scripts/us3_attack_masked.py    # runs CPA and the CNN on the masked traces
python scripts/us3_figure.py           # builds results/us3_defense_ge.png
```
Expect both attacks to report the key is not recovered (`traces_to_rank0 = None`), and a
before/after figure to be written. This needs `traces/masked_fixedkey.npz` and
`traces/masked_randomkey.npz` (see the note at the bottom).

## 7. Reproduce the attack on the unprotected target (needs the saved traces)

These are Jupyter notebooks, not scripts. Do not type the `.ipynb` path as a command. If you do,
you get `zsh: permission denied: notebooks/02_cpa_baseline.ipynb`, because a notebook is a file
you open in Jupyter, not a program you execute. Use one of the two ways below.

Make sure the environment is active first:
```bash
source .venv/bin/activate
```

Option A, in the browser (JupyterLab):
```bash
jupyter lab
```
This opens JupyterLab in your browser. In the file panel on the left, double-click
`notebooks/02_cpa_baseline.ipynb` to open it, then in the top menu choose `Run` then
`Run All Cells`. Do the same for `notebooks/03_cnn_dlsca.ipynb`. When you are done, go back to the
terminal and press `Ctrl+C` to stop the Jupyter server.

Expect notebook 02 to recover the key in about 100 traces (CPA) and notebook 03 in about 12
traces (CNN).

Option B, from the terminal (no browser; runs every cell and saves the outputs back into the
notebook):
```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/02_cpa_baseline.ipynb
jupyter nbconvert --to notebook --execute --inplace notebooks/03_cnn_dlsca.ipynb
```
If it finishes with no error, the run worked. Open the notebook afterward to see the recovered
key and the trace counts, or look at the figures written under `results/` (for example
`results/cpa_ge_curve.png` and `results/cnn_ge_curve.png`).

Both options need `traces/unprotected_fixedkey.npz` (notebook 03 also needs the random-key set).
See the note on power traces at the bottom.

## 8. Optional: live roundtrip on the ChipWhisperer-Nano (hardware)

This drives the board, so it is gated: flash the masked firmware first and record an approval in
`notes/approvals.md` (see `firmware/aes-masked/BUILD.md` for the flash steps).
```bash
python scripts/us3_live_roundtrip.py
```
Expect `16/16` ciphertexts correct and `16/16` decrypting back to the original, then
`PASS - masked chip output decrypts back to the original data`.

---

## Note on the power traces

The captured `.npz` trace files are large (about 100 MB each) and are not stored in git. Steps 2
and 3 still pass without them (the trace-dependent tests skip themselves), and steps 4 and 5 run
fully. Steps 6 and 7 need the traces: capture your own on a ChipWhisperer-Nano (the capture flow
is in `scripts/README.md` and `firmware/aes-masked/BUILD.md`). Every step that flashes firmware,
claims the USB device, or drives the board is done with explicit human approval and logged in
`notes/approvals.md`.
