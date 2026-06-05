# US3 (masking defense) reproduction scripts

Run from the repo root, in the project `.venv`. These produce the masked before/after result.

| Script | Hardware? | What it does |
|--------|-----------|--------------|
| `us3_capture_masked.py` | **YES (gated)** | Drives the masked-flashed CW-Nano to capture `traces/masked_fixedkey.npz` + `traces/masked_randomkey.npz` (N=5000 each) with manifests. Every captured ciphertext is verified against AES128(pt,key). Requires the masked firmware flashed (`firmware/aes-masked/`, see its BUILD.md) and per-action approval logged in `notes/approvals.md`. |
| `us3_attack_masked.py` | no | Runs CPA + the profiling CNN on the saved masked traces -> `results/cpa_aes-masked.json`, `results/cnn_aes-masked.json`. Unlike the unprotected notebooks it does **not** assert recovery: for masked traces, failure to recover is the expected (defense-holds) outcome. |
| `us3_figure.py` | no | Builds `results/us3_defense_ge.png`, the unprotected-vs-masked guessing-entropy comparison, and prints the summary table. |

Order: flash masked firmware (approved) -> `us3_capture_masked.py` (approved) -> `us3_attack_masked.py` -> `us3_figure.py`.

Result (2026-06-02, CW-Nano / STM32F0): unprotected falls at CPA 100 / CNN 12 traces;
masked is not recovered at 5000 traces (CPA + CNN both `traces_to_rank0 = None`, mean key rank
stays ~100+). First-order masking defeats both first-order attacks, well past the 10x budget bar.
