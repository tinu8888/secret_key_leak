"""Tests for dlsca.cpa, CPA recovers the key on synthetic HW-leakage traces (host-only).

Synthetic traces: at one "leak" sample the power equals HW(Sbox(p ^ k_true)) for each byte
plus Gaussian noise; the other samples are noise. CPA's Hamming-weight correlation should pick
out the correct key candidate per byte. No hardware involved.
"""

import numpy as np

from dlsca import attack, cpa
from dlsca.leakage import hamming_weight, sbox


def _synthetic_traces(n, s, known_key, leak_sample=None, noise=1.0, seed=0):
    rng = np.random.default_rng(seed)
    plaintexts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    traces = rng.normal(0.0, noise, size=(n, s))
    if leak_sample is None:
        leak_sample = s // 2
    # Superimpose each byte's HW leakage at a distinct sample (spread across the window).
    for b in range(16):
        samp = (leak_sample + b) % s
        hw = hamming_weight(sbox(plaintexts[:, b] ^ known_key[b])).astype(np.float64)
        traces[:, samp] += 3.0 * hw  # strong leak so it survives the noise
    return traces.astype(np.float32), plaintexts


def test_cpa_byte_scores_pick_correct_candidate():
    known = np.arange(16, dtype=np.uint8) * 9 % 256
    traces, pts = _synthetic_traces(800, 40, known, noise=1.0, seed=1)
    for b in range(16):
        scores = cpa.byte_scores(traces, pts, b)
        assert int(np.argmax(scores)) == known[b], f"byte {b}"


def test_cpa_recovers_full_key():
    known = (np.arange(16, dtype=np.uint8) * 17 + 3) % 256
    traces, pts = _synthetic_traces(800, 40, known, noise=1.0, seed=2)
    scores = cpa.cpa_scores(traces, pts)
    ranks = attack.key_rank(scores, known)
    assert np.array_equal(ranks, np.zeros(16, dtype=int)), ranks


def test_cpa_run_result_contract():
    known = (np.arange(16, dtype=np.uint8) * 5 + 1) % 256
    traces, pts = _synthetic_traces(800, 40, known, noise=1.0, seed=3)
    result = cpa.run(
        traces, pts, known, firmware="aes-unprotected", dataset="syn",
        n_orderings=3, seed=3, with_ge=True,
    )
    assert result["method"] == "cpa"
    assert result["label_model"] == "hamming-weight"
    assert result["correct"] == [True] * 16
    assert result["recovered_key"] == [int(v) for v in known]
    assert result["n_attack_traces"] == 800
    assert len(result["ge_curve"]) == len(result["ge_trace_counts"])
    # With strong leakage the full key is recovered within the budget.
    assert result["traces_to_rank0"] is not None


def test_cpa_fails_on_pure_noise():
    """No leakage -> CPA should NOT confidently recover the full key (honest negative)."""
    known = np.arange(16, dtype=np.uint8)
    rng = np.random.default_rng(4)
    traces = rng.normal(size=(200, 30)).astype(np.float32)  # no embedded leak
    pts = rng.integers(0, 256, size=(200, 16), dtype=np.uint8)
    scores = cpa.cpa_scores(traces, pts)
    ranks = attack.key_rank(scores, known)
    assert not np.array_equal(ranks, np.zeros(16, dtype=int))
