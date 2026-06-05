"""Tests for dlsca.attack, key_rank, guessing_entropy, run.

Synthetic leakage: L = HW(Sbox(p ^ k_true)) + Gaussian noise. The per-trace, per-candidate
score is a Gaussian log-likelihood (additive over traces), so summing makes the correct key
accumulate the highest score, exactly the structure the ranking engine consumes.
"""

import numpy as np

from dlsca import attack
from dlsca.leakage import hamming_weight, sbox

N_BYTES = 16
N_CAND = 256


def _synthetic_scores(n, known_key, noise=0.5, seed=0):
    """Build (16, N, 256) per-trace log-likelihood scores for a known key."""
    rng = np.random.default_rng(seed)
    plaintexts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    cand = np.arange(N_CAND, dtype=np.int64)

    per_trace = np.empty((N_BYTES, n, N_CAND), dtype=np.float64)
    for b in range(N_BYTES):
        true_hw = hamming_weight(sbox(plaintexts[:, b] ^ known_key[b])).astype(np.float64)
        leakage = true_hw + rng.normal(0.0, noise, size=n)  # (N,)
        # HW hypothesis for every candidate: (N, 256)
        hyp = hamming_weight(sbox(plaintexts[:, b][:, None] ^ cand[None, :])).astype(np.float64)
        # Gaussian log-likelihood up to constants: -(leak - hyp)^2 / (2 sigma^2)
        per_trace[b] = -((leakage[:, None] - hyp) ** 2)
    return per_trace


def test_key_rank_all_zero_with_enough_traces():
    known = np.arange(16, dtype=np.uint8) * 7 % 256
    per_trace = _synthetic_scores(400, known, noise=0.4, seed=1)
    scores = per_trace.sum(axis=1)  # (16, 256)
    ranks = attack.key_rank(scores, known)
    assert np.array_equal(ranks, np.zeros(16, dtype=int)), ranks


def test_guessing_entropy_decreases_to_zero():
    known = np.arange(16, dtype=np.uint8) * 11 % 256
    per_trace = _synthetic_scores(400, known, noise=0.4, seed=2)
    ge = attack.guessing_entropy(per_trace, known, n_orderings=5, seed=3)
    assert ge.shape == (400,)
    # GE starts well above 0 and trends down to 0 by the end.
    assert ge[0] > ge[-1]
    assert ge[-1] == 0.0
    # Roughly monotone non-increasing (allow tiny upticks from ordering noise).
    assert ge[10] >= ge[-1]


def test_run_assembles_full_result():
    known = (np.arange(16, dtype=np.uint8) * 13 + 5) % 256
    per_trace = _synthetic_scores(500, known, noise=0.4, seed=4)
    scores = per_trace.sum(axis=1)
    result = attack.run(
        scores=scores,
        known_key=known,
        method="cnn",
        firmware="aes-unprotected",
        label_model="identity-256",
        dataset="synthetic",
        per_trace_scores=per_trace,
        n_orderings=5,
        seed=4,
    )
    assert result["method"] == "cnn"
    assert result["firmware"] == "aes-unprotected"
    assert result["correct"] == [True] * 16
    assert result["recovered_key"] == [int(v) for v in known]
    assert result["traces_to_rank0"] is not None
    assert 0 < result["traces_to_rank0"] <= 500
    assert len(result["ge_curve"]) == 500


def test_traces_to_rank0_null_when_byte_never_recovers():
    """If one byte is pure noise (no leakage), full recovery is never reached -> null."""
    known = np.arange(16, dtype=np.uint8)
    per_trace = _synthetic_scores(300, known, noise=0.4, seed=5)
    # Wipe out byte 7's signal: make every candidate equally likely (flat scores).
    per_trace[7] = 0.0
    result = attack.run(
        scores=per_trace.sum(axis=1),
        known_key=known,
        method="cpa",
        firmware="aes-unprotected",
        label_model="hamming-weight",
        dataset="synthetic-broken",
        per_trace_scores=per_trace,
        n_orderings=5,
        seed=5,
    )
    assert result["traces_to_rank0"] is None
    assert result["correct"][7] is False  # the wiped byte never reaches rank 0


def test_run_without_per_trace_scores_keeps_t2r0_null():
    known = np.arange(16, dtype=np.uint8) * 3 % 256
    per_trace = _synthetic_scores(300, known, noise=0.4, seed=6)
    scores = per_trace.sum(axis=1)
    result = attack.run(
        scores=scores,
        known_key=known,
        method="cpa",
        firmware="aes-unprotected",
        label_model="hamming-weight",
        dataset="synthetic",
        per_trace_scores=None,
    )
    # Final ranking is good, but without a per-trace curve we don't claim a trace count.
    assert result["correct"] == [True] * 16
    assert result["traces_to_rank0"] is None
    assert result["ge_curve"] == []


def test_save_result_writes_json(tmp_path):
    known = np.zeros(16, dtype=np.uint8)
    per_trace = _synthetic_scores(100, known, noise=0.4, seed=7)
    result = attack.run(
        scores=per_trace.sum(axis=1),
        known_key=known,
        method="cpa",
        firmware="aes-unprotected",
        label_model="hamming-weight",
        dataset="syn",
        per_trace_scores=per_trace,
        n_orderings=3,
        seed=7,
    )
    path = attack.save_result(result, results_dir=str(tmp_path))
    import json

    with open(path) as fh:
        loaded = json.load(fh)
    assert loaded["recovered_key"] == result["recovered_key"]
