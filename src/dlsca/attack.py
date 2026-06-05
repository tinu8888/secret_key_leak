"""Key-ranking engine: key rank, guessing entropy, and the AttackResult assembler.

Shared by both attacks (CPA and CNN). The ranking is method-agnostic: an attack produces a
per-candidate **score** for each of the 16 key bytes (higher = more likely the correct
candidate), and this module turns scores into the standard, honest success metrics:
key rank and guessing entropy vs. number of traces.

Score conventions
-----------------
* ``scores``: ``(16, 256)`` accumulated scores, one row per key byte, one column per
  candidate value 0-255. Higher is better. Used by :func:`key_rank` and :func:`run`.
* ``per_trace_scores``: ``(16, N, 256)`` additive per-trace log-likelihood (or correlation)
  contributions. Cumulatively summed over traces inside :func:`guessing_entropy`.

Serialized to ``results/<method>_<firmware>.json``.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import numpy as np

N_BYTES = 16
N_CANDIDATES = 256


def key_rank(scores: np.ndarray, known_key) -> np.ndarray:
    """Per-byte rank of the correct key candidate from accumulated scores.

    Rank 0 means the correct candidate has the single highest score (fully recovered byte).

    Args:
        scores: ``(16, 256)`` accumulated per-candidate scores (higher = better).
        known_key: 16 known key bytes (for grading).

    Returns:
        ``int`` array ``[16]`` of ranks in ``0..255``.
    """
    scores = np.asarray(scores, dtype=np.float64)
    if scores.shape != (N_BYTES, N_CANDIDATES):
        raise ValueError(f"scores must be (16, 256), got {scores.shape}")
    known = np.asarray(known_key, dtype=np.int64).reshape(N_BYTES) & 0xFF

    ranks = np.empty(N_BYTES, dtype=int)
    for b in range(N_BYTES):
        row = scores[b]
        correct = row[known[b]]
        # Worst-case (pessimistic) tie-breaking: rank = #(strictly better) + #(equal) - 1.
        # This is the honest convention, a flat/undecided distribution yields a HIGH rank,
        # not a false rank-0, so "never recovered" is reported truthfully.
        ranks[b] = int(np.sum(row > correct) + np.sum(row == correct) - 1)
    return ranks


def guessing_entropy(
    per_trace_scores: np.ndarray,
    known_key,
    n_orderings: int = 10,
    seed: int = 0,
) -> np.ndarray:
    """Mean correct-key rank vs. number of attack traces, averaged over random orderings.

    Averaging over shuffled trace orderings guards against a lucky/unlucky ordering making a
    single run look better or worse than typical. The returned
    curve is the full-key guessing entropy: at each trace count it is the mean over bytes of
    the correct-candidate rank, averaged over ``n_orderings`` shuffles.

    Args:
        per_trace_scores: ``(16, N, 256)`` additive per-trace per-candidate scores.
        known_key: 16 known key bytes.
        n_orderings: number of random trace orderings to average over.
        seed: RNG seed for the shuffles (recorded for reproducibility).

    Returns:
        ``float`` array ``[N]``, guessing entropy after 1, 2, ..., N traces.
    """
    pts = np.asarray(per_trace_scores, dtype=np.float64)
    if pts.ndim != 3 or pts.shape[0] != N_BYTES or pts.shape[2] != N_CANDIDATES:
        raise ValueError(f"per_trace_scores must be (16, N, 256), got {pts.shape}")
    n = pts.shape[1]
    known = np.asarray(known_key, dtype=np.int64).reshape(N_BYTES) & 0xFF

    rng = np.random.default_rng(seed)
    ge_sum = np.zeros(n, dtype=np.float64)

    for _ in range(max(1, n_orderings)):
        order = rng.permutation(n)
        shuffled = pts[:, order, :]  # (16, N, 256)
        cum = np.cumsum(shuffled, axis=1)  # accumulated scores after t traces
        # Per byte, per trace count: rank of the correct candidate.
        ranks = np.empty((N_BYTES, n), dtype=np.float64)
        for b in range(N_BYTES):
            correct = cum[b, :, known[b]][:, None]  # (N, 1)
            # Pessimistic tie-break (matches key_rank): strictly-better + equal - 1.
            ranks[b] = np.sum(cum[b] > correct, axis=1) + np.sum(cum[b] == correct, axis=1) - 1
        ge_sum += ranks.mean(axis=0)  # mean over the 16 bytes

    return ge_sum / max(1, n_orderings)


def _first_full_recovery(
    per_trace_scores: np.ndarray, known_key, n_orderings: int, seed: int
) -> Optional[int]:
    """Smallest #traces at which *every* byte's rank is 0, averaged over orderings.

    Returns the mean (rounded up) first-full-recovery trace count, or ``None`` if at least
    one ordering never reaches all-bytes-rank-0 (then full recovery is "not reached").
    """
    pts = np.asarray(per_trace_scores, dtype=np.float64)
    n = pts.shape[1]
    known = np.asarray(known_key, dtype=np.int64).reshape(N_BYTES) & 0xFF
    rng = np.random.default_rng(seed)

    per_ordering = []
    for _ in range(max(1, n_orderings)):
        order = rng.permutation(n)
        cum = np.cumsum(pts[:, order, :], axis=1)  # (16, N, 256)
        # all_zero[t] True when every byte has rank 0 after t+1 traces.
        rank0 = np.ones(n, dtype=bool)
        for b in range(N_BYTES):
            correct = cum[b, :, known[b]][:, None]
            byte_rank = (
                np.sum(cum[b] > correct, axis=1)
                + np.sum(cum[b] == correct, axis=1)
                - 1
            )
            rank0 &= byte_rank == 0
        # Require it to STAY recovered through the end (stable recovery).
        hits = np.where(rank0)[0]
        reached = None
        for t in hits:
            if rank0[t:].all():
                reached = int(t) + 1  # 1-indexed trace count
                break
        if reached is None:
            return None
        per_ordering.append(reached)

    return int(np.ceil(np.mean(per_ordering)))


def run(
    scores: np.ndarray,
    known_key,
    method: str,
    firmware: str,
    label_model: str,
    dataset: str,
    per_trace_scores: Optional[np.ndarray] = None,
    n_orderings: int = 10,
    seed: int = 0,
) -> dict:
    """Assemble an AttackResult dict.

    Args:
        scores: ``(16, 256)`` accumulated scores over the full attack set.
        known_key: 16 known key bytes (grading).
        method: ``"cpa"`` or ``"cnn"``.
        firmware: ``"aes-unprotected"`` or ``"aes-masked"``.
        label_model: ``"hamming-weight"`` or ``"identity-256"``.
        dataset: name of the attacked TraceSet.
        per_trace_scores: ``(16, N, 256)`` for the GE curve + ``traces_to_rank0``. If omitted,
            ``ge_curve`` is empty and ``traces_to_rank0`` is computed from ``scores`` only
            (recovered now / null).
        n_orderings: orderings to average GE over.
        seed: recorded; also seeds the GE shuffles.

    Returns:
        The AttackResult dict (JSON-serializable). Use :func:`save_result` to persist it.
    """
    scores = np.asarray(scores, dtype=np.float64)
    known = np.asarray(known_key, dtype=np.int64).reshape(N_BYTES) & 0xFF

    ranks = key_rank(scores, known)
    recovered = np.argmax(scores, axis=1).astype(int)
    correct = [bool(ranks[b] == 0) for b in range(N_BYTES)]

    if per_trace_scores is not None:
        ge_curve = guessing_entropy(per_trace_scores, known, n_orderings, seed)
        n_attack = int(np.asarray(per_trace_scores).shape[1])
        traces_to_rank0 = _first_full_recovery(per_trace_scores, known, n_orderings, seed)
    else:
        # Without a per-trace curve we can report the final ranking but not when full
        # recovery happened, so traces_to_rank0 stays null (don't claim what wasn't shown).
        ge_curve = np.array([], dtype=np.float64)
        n_attack = 0
        traces_to_rank0 = None

    return {
        "method": method,
        "firmware": firmware,
        "dataset": dataset,
        "label_model": label_model,
        "recovered_key": [int(v) for v in recovered],
        "known_key": [int(v) for v in known],
        "correct": correct,
        "traces_to_rank0": traces_to_rank0,
        "n_attack_traces": n_attack,
        "n_orderings": int(n_orderings),
        "ge_curve": [float(v) for v in ge_curve],
        "seed": int(seed),
    }


def save_result(result: dict, results_dir: str = "results") -> str:
    """Write an AttackResult to ``results/<method>_<firmware>.json``.

    Returns:
        The path written.
    """
    os.makedirs(results_dir, exist_ok=True)
    path = os.path.join(results_dir, f"{result['method']}_{result['firmware']}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
    return path
