"""Correlation Power Analysis (CPA), the classical control.

CPA correlates the measured power at each time sample against the **Hamming weight** of the
first-round S-box output for each key-byte candidate; the candidate whose correlation peak is
largest is the guess. Running CPA *before* the CNN is trusted is what proves the leak is real.
This module is pure NumPy and operates entirely on saved traces (no
hardware), so it is not approval-gated.

The accumulated ``(16, 256)`` score matrix it produces (peak absolute correlation per
candidate) plugs straight into :func:`dlsca.attack.run` / :func:`dlsca.attack.key_rank`.
"""

from __future__ import annotations

from typing import Optional, Sequence

import numpy as np

from . import attack as _attack
from .leakage import hamming_weight, sbox

N_BYTES = 16
N_CANDIDATES = 256


def _pearson_cols(model: np.ndarray, traces: np.ndarray) -> np.ndarray:
    """Pearson correlation of each model column against each trace sample column.

    Args:
        model: ``(N, C)`` hypothesis matrix (C candidates).
        traces: ``(N, S)`` power traces.

    Returns:
        ``(C, S)`` correlation matrix.
    """
    model = np.asarray(model, dtype=np.float64)
    traces = np.asarray(traces, dtype=np.float64)
    n = model.shape[0]

    m_c = model - model.mean(axis=0, keepdims=True)  # (N, C)
    t_c = traces - traces.mean(axis=0, keepdims=True)  # (N, S)

    cov = m_c.T @ t_c  # (C, S)
    m_ss = np.sqrt(np.einsum("nc,nc->c", m_c, m_c))  # (C,)
    t_ss = np.sqrt(np.einsum("ns,ns->s", t_c, t_c))  # (S,)

    denom = np.outer(m_ss, t_ss)  # (C, S)
    with np.errstate(divide="ignore", invalid="ignore"):
        corr = np.where(denom > 0, cov / denom, 0.0)
    return corr


def byte_correlations(
    traces: np.ndarray, plaintexts: np.ndarray, target_byte: int
) -> np.ndarray:
    """Per-candidate, per-sample correlation for one key byte.

    Returns:
        ``(256, S)`` absolute correlation matrix (rows = candidate key bytes).
    """
    pts = np.asarray(plaintexts, dtype=np.int64) & 0xFF
    p_b = pts[:, target_byte]  # (N,)

    # Hypothesis HW for every candidate: HW(Sbox(p ^ k)) -> (N, 256).
    candidates = np.arange(N_CANDIDATES, dtype=np.int64)
    inter = sbox(p_b[:, None] ^ candidates[None, :])  # (N, 256)
    model = hamming_weight(inter).astype(np.float64)  # (N, 256)

    corr = _pearson_cols(model, traces)  # (256, S)
    return np.abs(corr)


def byte_scores(traces: np.ndarray, plaintexts: np.ndarray, target_byte: int) -> np.ndarray:
    """Per-candidate score for one key byte = peak absolute correlation over time.

    Returns:
        ``(256,)`` score vector (higher = more likely the correct candidate).
    """
    return byte_correlations(traces, plaintexts, target_byte).max(axis=1)


def cpa_scores(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    target_bytes: Optional[Sequence[int]] = None,
) -> np.ndarray:
    """Accumulated ``(16, 256)`` CPA score matrix over all key bytes.

    Args:
        traces: ``(N, S)`` power traces.
        plaintexts: ``(N, 16)`` plaintexts.
        target_bytes: which bytes to attack (default all 16).

    Returns:
        ``(16, 256)`` scores ready for :func:`dlsca.attack.key_rank` / ``run``.
    """
    if target_bytes is None:
        target_bytes = range(N_BYTES)
    scores = np.zeros((N_BYTES, N_CANDIDATES), dtype=np.float64)
    for b in target_bytes:
        scores[b] = byte_scores(traces, plaintexts, b)
    return scores


def ge_curve(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    known_key,
    trace_counts: Optional[Sequence[int]] = None,
    n_orderings: int = 10,
    seed: int = 0,
) -> tuple:
    """Guessing-entropy curve for CPA by recomputing correlation at growing trace counts.

    CPA correlation is not additive per trace, so (unlike the CNN log-likelihood path) the GE
    curve is built by re-running CPA on the first ``t`` traces of each random ordering and
    averaging the full-key rank over orderings.

    Args:
        traces: ``(N, S)`` traces.
        plaintexts: ``(N, 16)`` plaintexts.
        known_key: 16 known key bytes (grading).
        trace_counts: ascending trace counts to evaluate (default: a log-ish spread up to N).
        n_orderings: random orderings to average over.
        seed: RNG seed for shuffles.

    Returns:
        ``(trace_counts, ge)`` where ``ge[i]`` is the mean full-key rank at ``trace_counts[i]``.
    """
    traces = np.asarray(traces, dtype=np.float64)
    pts = np.asarray(plaintexts, dtype=np.int64) & 0xFF
    known = np.asarray(known_key, dtype=np.int64).reshape(N_BYTES) & 0xFF
    n = traces.shape[0]

    if trace_counts is None:
        # Spread of counts from a few traces up to all of them.
        counts = sorted(set(int(c) for c in np.unique(
            np.geomspace(max(2, n // 50), n, num=min(20, n)).astype(int)
        )))
        trace_counts = [c for c in counts if 1 <= c <= n]

    rng = np.random.default_rng(seed)
    ge = np.zeros(len(trace_counts), dtype=np.float64)

    for _ in range(max(1, n_orderings)):
        order = rng.permutation(n)
        for i, t in enumerate(trace_counts):
            sel = order[:t]
            scores = cpa_scores(traces[sel], pts[sel])
            ranks = _attack.key_rank(scores, known)
            ge[i] += ranks.mean()

    ge /= max(1, n_orderings)
    return list(trace_counts), ge


def run(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    known_key,
    firmware: str = "aes-unprotected",
    dataset: str = "",
    n_orderings: int = 10,
    seed: int = 0,
    with_ge: bool = True,
) -> dict:
    """Full CPA attack -> AttackResult dict.

    Computes the accumulated scores (final recovered key + per-byte correctness) and, when
    ``with_ge``, a guessing-entropy curve and ``traces_to_rank0`` (smallest trace count at
    which the full key is recovered, averaged over orderings; ``null`` if never reached).
    """
    traces = np.asarray(traces, dtype=np.float64)
    scores = cpa_scores(traces, plaintexts)

    result = _attack.run(
        scores=scores,
        known_key=known_key,
        method="cpa",
        firmware=firmware,
        label_model="hamming-weight",
        dataset=dataset,
        per_trace_scores=None,
        n_orderings=n_orderings,
        seed=seed,
    )
    result["n_attack_traces"] = int(traces.shape[0])

    if with_ge:
        counts, ge = ge_curve(
            traces, plaintexts, known_key, n_orderings=n_orderings, seed=seed
        )
        result["ge_curve"] = [float(v) for v in ge]
        result["ge_trace_counts"] = [int(c) for c in counts]
        # traces_to_rank0 = first count where full-key GE rounds to 0 (all bytes rank 0).
        t2r0 = None
        for c, g in zip(counts, ge):
            if g == 0.0:
                t2r0 = int(c)
                break
        result["traces_to_rank0"] = t2r0

    return result
