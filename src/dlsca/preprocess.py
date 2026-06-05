"""Trace preprocessing: POI windowing + standardization.

The CNN consumes a windowed, standardized slice of each trace. The standardization stats
(``mean``/``std``) are stored so the exact same transform is re-applied at attack/inference
time (model-card ``normalization`` block), otherwise a loaded model sees a different input
distribution than it trained on.
"""

from __future__ import annotations

from typing import Optional, Tuple

import numpy as np

# Smallest std we divide by, to avoid blow-up on constant (zero-variance) samples.
_EPS = 1e-8


def window(traces: np.ndarray, poi_window: Tuple[int, int]) -> np.ndarray:
    """Slice traces to a points-of-interest window ``[start, end)``.

    Args:
        traces: ``(N, S)`` array (or 1-D ``(S,)`` for a single trace).
        poi_window: ``(start, end)`` sample indices; ``end`` is exclusive.

    Returns:
        The windowed traces ``(N, end-start)`` (or ``(end-start,)`` for 1-D input).

    Raises:
        ValueError: if the window is out of bounds or empty.
    """
    arr = np.asarray(traces)
    start, end = int(poi_window[0]), int(poi_window[1])
    n_samples = arr.shape[-1]
    if start < 0 or end > n_samples:
        raise ValueError(
            f"poi_window [{start}, {end}) out of bounds for {n_samples} samples"
        )
    if end <= start:
        raise ValueError(f"poi_window must be non-empty: got [{start}, {end})")
    return arr[..., start:end]


def fit_standardizer(traces: np.ndarray) -> dict:
    """Compute per-sample mean/std normalization stats from (training) traces.

    Per-sample (column-wise) stats are standard for SCA CNNs: each time sample is centered
    and scaled independently. Stored as lists in the returned dict so they serialize cleanly
    into the JSON model card.

    Args:
        traces: ``(N, S)`` training traces (already windowed).

    Returns:
        ``{"mean": [...], "std": [...]}``, per-sample stats.
    """
    arr = np.asarray(traces, dtype=np.float64)
    if arr.ndim != 2:
        raise ValueError(f"expected 2-D (N, S) traces, got shape {arr.shape}")
    mean = arr.mean(axis=0)
    std = arr.std(axis=0)
    std = np.where(std < _EPS, 1.0, std)  # leave constant samples unscaled
    return {"mean": mean.tolist(), "std": std.tolist()}


def apply_standardizer(traces: np.ndarray, stats: dict) -> np.ndarray:
    """Apply stored standardization stats: ``(x - mean) / std``.

    Args:
        traces: ``(N, S)`` or ``(S,)`` traces (already windowed to match ``stats`` length).
        stats: dict from :func:`fit_standardizer` with ``mean``/``std``.

    Returns:
        Standardized traces as ``float32`` (the dtype the CNN expects).
    """
    arr = np.asarray(traces, dtype=np.float64)
    mean = np.asarray(stats["mean"], dtype=np.float64)
    std = np.asarray(stats["std"], dtype=np.float64)
    std = np.where(np.abs(std) < _EPS, 1.0, std)
    return ((arr - mean) / std).astype(np.float32)


def standardize(
    traces: np.ndarray, stats: Optional[dict] = None
) -> Tuple[np.ndarray, dict]:
    """Standardize traces, fitting stats when not supplied.

    Convenience wrapper for the common "fit on train, reuse on attack" pattern.

    Args:
        traces: ``(N, S)`` traces.
        stats: pre-computed stats to reuse; if ``None``, fit them from ``traces``.

    Returns:
        ``(standardized_traces, stats)``.
    """
    if stats is None:
        stats = fit_standardizer(traces)
    return apply_standardizer(traces, stats), stats


def restore(standardized: np.ndarray, stats: dict) -> np.ndarray:
    """Inverse of :func:`apply_standardizer`: recover the original (windowed) traces.

    Args:
        standardized: standardized traces.
        stats: the stats used to standardize.

    Returns:
        Reconstructed traces (``float64``), up to floating-point round-trip error.
    """
    arr = np.asarray(standardized, dtype=np.float64)
    mean = np.asarray(stats["mean"], dtype=np.float64)
    std = np.asarray(stats["std"], dtype=np.float64)
    std = np.where(np.abs(std) < _EPS, 1.0, std)
    return arr * std + mean
