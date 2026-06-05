"""dlsca, host-side DLSCA AES-128 key recovery for a ChipWhisperer target.

Public modules:
    seeds       central seed control (reproducibility)
    leakage     AES S-box, Hamming-weight (CPA) + identity (CNN) labels
    dataset     .npz TraceSet save/load/validate + JSON manifest
    preprocess  POI windowing + standardization
    cpa         Correlation Power Analysis, the classical control
    attack      key rank / guessing entropy / AttackResult
    capture     ChipWhisperer capture orchestration, hardware, approval-gated
    model       profiling CNN (added in US2; optional until torch is installed)

Pure-analysis modules import without torch or chipwhisperer present, so the package is usable
on a clean host before the approval-gated environment install.
"""

from __future__ import annotations

from . import attack, capture, dataset, leakage, preprocess, seeds

try:  # CPA depends only on NumPy; keep it optional-safe for symmetry.
    from . import cpa
except ImportError:  # pragma: no cover
    cpa = None  # type: ignore[assignment]

try:  # model.py lands in US2 and needs torch; don't hard-require it here.
    from . import model
except ImportError:  # pragma: no cover - model not implemented / torch absent yet
    model = None  # type: ignore[assignment]

__all__ = [
    "seeds",
    "leakage",
    "dataset",
    "preprocess",
    "cpa",
    "attack",
    "capture",
    "model",
]

__version__ = "0.1.0"
