"""Central seed control for end-to-end reproducibility.

A single integer seeds Python's ``random``, NumPy, and (when installed) PyTorch, including
the determinism flags for the MPS / CPU backends used on the headline MacBook host. Every
notebook calls :func:`set_all` in its first cell and runs top-to-bottom.

The ``torch`` import is guarded so this module (and the rest of ``dlsca``) imports and runs
even before the approval-gated environment install adds PyTorch.
"""

from __future__ import annotations

import os
import random

import numpy as np

try:  # torch is optional until the approved environment install.
    import torch

    _HAS_TORCH = True
except ImportError:  # pragma: no cover - exercised only without torch installed
    torch = None  # type: ignore[assignment]
    _HAS_TORCH = False


def set_all(seed: int) -> int:
    """Seed every RNG used in the project from one integer.

    Seeds Python ``random``, NumPy, and, when available, PyTorch (CPU, CUDA, and MPS),
    and enables deterministic behaviour. Returns ``seed`` so callers can record it.

    Args:
        seed: Non-negative integer recorded in manifests / model cards.

    Returns:
        The seed that was set (for convenient recording).
    """
    seed = int(seed)

    # Hash-randomization affects dict/set ordering across processes; pin it for reproducibility.
    os.environ["PYTHONHASHSEED"] = str(seed)

    random.seed(seed)
    np.random.seed(seed)

    if _HAS_TORCH:
        torch.manual_seed(seed)
        # Covers all current/future devices in one call (CPU + any accelerator).
        torch.cuda.manual_seed_all(seed)
        try:
            # Best-effort global determinism; tolerated if the backend lacks support.
            torch.use_deterministic_algorithms(True, warn_only=True)
        except (AttributeError, RuntimeError):  # pragma: no cover - backend-dependent
            pass
        # cuDNN determinism flags are harmless no-ops on MPS/CPU.
        if hasattr(torch.backends, "cudnn"):
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False

    return seed


def has_torch() -> bool:
    """Whether PyTorch is importable in the current environment."""
    return _HAS_TORCH
