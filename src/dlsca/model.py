"""Profiling CNN for DLSCA, compact 1-D CNN with the identity (256-class) label (US2).

A small ASCAD-style 1-D CNN learns ``p(Sbox(plaintext[b] xor key[b]) | trace)`` from the
random-key profiling set, then scores the fixed-key attack set. The model is
self-describing: a JSON **model card** stores everything needed to re-apply the exact training
transform (POI window + standardization) at inference time, so a loaded model produces the
same outputs it did during training.

``torch`` is imported here only; the package guards the ``model`` import so the rest of
``dlsca`` (pure-NumPy analysis) still works on a host without PyTorch installed.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from typing import Optional, Tuple

import numpy as np

import torch
import torch.nn as nn

from . import preprocess, seeds

N_CLASSES = 256


# --------------------------------------------------------------------------------------
# Architecture: compact 1-D CNN, identity 256-class head.
# --------------------------------------------------------------------------------------
class CnnDLSCA(nn.Module):
    """Compact ASCAD-style 1-D CNN: Conv→BN→ReLU→AvgPool blocks → dense → 256-way logits.

    Small by design (a few thousand parameters per conv stage) so it trains in seconds on a
    laptop CPU/MPS while still reaching rank 0 on an unprotected software-AES target.
    """

    def __init__(self, input_len: int, n_classes: int = N_CLASSES):
        super().__init__()
        self.input_len = int(input_len)
        self.n_classes = int(n_classes)

        # Two conv blocks; AvgPool halves the length each time.
        self.features = nn.Sequential(
            nn.Conv1d(1, 8, kernel_size=11, padding=5),
            nn.BatchNorm1d(8),
            nn.ReLU(),
            nn.AvgPool1d(2),
            nn.Conv1d(8, 16, kernel_size=11, padding=5),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.AvgPool1d(2),
        )
        # Length after two /2 pools (floor division).
        flat_len = (self.input_len // 2) // 2
        self.flat_features = 16 * flat_len
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(self.flat_features, 128),
            nn.ReLU(),
            nn.Linear(128, self.n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (N, input_len) -> add channel dim -> (N, 1, input_len).
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.features(x)
        return self.classifier(x)


def build(input_len: int, n_classes: int = N_CLASSES) -> nn.Module:
    """Construct the compact 1-D CNN.

    Args:
        input_len: number of samples in the (windowed) input trace.
        n_classes: output classes (256 for the identity label).

    Returns:
        An untrained ``CnnDLSCA`` module.
    """
    return CnnDLSCA(input_len, n_classes)


# --------------------------------------------------------------------------------------
# Device selection.
# --------------------------------------------------------------------------------------
def _pick_device(prefer_mps: bool = True) -> torch.device:
    """MPS if available (Apple Silicon), else CPU."""
    if prefer_mps and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


# --------------------------------------------------------------------------------------
# Training.
# --------------------------------------------------------------------------------------
def train(
    model: nn.Module,
    traces: np.ndarray,
    labels: np.ndarray,
    poi_window: Tuple[int, int],
    seed: int = 0,
    *,
    name: str = "cnn",
    target_byte=None,
    label_model: str = "identity-256",
    train_set: str = "",
    epochs: int = 30,
    batch_size: int = 128,
    lr: float = 1e-3,
    val_frac: float = 0.1,
    prefer_mps: bool = True,
    verbose: bool = False,
) -> dict:
    """Train the CNN deterministically and return its model card.

    The input ``traces`` are sliced to ``poi_window`` and standardized with stats fit on the
    training split; those stats are stored in the card so inference re-applies the identical
    transform (model-card contract). Training is deterministic given ``seed``
    (``seeds.set_all``). On an MPS runtime error the run falls back to CPU and records it.

    Args:
        model: a module from :func:`build` with matching ``input_len``.
        traces: ``(N, S)`` raw profiling traces (full length; windowed here).
        labels: ``(N,)`` integer class labels 0-255 (identity S-box value).
        poi_window: ``(start, end)`` POI slice applied to ``traces``.
        seed: reproducibility seed (recorded in the card).
        name: card/model name.
        target_byte: which key byte this model attacks (recorded; may be "per-byte").
        label_model: label encoding name (recorded).
        train_set: profiling TraceSet name (recorded).
        epochs / batch_size / lr: training hyperparameters (recorded).
        val_frac: fraction held out for validation accuracy.
        prefer_mps: try MPS first; fall back to CPU on error.
        verbose: print per-epoch loss/accuracy.

    Returns:
        The model card dict.
    """
    seeds.set_all(seed)

    start, end = int(poi_window[0]), int(poi_window[1])
    windowed = preprocess.window(np.asarray(traces, dtype=np.float64), (start, end))
    labels = np.asarray(labels, dtype=np.int64).reshape(-1)
    n = windowed.shape[0]
    if labels.shape[0] != n:
        raise ValueError(f"labels ({labels.shape[0]}) and traces ({n}) length mismatch")
    input_len = end - start
    if getattr(model, "input_len", input_len) != input_len:
        raise ValueError(
            f"model input_len={model.input_len} != poi_window length {input_len}"
        )

    # Deterministic train/val split.
    rng = np.random.default_rng(seed)
    perm = rng.permutation(n)
    n_val = max(1, int(round(val_frac * n))) if val_frac > 0 else 0
    val_idx = perm[:n_val]
    tr_idx = perm[n_val:]

    # Fit standardizer on the TRAIN split only, then apply everywhere.
    stats = preprocess.fit_standardizer(windowed[tr_idx])
    x_all = preprocess.apply_standardizer(windowed, stats)  # float32 (N, L)

    device = _pick_device(prefer_mps)

    def _run_training(dev: torch.device) -> Tuple[nn.Module, float]:
        seeds.set_all(seed)  # re-seed so device fallback is still deterministic
        net = model.to(dev)
        opt = torch.optim.Adam(net.parameters(), lr=lr)
        loss_fn = nn.CrossEntropyLoss()

        x_tr = torch.from_numpy(x_all[tr_idx]).to(dev)
        y_tr = torch.from_numpy(labels[tr_idx]).to(dev)
        x_vl = torch.from_numpy(x_all[val_idx]).to(dev) if n_val else None
        y_vl = torch.from_numpy(labels[val_idx]).to(dev) if n_val else None

        n_tr = x_tr.shape[0]
        g = torch.Generator(device="cpu").manual_seed(seed)
        for ep in range(epochs):
            net.train()
            order = torch.randperm(n_tr, generator=g)
            ep_loss = 0.0
            for i in range(0, n_tr, batch_size):
                idx = order[i : i + batch_size]
                xb = x_tr[idx]
                yb = y_tr[idx]
                opt.zero_grad()
                logits = net(xb)
                loss = loss_fn(logits, yb)
                loss.backward()
                opt.step()
                ep_loss += float(loss.item()) * xb.shape[0]
            if verbose:
                msg = f"[{name}] epoch {ep + 1}/{epochs} loss={ep_loss / n_tr:.4f}"
                if x_vl is not None:
                    net.eval()
                    with torch.no_grad():
                        acc = (net(x_vl).argmax(1) == y_vl).float().mean().item()
                    msg += f" val_acc={acc:.4f}"
                print(msg)

        val_acc = 0.0
        if x_vl is not None:
            net.eval()
            with torch.no_grad():
                val_acc = float((net(x_vl).argmax(1) == y_vl).float().mean().item())
        return net, val_acc

    try:
        net, val_acc = _run_training(device)
    except RuntimeError as exc:  # MPS can be flaky for some ops; fall back to CPU.
        if device.type == "mps":
            if verbose:
                print(f"[{name}] MPS failed ({exc}); falling back to CPU")
            device = torch.device("cpu")
            net, val_acc = _run_training(device)
        else:
            raise

    net.eval()
    net.to("cpu")  # store/serve on CPU for portability

    card = {
        "name": name,
        "label_model": label_model,
        "target_byte": (
            int(target_byte) if isinstance(target_byte, (int, np.integer)) else "per-byte"
        ),
        "arch": f"CnnDLSCA(input_len={input_len}): Conv8-BN-ReLU-Avg2 x Conv16 -> FC128 -> {N_CLASSES}",
        "poi_window": [start, end],
        "normalization": {"mean": stats["mean"], "std": stats["std"]},
        "train_set": train_set,
        "epochs": int(epochs),
        "batch_size": int(batch_size),
        "lr": float(lr),
        "val_accuracy": float(val_acc),
        "seed": int(seed),
        "framework": f"torch {torch.__version__}",
        "numpy": np.__version__,
        "device": device.type,
        "input_len": int(input_len),
        "n_classes": int(getattr(net, "n_classes", N_CLASSES)),
        "date": _dt.date.today().isoformat(),
    }
    return card


# --------------------------------------------------------------------------------------
# Inference helper.
# --------------------------------------------------------------------------------------
def predict_log_proba(
    model: nn.Module, traces: np.ndarray, card: dict, *, prefer_mps: bool = True
) -> np.ndarray:
    """Class log-probabilities for raw traces, applying the card's POI + normalization.

    Re-applies the exact training-time transform stored in ``card`` so a loaded model sees the
    same input distribution it trained on (model-card contract).

    Args:
        model: a trained module.
        traces: ``(N, S)`` raw traces (full length).
        card: model card with ``poi_window`` + ``normalization``.
        prefer_mps: run inference on MPS when available.

    Returns:
        ``(N, 256)`` log-probabilities (``float64``).
    """
    start, end = int(card["poi_window"][0]), int(card["poi_window"][1])
    windowed = preprocess.window(np.asarray(traces, dtype=np.float64), (start, end))
    x = preprocess.apply_standardizer(windowed, card["normalization"])

    device = _pick_device(prefer_mps)
    try:
        net = model.to(device).eval()
        with torch.no_grad():
            logits = net(torch.from_numpy(x).to(device))
            logp = torch.log_softmax(logits, dim=1).cpu().numpy()
    except RuntimeError:
        net = model.to("cpu").eval()
        with torch.no_grad():
            logits = net(torch.from_numpy(x))
            logp = torch.log_softmax(logits, dim=1).numpy()
    model.to("cpu")
    return logp.astype(np.float64)


# --------------------------------------------------------------------------------------
# Persistence (weights + card).
# --------------------------------------------------------------------------------------
def save(model: nn.Module, card: dict, models_dir: str = "models") -> Tuple[str, str]:
    """Persist weights (``models/<name>.pt``) + card (``models/<name>.card.json``).

    Returns:
        ``(weights_path, card_path)``.
    """
    os.makedirs(models_dir, exist_ok=True)
    name = card["name"]
    weights_path = os.path.join(models_dir, f"{name}.pt")
    card_path = os.path.join(models_dir, f"{name}.card.json")
    torch.save(model.to("cpu").state_dict(), weights_path)
    with open(card_path, "w", encoding="utf-8") as fh:
        json.dump(card, fh, indent=2, sort_keys=True)
    return weights_path, card_path


def load(name: str, models_dir: str = "models") -> Tuple[nn.Module, dict]:
    """Load a trained model + card; rebuild the architecture from the card.

    The card's ``poi_window`` and ``normalization`` are restored so inference re-applies the
    same transform as training (model-card contract / test obligation).

    Returns:
        ``(model, card)`` with weights loaded and the module in eval mode on CPU.
    """
    card_path = os.path.join(models_dir, f"{name}.card.json")
    weights_path = os.path.join(models_dir, f"{name}.pt")
    with open(card_path, "r", encoding="utf-8") as fh:
        card = json.load(fh)

    input_len = int(card.get("input_len") or (card["poi_window"][1] - card["poi_window"][0]))
    n_classes = int(card.get("n_classes", N_CLASSES))
    model = build(input_len, n_classes)
    state = torch.load(weights_path, map_location="cpu")
    model.load_state_dict(state)
    model.eval()
    return model, card
