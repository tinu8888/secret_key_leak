"""TraceSet persistence: ``.npz`` arrays + sidecar JSON manifest.

A TraceSet is the interchange format every analysis step reads. Saving a valid dataset is
what lets a clean machine reproduce the attack with no hardware. This module
owns ``save`` / ``load`` / ``validate`` and a self-contained AES-128 ECB used to check the
per-row ciphertext invariant (``AES128(plaintext_i, key_i) == ciphertext_i``).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .leakage import SBOX

# Exact array keys the contract mandates.
_ARRAY_KEYS = ("traces", "plaintexts", "keys", "ciphertexts")

# Inverse S-box is not needed (encryption only); key expansion uses the forward S-box.
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


# --------------------------------------------------------------------------------------
# Minimal AES-128 ECB (single block), for the ciphertext-consistency invariant only.
# --------------------------------------------------------------------------------------
def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """GF(2^8) multiply."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


def _key_expansion(key16: np.ndarray) -> list:
    """Expand a 16-byte key into 11 round keys (each a list of 16 bytes)."""
    sbox = SBOX
    words = [list(key16[i * 4 : i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [int(sbox[b]) for b in temp]  # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = []
        for w in range(4):
            rk.extend(words[r * 4 + w])
        round_keys.append(rk)
    return round_keys


def _add_round_key(state: list, rk: list) -> None:
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state: list) -> None:
    for i in range(16):
        state[i] = int(SBOX[state[i]])


def _shift_rows(state: list) -> None:
    # State is column-major: index = row + 4*col.
    new = list(state)
    for r in range(1, 4):
        for c in range(4):
            new[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    state[:] = new


def _mix_columns(state: list) -> None:
    for c in range(4):
        col = state[4 * c : 4 * c + 4]
        state[4 * c + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
        state[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
        state[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
        state[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)


def aes128_encrypt_block(plaintext16, key16) -> np.ndarray:
    """Encrypt one 16-byte block with AES-128 (ECB, single block).

    Args:
        plaintext16: 16 byte values.
        key16: 16 byte values.

    Returns:
        ``uint8`` array of 16 ciphertext bytes.
    """
    pt = np.asarray(plaintext16, dtype=np.uint8).reshape(16)
    key = np.asarray(key16, dtype=np.uint8).reshape(16)
    round_keys = _key_expansion(key)
    state = [int(b) for b in pt]

    _add_round_key(state, round_keys[0])
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return np.array(state, dtype=np.uint8)


def aes128_encrypt(plaintexts: np.ndarray, keys: np.ndarray) -> np.ndarray:
    """Vectorized convenience wrapper over :func:`aes128_encrypt_block` for ``(N, 16)`` inputs."""
    pts = np.asarray(plaintexts, dtype=np.uint8).reshape(-1, 16)
    ks = np.asarray(keys, dtype=np.uint8).reshape(-1, 16)
    if pts.shape[0] != ks.shape[0]:
        raise ValueError("plaintexts and keys must have the same N")
    out = np.empty_like(pts)
    for i in range(pts.shape[0]):
        out[i] = aes128_encrypt_block(pts[i], ks[i])
    return out


# --------------------------------------------------------------------------------------
# TraceSet container + I/O
# --------------------------------------------------------------------------------------
@dataclass
class TraceSet:
    """Captured campaign: aligned arrays + parsed manifest (data-model TraceSet)."""

    traces: np.ndarray
    plaintexts: np.ndarray
    keys: np.ndarray
    ciphertexts: np.ndarray
    manifest: dict = field(default_factory=dict)

    @property
    def n_traces(self) -> int:
        return int(self.traces.shape[0])

    @property
    def n_samples(self) -> int:
        return int(self.traces.shape[1])


def _paths(name: str, traces_dir: str) -> tuple:
    return (
        os.path.join(traces_dir, f"{name}.npz"),
        os.path.join(traces_dir, f"{name}.manifest.json"),
    )


def _check_shared_n(traces, plaintexts, keys, ciphertexts) -> int:
    """Validate the four arrays share N (first axis) and the 16-byte label width."""
    n = traces.shape[0]
    for label_name, arr in (
        ("plaintexts", plaintexts),
        ("keys", keys),
        ("ciphertexts", ciphertexts),
    ):
        if arr.shape[0] != n:
            raise ValueError(
                f"N mismatch: traces has {n} rows but {label_name} has {arr.shape[0]}"
            )
        if arr.ndim != 2 or arr.shape[1] != 16:
            raise ValueError(f"{label_name} must be (N, 16), got {arr.shape}")
    if traces.ndim != 2:
        raise ValueError(f"traces must be (N, S), got {traces.shape}")
    return n


def save(
    name: str,
    traces: np.ndarray,
    plaintexts: np.ndarray,
    keys: np.ndarray,
    ciphertexts: np.ndarray,
    manifest: dict,
    traces_dir: str = "traces",
    overwrite: bool = False,
) -> tuple:
    """Write ``traces/<name>.npz`` + ``traces/<name>.manifest.json``.

    Arrays are coerced to the contract dtypes (``traces`` float32, labels uint8). Refuses to
    overwrite existing files unless ``overwrite=True``.

    Returns:
        ``(npz_path, manifest_path)``.
    """
    traces = np.asarray(traces, dtype=np.float32)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    keys = np.asarray(keys, dtype=np.uint8)
    ciphertexts = np.asarray(ciphertexts, dtype=np.uint8)
    n = _check_shared_n(traces, plaintexts, keys, ciphertexts)

    os.makedirs(traces_dir, exist_ok=True)
    npz_path, manifest_path = _paths(name, traces_dir)
    if not overwrite and (os.path.exists(npz_path) or os.path.exists(manifest_path)):
        raise FileExistsError(
            f"refusing to overwrite existing dataset '{name}' (pass overwrite=True)"
        )

    manifest = dict(manifest)
    manifest.setdefault("name", name)
    manifest["n_traces"] = n
    manifest["n_samples"] = int(traces.shape[1])

    # Write atomically via temp files then rename, so a crash never leaves a half-written set.
    tmp_npz = npz_path + ".tmp"
    tmp_manifest = manifest_path + ".tmp"
    np.savez(
        tmp_npz,
        traces=traces,
        plaintexts=plaintexts,
        keys=keys,
        ciphertexts=ciphertexts,
    )
    # np.savez appends .npz to a path without one; normalize.
    if not os.path.exists(tmp_npz) and os.path.exists(tmp_npz + ".npz"):
        os.replace(tmp_npz + ".npz", tmp_npz)
    with open(tmp_manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp_npz, npz_path)
    os.replace(tmp_manifest, manifest_path)
    return npz_path, manifest_path


def load(name: str, traces_dir: str = "traces") -> TraceSet:
    """Load a TraceSet, validating the four arrays share N.

    Raises:
        FileNotFoundError: if the ``.npz`` is missing.
        ValueError: on an N mismatch between arrays.
    """
    npz_path, manifest_path = _paths(name, traces_dir)
    if not os.path.exists(npz_path):
        raise FileNotFoundError(f"no trace archive at {npz_path}")
    with np.load(npz_path) as data:
        missing = [k for k in _ARRAY_KEYS if k not in data]
        if missing:
            raise ValueError(f"{npz_path} missing arrays: {missing}")
        traces = data["traces"]
        plaintexts = data["plaintexts"]
        keys = data["keys"]
        ciphertexts = data["ciphertexts"]
    _check_shared_n(traces, plaintexts, keys, ciphertexts)

    manifest: dict = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)

    return TraceSet(traces, plaintexts, keys, ciphertexts, manifest)


def is_fixed_key(keys: np.ndarray) -> bool:
    """True if every key row is identical (the fixed-key / attack-set invariant)."""
    ks = np.asarray(keys, dtype=np.uint8)
    if ks.shape[0] == 0:
        return True
    return bool(np.all(ks == ks[0]))


def validate(ts: TraceSet, sample: Optional[int] = None) -> dict:
    """Validate a TraceSet before it feeds an attack.

    Checks, surfacing every failure (not silently dropping rows):
      * the four arrays share N and labels are ``(N, 16)``;
      * ``manifest.n_samples == traces.shape[1]`` (when the manifest records it);
      * the fixed/random-key invariant matches ``manifest.role``;
      * ``AES128(plaintext_i, key_i) == ciphertext_i`` for sampled (or all) rows.

    Args:
        ts: the TraceSet to check.
        sample: if given, check ciphertexts for a random subset of this many rows
            (deterministic order = first ``sample`` rows) instead of all N.

    Returns:
        A report dict: ``{"ok": bool, "errors": [...], "checked_rows": int, "n_traces": int,
        "fixed_key": bool, "role": str|None}``.
    """
    errors = []

    # Shapes.
    try:
        n = _check_shared_n(ts.traces, ts.plaintexts, ts.keys, ts.ciphertexts)
    except ValueError as exc:
        return {
            "ok": False,
            "errors": [str(exc)],
            "checked_rows": 0,
            "n_traces": int(ts.traces.shape[0]) if ts.traces.ndim >= 1 else 0,
            "fixed_key": None,
            "role": ts.manifest.get("role"),
        }

    role = ts.manifest.get("role")
    fixed = is_fixed_key(ts.keys)

    # n_samples consistency.
    manifest_ns = ts.manifest.get("n_samples")
    if manifest_ns is not None and int(manifest_ns) != int(ts.traces.shape[1]):
        errors.append(
            f"manifest n_samples={manifest_ns} != traces.shape[1]={ts.traces.shape[1]}"
        )

    # Fixed/random-key invariant vs role.
    if role == "fixed-key" and not fixed:
        errors.append("role is 'fixed-key' but key rows are not constant")
    if role == "random-key" and fixed and n > 1:
        errors.append("role is 'random-key' but every key row is identical")

    # Ciphertext consistency.
    if sample is not None and sample < n:
        idx = np.arange(min(sample, n))
    else:
        idx = np.arange(n)
    checked = 0
    bad_rows = []
    for i in idx:
        expected = aes128_encrypt_block(ts.plaintexts[i], ts.keys[i])
        if not np.array_equal(expected, np.asarray(ts.ciphertexts[i], dtype=np.uint8)):
            bad_rows.append(int(i))
        checked += 1
    if bad_rows:
        preview = bad_rows[:10]
        errors.append(
            f"ciphertext mismatch in {len(bad_rows)} row(s) "
            f"(AES128(pt,key) != ct); e.g. rows {preview}"
        )

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "checked_rows": checked,
        "n_traces": n,
        "fixed_key": fixed,
        "role": role,
    }
