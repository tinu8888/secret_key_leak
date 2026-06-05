"""ChipWhisperer capture orchestration.

The ONLY hardware-touching module. Every function that claims the USB device, flashes
firmware, or drives the target is **per-action human-approved**: it refuses
to run unless the caller passes ``approved=True``, and records the supplied ``approval_ref``
(a pointer into ``notes/approvals.md``) into the capture manifest. Pure-analysis code
(``cpa.py`` / ``attack.py`` / ``model.py``) operating on saved ``.npz`` is never gated.

The ``chipwhisperer`` import is guarded so this module imports even before the approval-gated
environment install adds the package, authoring and unit-testing the gating logic
needs no hardware and no SDK.

**This module is authoring only, no capture is run here.** Running any gated function is a
separate, human-approved hardware session.
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

import numpy as np

from .dataset import TraceSet, aes128_encrypt_block

try:  # chipwhisperer is optional until the approved environment install.
    import chipwhisperer as cw

    _HAS_CW = True
except ImportError:  # pragma: no cover - exercised only without chipwhisperer installed
    cw = None  # type: ignore[assignment]
    _HAS_CW = False


class ApprovalRequiredError(RuntimeError):
    """Raised when a hardware-touching action is invoked without explicit human approval."""


class DeviceClaimError(RuntimeError):
    """Raised when the host cannot claim the ChipWhisperer USB device, with remediation."""


def _require_approval(action: str, approved: bool, approval_ref: Optional[str]) -> str:
    """Gate a hardware action behind explicit, logged human approval.

    Args:
        action: human-readable description (used in the error message).
        approved: must be ``True`` to proceed.
        approval_ref: pointer into ``notes/approvals.md`` for the logged approval.

    Returns:
        The validated ``approval_ref`` (for embedding in the manifest).

    Raises:
        ApprovalRequiredError: if not approved or no approval reference was given.
    """
    if not approved:
        raise ApprovalRequiredError(
            f"'{action}' touches hardware and needs explicit human approval. "
            f"Re-invoke with approved=True ONLY after a human has authorized this exact "
            f"action and you have logged it in notes/approvals.md, then pass "
            f"approval_ref='notes/approvals.md#<entry>'. (Per-action human approval, "
            f"never batched, never unattended.)"
        )
    if not approval_ref:
        raise ApprovalRequiredError(
            f"'{action}' was marked approved=True but no approval_ref was supplied. "
            f"Record the approval in notes/approvals.md and pass its reference so the "
            f"manifest is auditable."
        )
    return approval_ref


def _require_cw() -> None:
    if not _HAS_CW:
        raise ImportError(
            "chipwhisperer is not installed. Installing it is an approval-gated step. "
            "Log it in notes/approvals.md before `pip install -r requirements.txt`."
        )


def connect(
    scope_config: Optional[dict] = None,
    approved: bool = False,
    approval_ref: Optional[str] = None,
):
    """Open the scope + target (claims the USB device, GATED).

    Args:
        scope_config: manifest ``scope`` block (sample rate, samples, gain, adc_clock,
            trigger) used to configure the scope.
        approved: must be ``True`` (per-action human approval).
        approval_ref: pointer into ``notes/approvals.md``.

    Returns:
        ``(scope, target)`` ChipWhisperer handles.

    Raises:
        ApprovalRequiredError: if not approved.
        DeviceClaimError: if the USB device cannot be claimed (with remediation steps).
    """
    _require_approval("connect (claim USB scope/target)", approved, approval_ref)
    _require_cw()

    try:
        scope = cw.scope()
    except Exception as exc:  # noqa: BLE001 - surface ANY claim failure as actionable advice
        raise DeviceClaimError(
            "Could not claim the ChipWhisperer USB device.\n"
            "Remediation:\n"
            "  1. Unplug and replug the ChipWhisperer (re-enumerate the USB device).\n"
            "  2. Ensure no other process holds it (close other notebooks/CW sessions, "
            "any running `cw` REPL, the CW GUI; check `lsof`/Activity Monitor).\n"
            "  3. Confirm the cable/port (use a known-good USB port; avoid passive hubs).\n"
            "  4. On macOS, verify libusb is installed and the device shows in System "
            "Information > USB.\n"
            f"Underlying error: {exc!r}"
        ) from exc

    try:
        target = cw.target(scope)
        # Start the target clock + default IO routing. Without this the Nano can flash a target
        # fine yet never RUN it (no clock) after a program/reset cycle -> the target stops
        # acking simpleserial and no trigger fires. (Diagnosed 2026-06-02; see notes/approvals.md.)
        if hasattr(scope, "default_setup"):
            scope.default_setup()
        if scope_config:
            _apply_scope_config(scope, scope_config)
    except Exception as exc:  # noqa: BLE001
        # Release the partially-claimed scope so the next attempt can re-claim it.
        try:
            scope.dis()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
        raise DeviceClaimError(
            "Claimed the scope but failed to attach the target / apply scope config. "
            "Replug the device and retry; ensure the correct target type is selected.\n"
            f"Underlying error: {exc!r}"
        ) from exc

    return scope, target


def _apply_scope_config(scope, scope_config: dict) -> None:
    """Best-effort application of a manifest ``scope`` block onto a CW scope handle."""
    gain = scope_config.get("gain")
    if gain is not None:
        scope.gain.db = gain
    samples = scope_config.get("samples")
    if samples is not None:
        scope.adc.samples = samples
    adc_clock = scope_config.get("adc_clock")
    if adc_clock is not None and hasattr(scope.clock, "adc_src"):
        scope.clock.adc_src = adc_clock
    trigger = scope_config.get("trigger")
    if trigger is not None and hasattr(scope, "trigger"):
        scope.trigger.triggers = trigger


def program(
    scope,
    variant: str,
    binary_path: str,
    approved: bool = False,
    approval_ref: Optional[str] = None,
) -> str:
    """Flash a firmware binary onto the target (FLASHES FIRMWARE, GATED).

    Args:
        scope: the connected scope handle.
        variant: ``"aes-unprotected"`` or ``"aes-masked"`` (recorded in the manifest).
        binary_path: path to the built ``.hex``/``.bin`` to flash.
        approved: must be ``True``.
        approval_ref: pointer into ``notes/approvals.md``.

    Returns:
        ``firmware_hash`` (``"sha256:..."``) of the flashed binary, for the manifest.
    """
    _require_approval(f"program/flash firmware '{variant}'", approved, approval_ref)
    _require_cw()

    firmware_hash = _sha256_file(binary_path)
    cw.program_target(scope, cw.programmers.STM32FProgrammer, binary_path)
    return firmware_hash


def capture_trace(scope, target, key, plaintext):
    """One armed capture; verifies the returned ciphertext (DRIVES THE TARGET).

    This drives the target, so it is only ever reached from within an approved ``campaign``;
    it deliberately takes no ``approved`` flag of its own, the campaign owns the approval.

    Returns:
        ``(wave, ciphertext)``, the power trace and the 16-byte ciphertext.

    Raises:
        ValueError: if the returned ciphertext != AES128(plaintext, key) (alignment/firmware bug).
    """
    _require_cw()
    # Accept bytes/bytearray as well as arrays/lists: np.asarray(b"...",
    # dtype=np.uint8) tries to PARSE the bytes as a numeric string and raises ValueError.
    # Convert raw bytes via frombuffer first so they're treated as bytes, not a number.
    if isinstance(key, (bytes, bytearray)):
        key = np.frombuffer(bytes(key), dtype=np.uint8)
    if isinstance(plaintext, (bytes, bytearray)):
        plaintext = np.frombuffer(bytes(plaintext), dtype=np.uint8)
    key = np.asarray(key, dtype=np.uint8).reshape(16)
    plaintext = np.asarray(plaintext, dtype=np.uint8).reshape(16)

    # bytearray(uint8 array) yields the right raw bytes for cw.capture_trace (not a coercion).
    trace = cw.capture_trace(scope, target, bytearray(plaintext), bytearray(key))
    if trace is None:
        raise DeviceClaimError(
            "capture_trace timed out (no trigger seen). Check the GPIO trigger fires at "
            "encryption start and the scope arm/trigger config matches the firmware."
        )
    wave = np.asarray(trace.wave, dtype=np.float32)
    ciphertext = np.asarray(bytearray(trace.textout), dtype=np.uint8)

    expected = aes128_encrypt_block(plaintext, key)
    if not np.array_equal(expected, ciphertext):
        raise ValueError(
            "captured ciphertext != AES128(plaintext, key), wrong firmware, key/plaintext "
            "mismatch, or a serial framing error. Refusing to record a bad trace."
        )
    return wave, ciphertext


def campaign(
    scope,
    target,
    role: str,
    n: int,
    base_manifest: dict,
    key_mode: str = "fixed",
    fixed_key=None,
    seed: int = 0,
    approved: bool = False,
    approval_ref: Optional[str] = None,
) -> TraceSet:
    """Capture ``n`` traces into a TraceSet (DRIVES THE TARGET, GATED).

    Args:
        scope, target: connected handles.
        role: ``"fixed-key"`` (attack set) or ``"random-key"`` (profiling set).
        n: number of traces to capture.
        base_manifest: manifest fields to merge (board/target/scope/cw_version/etc.).
        key_mode: ``"fixed"`` (one key, random plaintexts) or ``"random"`` (random keys).
        fixed_key: the 16-byte key for ``key_mode="fixed"`` (random if ``None``).
        seed: capture-time RNG seed (recorded).
        approved: must be ``True``.
        approval_ref: pointer into ``notes/approvals.md`` (recorded as ``approval_ref``).

    Returns:
        A :class:`~dlsca.dataset.TraceSet` ready for :func:`dlsca.dataset.save`.
    """
    _require_approval(f"capture campaign ({role}, n={n})", approved, approval_ref)
    _require_cw()

    rng = np.random.default_rng(seed)
    if key_mode == "fixed":
        key = (
            np.asarray(fixed_key, dtype=np.uint8).reshape(16)
            if fixed_key is not None
            else rng.integers(0, 256, size=16, dtype=np.uint8)
        )

    traces_list = []
    plaintexts = np.empty((n, 16), dtype=np.uint8)
    keys = np.empty((n, 16), dtype=np.uint8)
    ciphertexts = np.empty((n, 16), dtype=np.uint8)

    for i in range(n):
        pt = rng.integers(0, 256, size=16, dtype=np.uint8)
        k = key if key_mode == "fixed" else rng.integers(0, 256, size=16, dtype=np.uint8)
        wave, ct = capture_trace(scope, target, k, pt)
        traces_list.append(wave)
        plaintexts[i] = pt
        keys[i] = k
        ciphertexts[i] = ct

    traces = np.asarray(traces_list, dtype=np.float32)

    manifest = dict(base_manifest)
    manifest.update(
        {
            "role": role,
            "seed": int(seed),
            "approval_ref": approval_ref,
            "n_traces": int(n),
            "n_samples": int(traces.shape[1]) if n > 0 else 0,
            "date": _dt.date.today().isoformat(),
        }
    )
    if _HAS_CW and hasattr(cw, "__version__"):
        manifest.setdefault("cw_version", cw.__version__)

    return TraceSet(traces, plaintexts, keys, ciphertexts, manifest)


def _sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def has_chipwhisperer() -> bool:
    """Whether the ``chipwhisperer`` package is importable in the current environment."""
    return _HAS_CW
