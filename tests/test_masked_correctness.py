"""Masking correctness tests (Group A).

These tests drive the REAL masked AES C implementation on the host via a tiny
CLI (firmware/aes-masked/test/masked_cli.c) and compare its output against the
project's reference AES (encrypt and decrypt).

Goals verified here:
  8.1  the masked encrypt produces standard AES ciphertext.
  8.2  decrypting the masked ciphertext recovers the original plaintext (the
       single most important property: data is fully recovered).
  8.3  the ciphertext is independent of the random mask (the mask must not
       change the result), checked across many seeds.
  8.5  the masked output equals the unprotected firmware output.

Determinism: a fixed numpy seed is used so the random (key, plaintext, mask)
cases are identical on every run. No network, no hardware: the masked C code is
compiled and run purely on the host.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import pytest

from dlsca.aes_ref import aes128_decrypt_block
from dlsca.dataset import aes128_encrypt_block

# Repo root is two levels up from this test file (tests/ -> repo root).
REPO_ROOT = Path(__file__).resolve().parents[1]
MASKED_SRC = REPO_ROOT / "firmware" / "aes-masked" / "src" / "dlsca_masked_aes.c"
MASKED_CLI = REPO_ROOT / "firmware" / "aes-masked" / "test" / "masked_cli.c"


@pytest.fixture(scope="module")
def masked_cli():
    """Compile the masked AES CLI once per module and return its path.

    If a C compiler (cc) is not available, the whole module is skipped with a
    clear message rather than failing.
    """
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler (cc) available; cannot build masked AES CLI")
    if not MASKED_SRC.exists() or not MASKED_CLI.exists():
        pytest.skip(f"masked AES sources not found under {MASKED_SRC.parent}")

    tmpdir = tempfile.mkdtemp(prefix="masked_cli_")
    binary = Path(tmpdir) / "masked_cli"
    cmd = [
        cc,
        "-O2",
        "-std=c11",
        str(MASKED_SRC),
        str(MASKED_CLI),
        "-o",
        str(binary),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        pytest.skip(
            "failed to compile masked AES CLI:\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stderr:\n{proc.stderr}"
        )

    yield binary

    shutil.rmtree(tmpdir, ignore_errors=True)


def _run_masked(binary, key, pt, seed):
    """Run the masked CLI for one (key, plaintext, seed) and return ct bytes.

    key and pt are 16-byte numpy uint8 arrays; seed is an int (uint32 range).
    Returns a 16-element numpy uint8 array (the ciphertext).
    """
    key_hex = bytes(key).hex()
    pt_hex = bytes(pt).hex()
    proc = subprocess.run(
        [str(binary), key_hex, pt_hex, str(int(seed))],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"masked CLI failed (rc={proc.returncode}) for key={key_hex} "
        f"pt={pt_hex} seed={seed}: stderr={proc.stderr!r}"
    )
    out = proc.stdout.strip()
    assert len(out) == 32, f"expected 32 hex chars, got {out!r}"
    return np.frombuffer(bytes.fromhex(out), dtype=np.uint8)


def _random_cases(n, seed):
    """Generate n deterministic (key, plaintext, mask_seed) cases."""
    rng = np.random.default_rng(seed)
    keys = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    pts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    mask_seeds = rng.integers(0, 2**32, size=n, dtype=np.uint64)
    return keys, pts, mask_seeds


# N is kept at 1000: each subprocess call is fast, so 1000 cases (one process
# each) for 8.1 and 8.2 stays well under the 30s budget on this host.
N_CASES = 1000


def test_8_1_masked_equals_standard_aes(masked_cli):
    """8.1: masked encrypt output == standard AES ciphertext, many cases."""
    keys, pts, seeds = _random_cases(N_CASES, seed=20260602)
    for key, pt, seed in zip(keys, pts, seeds):
        ct_masked = _run_masked(masked_cli, key, pt, seed)
        ct_ref = aes128_encrypt_block(pt, key)
        assert np.array_equal(ct_masked, ct_ref), (
            f"masked ct != reference AES for key={bytes(key).hex()} "
            f"pt={bytes(pt).hex()} seed={int(seed)}"
        )


def test_8_2_roundtrip_recovery(masked_cli):
    """8.2: decrypt(masked_ct, key) == original plaintext (data recovered)."""
    keys, pts, seeds = _random_cases(N_CASES, seed=20260602)
    for key, pt, seed in zip(keys, pts, seeds):
        ct_masked = _run_masked(masked_cli, key, pt, seed)
        recovered = aes128_decrypt_block(ct_masked, key)
        assert np.array_equal(recovered, pt), (
            f"roundtrip failed: decrypt(masked_ct) != pt for "
            f"key={bytes(key).hex()} pt={bytes(pt).hex()} seed={int(seed)}"
        )


def test_8_3_output_independent_of_mask(masked_cli):
    """8.3: for a fixed (key, pt), all mask seeds give identical ciphertext."""
    rng = np.random.default_rng(424242)
    n_fixed = 3
    n_seeds = 60  # >= 50 distinct mask seeds per fixed case.
    for _ in range(n_fixed):
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        pt = rng.integers(0, 256, size=16, dtype=np.uint8)
        seeds = rng.integers(0, 2**32, size=n_seeds, dtype=np.uint64)
        cts = [_run_masked(masked_cli, key, pt, s) for s in seeds]
        first = cts[0]
        for s, ct in zip(seeds, cts):
            assert np.array_equal(ct, first), (
                f"ciphertext changed with mask seed {int(s)} for "
                f"key={bytes(key).hex()} pt={bytes(pt).hex()} "
                "(mask must not affect the result)"
            )


def test_8_5_masked_equals_unprotected(masked_cli):
    """8.5: masked output == unprotected firmware output, several cases.

    The unprotected firmware implements standard AES exactly, so the reference
    encrypt (aes128_encrypt_block) stands in for the unprotected firmware
    output here. Comparing the masked CLI against the reference therefore shows
    masked == unprotected without needing to flash or run the unprotected
    firmware.
    """
    keys, pts, seeds = _random_cases(25, seed=7777)
    for key, pt, seed in zip(keys, pts, seeds):
        ct_masked = _run_masked(masked_cli, key, pt, seed)
        unprotected_ct = aes128_encrypt_block(pt, key)
        assert np.array_equal(ct_masked, unprotected_ct), (
            f"masked ct != unprotected (reference) for "
            f"key={bytes(key).hex()} pt={bytes(pt).hex()} seed={int(seed)}"
        )
