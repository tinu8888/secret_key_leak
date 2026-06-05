"""Tests for dlsca.dataset, round-trip, N-mismatch, validate."""

import numpy as np
import pytest

from dlsca import dataset


def _make_set(n=8, s=20, fixed=True, seed=0):
    rng = np.random.default_rng(seed)
    traces = rng.standard_normal((n, s)).astype(np.float32)
    plaintexts = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    if fixed:
        key = rng.integers(0, 256, size=16, dtype=np.uint8)
        keys = np.tile(key, (n, 1))
    else:
        keys = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    ciphertexts = dataset.aes128_encrypt(plaintexts, keys)
    return traces, plaintexts, keys, ciphertexts


def test_aes_test_vector():
    pt = list(bytes.fromhex("00112233445566778899aabbccddeeff"))
    key = list(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    ct = dataset.aes128_encrypt_block(pt, key)
    assert bytes(ct.tolist()).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_save_load_round_trip(tmp_path):
    traces, pts, keys, cts = _make_set()
    manifest = {"role": "fixed-key", "firmware": "aes-unprotected", "seed": 0}
    dataset.save("rt", traces, pts, keys, cts, manifest, traces_dir=str(tmp_path))
    ts = dataset.load("rt", traces_dir=str(tmp_path))

    assert np.array_equal(ts.traces, traces)
    assert np.array_equal(ts.plaintexts, pts)
    assert np.array_equal(ts.keys, keys)
    assert np.array_equal(ts.ciphertexts, cts)
    assert ts.manifest["role"] == "fixed-key"
    assert ts.manifest["n_traces"] == traces.shape[0]
    assert ts.manifest["n_samples"] == traces.shape[1]


def test_refuses_overwrite(tmp_path):
    traces, pts, keys, cts = _make_set()
    m = {"role": "fixed-key"}
    dataset.save("dup", traces, pts, keys, cts, m, traces_dir=str(tmp_path))
    with pytest.raises(FileExistsError):
        dataset.save("dup", traces, pts, keys, cts, m, traces_dir=str(tmp_path))
    # overwrite=True succeeds.
    dataset.save("dup", traces, pts, keys, cts, m, traces_dir=str(tmp_path), overwrite=True)


def test_n_mismatch_raises_on_save(tmp_path):
    traces, pts, keys, cts = _make_set(n=8)
    with pytest.raises(ValueError):
        dataset.save("bad", traces, pts[:5], keys, cts, {}, traces_dir=str(tmp_path))


def test_n_mismatch_raises_on_load(tmp_path):
    # Hand-craft a .npz with mismatched N to exercise the loader guard.
    p = tmp_path / "mm.npz"
    np.savez(
        p,
        traces=np.zeros((8, 10), np.float32),
        plaintexts=np.zeros((5, 16), np.uint8),
        keys=np.zeros((8, 16), np.uint8),
        ciphertexts=np.zeros((8, 16), np.uint8),
    )
    with pytest.raises(ValueError):
        dataset.load("mm", traces_dir=str(tmp_path))


def test_validate_clean_fixed_key():
    traces, pts, keys, cts = _make_set(fixed=True)
    ts = dataset.TraceSet(traces, pts, keys, cts, {"role": "fixed-key", "n_samples": traces.shape[1]})
    report = dataset.validate(ts)
    assert report["ok"], report["errors"]
    assert report["fixed_key"] is True


def test_validate_clean_random_key():
    traces, pts, keys, cts = _make_set(fixed=False)
    ts = dataset.TraceSet(traces, pts, keys, cts, {"role": "random-key", "n_samples": traces.shape[1]})
    report = dataset.validate(ts)
    assert report["ok"], report["errors"]
    assert report["fixed_key"] is False


def test_validate_flags_corrupted_ciphertext():
    traces, pts, keys, cts = _make_set(fixed=True)
    cts = cts.copy()
    cts[3] ^= 0xFF  # corrupt one ciphertext row
    ts = dataset.TraceSet(traces, pts, keys, cts, {"role": "fixed-key"})
    report = dataset.validate(ts)
    assert not report["ok"]
    assert any("ciphertext mismatch" in e for e in report["errors"])


def test_validate_flags_role_invariant_mismatch():
    # Constant keys but labelled random-key -> flagged.
    traces, pts, keys, cts = _make_set(fixed=True)
    ts = dataset.TraceSet(traces, pts, keys, cts, {"role": "random-key"})
    report = dataset.validate(ts)
    assert not report["ok"]
    assert any("random-key" in e for e in report["errors"])


def test_validate_flags_nsamples_mismatch():
    traces, pts, keys, cts = _make_set()
    ts = dataset.TraceSet(traces, pts, keys, cts, {"role": "fixed-key", "n_samples": 999})
    report = dataset.validate(ts)
    assert not report["ok"]
    assert any("n_samples" in e for e in report["errors"])
