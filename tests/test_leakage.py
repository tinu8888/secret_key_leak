"""Tests for dlsca.leakage, S-box correctness + label ranges (data-model LeakageModel)."""

import numpy as np

from dlsca import leakage


def test_sbox_known_vectors():
    # FIPS-197 S-box spot checks.
    assert leakage.sbox(0x00) == 0x63
    assert leakage.sbox(0x53) == 0xED
    assert leakage.sbox(0xFF) == 0x16
    assert leakage.sbox(0x01) == 0x7C


def test_sbox_is_a_permutation():
    out = leakage.sbox(np.arange(256))
    assert sorted(out.tolist()) == list(range(256))


def test_sbox_vectorized_matches_scalar():
    xs = np.arange(256)
    vec = leakage.sbox(xs)
    assert all(int(vec[i]) == leakage.sbox(int(i)) for i in range(256))


def test_hamming_weight_range_and_values():
    hw = leakage.hamming_weight(np.arange(256))
    assert hw.min() == 0 and hw.max() == 8
    assert leakage.hamming_weight(0x00) == 0
    assert leakage.hamming_weight(0xFF) == 8
    assert leakage.hamming_weight(0x0F) == 4
    assert leakage.hamming_weight(0x80) == 1


def test_identity_label_range():
    ident = leakage.identity_label(np.arange(256))
    assert ident.min() == 0 and ident.max() == 255
    assert np.array_equal(ident, np.arange(256, dtype=np.uint8))


def test_intermediate_scalar():
    # Sbox(p ^ k) for known bytes.
    p, k = 0x32, 0x2B
    assert leakage.intermediate([p] + [0] * 15, [k] + [0] * 15, 0) == leakage.sbox(p ^ k)


def test_intermediate_candidate_sweep_batched():
    rng = np.random.default_rng(0)
    pts = rng.integers(0, 256, size=(50, 16), dtype=np.uint8)
    byte = 5
    # Single candidate key byte across a batch of plaintexts.
    out = leakage.intermediate(pts, 0x42, byte)
    assert out.shape == (50,)
    expected = leakage.sbox(pts[:, byte] ^ 0x42)
    assert np.array_equal(out, expected)


def test_intermediate_byte_bounds():
    import pytest

    with pytest.raises(ValueError):
        leakage.intermediate([0] * 16, [0] * 16, 16)
