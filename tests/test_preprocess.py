"""Tests for dlsca.preprocess, windowing bounds + standardization round-trip."""

import numpy as np
import pytest

from dlsca import preprocess


def test_window_basic():
    traces = np.arange(100).reshape(5, 20).astype(np.float64)
    w = preprocess.window(traces, (5, 15))
    assert w.shape == (5, 10)
    assert np.array_equal(w[0], np.arange(5, 15))


def test_window_1d():
    t = np.arange(20.0)
    w = preprocess.window(t, (3, 8))
    assert np.array_equal(w, np.arange(3, 8))


def test_window_out_of_bounds():
    traces = np.zeros((4, 10))
    with pytest.raises(ValueError):
        preprocess.window(traces, (0, 11))
    with pytest.raises(ValueError):
        preprocess.window(traces, (-1, 5))


def test_window_empty():
    traces = np.zeros((4, 10))
    with pytest.raises(ValueError):
        preprocess.window(traces, (5, 5))


def test_standardize_mean0_std1():
    rng = np.random.default_rng(0)
    traces = rng.normal(loc=3.0, scale=7.0, size=(500, 12))
    std_traces, stats = preprocess.standardize(traces)
    assert np.allclose(std_traces.mean(axis=0), 0.0, atol=1e-5)
    assert np.allclose(std_traces.std(axis=0), 1.0, atol=1e-5)
    assert len(stats["mean"]) == 12 and len(stats["std"]) == 12


def test_standardize_reuse_stats():
    rng = np.random.default_rng(1)
    train = rng.normal(size=(200, 8))
    attack = rng.normal(size=(50, 8))
    _, stats = preprocess.standardize(train)
    a1 = preprocess.apply_standardizer(attack, stats)
    a2, _ = preprocess.standardize(attack, stats)
    assert np.allclose(a1, a2)


def test_restore_round_trip():
    rng = np.random.default_rng(2)
    traces = rng.normal(loc=-2.0, scale=4.0, size=(100, 16))
    std_traces, stats = preprocess.standardize(traces)
    restored = preprocess.restore(std_traces, stats)
    assert np.allclose(restored, traces, atol=1e-4)


def test_constant_sample_no_blowup():
    traces = np.ones((10, 4)) * 5.0  # zero variance everywhere
    std_traces, stats = preprocess.standardize(traces)
    assert np.all(np.isfinite(std_traces))
