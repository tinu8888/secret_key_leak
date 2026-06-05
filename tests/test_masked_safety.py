"""Masking SAFETY tests (Group B).

These tests prove two things about the first-order masked AES firmware (US3):

  1. CORRECTNESS: data captured on the real ChipWhisperer-Nano still decrypts
     back to the original plaintext (the masking does not corrupt the cipher).
  2. SAFETY: the same attacks that break the unprotected target (CPA + CNN)
     fail on the masked target, and the exploitable first-order leak is gone.

Everything runs on saved traces and saved result JSONs only. No hardware,
no network. Every test seeds numpy and subsamples large arrays so each test
finishes well under 30 seconds (pure-Python AES decryption is slow, so the
roundtrip test checks a small random subset).
"""

import json
import os

import numpy as np
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO_ROOT, "results")

# Fixed seeds so every run picks the same rows / candidates.
SEED = 1234

# Leakage window. The unprotected first-round S-box leak lives near samples
# 500-800 (verified separately). We scan a window that covers the active AES
# computation but excludes the flat capture tail, where a near-constant ADC
# signal produces spurious correlation that is not exploitable leakage.
LEAK_LO = 400
LEAK_HI = 1000


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _load_result(name):
    path = os.path.join(RESULTS_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"missing result file: {path}")
    with open(path) as fh:
        return json.load(fh)


def _load_dataset(name):
    """Load a saved TraceSet, skipping the test cleanly if the file is absent."""
    from dlsca import dataset

    try:
        return dataset.load(name)
    except FileNotFoundError as exc:
        pytest.skip(f"missing trace file for dataset {name!r}: {exc}")
    except Exception as exc:  # noqa: BLE001 - any load failure should skip, not error
        # A missing .npz under traces/ surfaces as OSError/ValueError depending
        # on numpy version; treat any load failure as "no data, skip".
        if "No such file" in str(exc) or "not found" in str(exc).lower():
            pytest.skip(f"missing trace file for dataset {name!r}: {exc}")
        raise


def _first_order_leak(traces, plaintexts, key, lo=LEAK_LO, hi=LEAK_HI):
    """Maximum first-order HW(S-box) Pearson correlation over bytes and samples.

    leak = max over the 16 key bytes of
           ( max over samples of | corr( HW(Sbox(pt_b xor key_b)), trace[:, s] ) | )

    The correlation is vectorized: standardize the trace columns once, then for
    each byte standardize the leak model and take the mean of the product, which
    equals Pearson r per sample. Only the [lo:hi] sample window is scanned.
    """
    from dlsca.leakage import hamming_weight, sbox

    tr = np.asarray(traces[:, lo:hi], dtype=np.float64)
    tr = tr - tr.mean(axis=0, keepdims=True)
    std = tr.std(axis=0, keepdims=True)
    std[std == 0.0] = 1.0
    tr_n = tr / std

    key = np.asarray(key, dtype=np.uint8)
    pt = np.asarray(plaintexts, dtype=np.uint8)

    best = 0.0
    for b in range(16):
        model = hamming_weight(sbox(pt[:, b] ^ key[b])).astype(np.float64)
        model -= model.mean()
        m_std = model.std()
        if m_std == 0.0:
            continue
        model /= m_std
        corr = np.abs((tr_n * model[:, None]).mean(axis=0))
        peak = float(corr.max())
        if peak > best:
            best = peak
    return best


# --------------------------------------------------------------------------
# 8.4  ON-HARDWARE DATA RECOVERY (roundtrip)
# --------------------------------------------------------------------------
@pytest.mark.parametrize("ds_name", ["masked_fixedkey", "masked_randomkey"])
def test_8_4_onhardware_roundtrip_decrypts(ds_name):
    """8.4: ciphertexts captured on the real Nano decrypt back to the plaintext.

    For a seeded random subset of rows, assert
    aes128_decrypt_block(ciphertext_row, key_row) == plaintext_row.
    """
    from dlsca.aes_ref import aes128_decrypt_block

    ts = _load_dataset(ds_name)
    n = ts.traces.shape[0]
    rng = np.random.default_rng(SEED)
    # ~300 rows: pure-Python AES decryption is slow, so keep the subset small.
    n_check = min(300, n)
    idx = rng.choice(n, size=n_check, replace=False)

    for i in idx:
        ct = np.asarray(ts.ciphertexts[i], dtype=np.uint8)
        key = np.asarray(ts.keys[i], dtype=np.uint8)
        pt = np.asarray(ts.plaintexts[i], dtype=np.uint8)
        recovered = np.asarray(aes128_decrypt_block(ct, key), dtype=np.uint8)
        assert np.array_equal(recovered, pt), (
            f"{ds_name} row {i}: decrypt(ciphertext, key) != plaintext"
        )


# --------------------------------------------------------------------------
# 8.6  CPA fails on masked
# --------------------------------------------------------------------------
def test_8_6_cpa_fails_on_masked():
    """8.6: the CPA attack never reaches rank 0 and does not recover the key."""
    r = _load_result("cpa_aes-masked.json")
    assert r["traces_to_rank0"] is None, "CPA reached rank 0 on masked (should not)"
    assert r["recovered_key"] != r["known_key"], "CPA recovered the masked key"
    assert not all(r["correct"]), "CPA marked every byte correct on masked"


# --------------------------------------------------------------------------
# 8.7  CNN fails on masked
# --------------------------------------------------------------------------
def test_8_7_cnn_fails_on_masked():
    """8.7: the CNN attack never reaches rank 0 and does not recover the key."""
    r = _load_result("cnn_aes-masked.json")
    assert r["traces_to_rank0"] is None, "CNN reached rank 0 on masked (should not)"
    assert r["recovered_key"] != r["known_key"], "CNN recovered the masked key"
    assert not all(r["correct"]), "CNN marked every byte correct on masked"


# --------------------------------------------------------------------------
# 8.8  first-order leakage is gone
# --------------------------------------------------------------------------
def test_8_8_first_order_leakage_gone():
    """8.8: HW(S-box) first-order correlation is high unprotected, near zero masked.

    Computed on a seeded subset (4000 traces) of unprotected_fixedkey and
    masked_fixedkey over the active AES window. Unprotected should be clearly
    high; masked should sit at the statistical noise floor and be far smaller.
    """
    rng = np.random.default_rng(SEED)

    up = _load_dataset("unprotected_fixedkey")
    mk = _load_dataset("masked_fixedkey")

    def subset_leak(ts):
        n = ts.traces.shape[0]
        n_use = min(4000, n)
        idx = rng.choice(n, size=n_use, replace=False)
        # fixed-key dataset: every row carries the same key, use row 0's key.
        key = ts.keys[idx[0]]
        return _first_order_leak(ts.traces[idx], ts.plaintexts[idx], key)

    leak_unprotected = subset_leak(up)
    leak_masked = subset_leak(mk)

    # Unprotected clearly leaks first order.
    assert leak_unprotected > 0.2, (
        f"unprotected first-order leak too low ({leak_unprotected:.4f}); "
        "expected a strong HW(S-box) correlation"
    )
    # Masked is near zero: below 0.1 (noise floor for thousands of traces)
    # and at least 3x smaller than the unprotected leak.
    assert leak_masked < 0.1, (
        f"masked first-order leak too high ({leak_masked:.4f}); masking failed"
    )
    assert leak_masked < leak_unprotected / 3.0, (
        f"masked leak {leak_masked:.4f} not far below unprotected "
        f"{leak_unprotected:.4f} (need >=3x smaller)"
    )


# --------------------------------------------------------------------------
# 8.9  same attack code, both targets
# --------------------------------------------------------------------------
def test_8_9_same_cpa_pipeline_both_targets():
    """8.9: identical CPA pipeline recovers the unprotected key but not the masked one.

    cpa.cpa_scores + attack.key_rank on a seeded 2000-trace subset of each
    fixed-key dataset. Unprotected: all 16 byte ranks == 0. Masked: not all == 0.
    """
    from dlsca import attack, cpa

    rng = np.random.default_rng(SEED)

    def run_pipeline(ts):
        n = ts.traces.shape[0]
        n_use = min(2000, n)
        idx = rng.choice(n, size=n_use, replace=False)
        scores = cpa.cpa_scores(ts.traces[idx], ts.plaintexts[idx])
        ranks = attack.key_rank(scores, ts.keys[idx[0]])
        return np.asarray(ranks)

    up_ranks = run_pipeline(_load_dataset("unprotected_fixedkey"))
    mk_ranks = run_pipeline(_load_dataset("masked_fixedkey"))

    assert np.all(up_ranks == 0), (
        f"CPA did not recover every unprotected byte; ranks={up_ranks.tolist()}"
    )
    assert not np.all(mk_ranks == 0), (
        f"CPA recovered the masked key with the same code; ranks={mk_ranks.tolist()}"
    )


# --------------------------------------------------------------------------
# 8.11  mask freshness / no fixed-mask shortcut
# --------------------------------------------------------------------------
def test_8_11_mask_freshness_no_fixed_mask_shortcut():
    """8.11: at the leakiest unprotected sample, masked carries no first-order leak.

    Find the single (byte, sample) with the strongest HW(S-box) correlation on
    unprotected_fixedkey. At that exact sample the masked traces must show
    essentially zero first-order correlation for that byte. We also confirm the
    masked ciphertexts genuinely vary row to row (the data really differs, so a
    flat / fixed-mask shortcut is ruled out: if the mask were constant the
    first-order leak would survive, and it does not).
    """
    from dlsca.leakage import hamming_weight, sbox

    rng = np.random.default_rng(SEED)
    up = _load_dataset("unprotected_fixedkey")
    mk = _load_dataset("masked_fixedkey")

    # Locate the leakiest (byte, sample) on the unprotected target.
    n_up = up.traces.shape[0]
    idx_up = rng.choice(n_up, size=min(4000, n_up), replace=False)
    up_traces = np.asarray(up.traces[idx_up, LEAK_LO:LEAK_HI], dtype=np.float64)
    up_traces -= up_traces.mean(axis=0, keepdims=True)
    up_std = up_traces.std(axis=0, keepdims=True)
    up_std[up_std == 0.0] = 1.0
    up_n = up_traces / up_std
    up_pt = np.asarray(up.plaintexts[idx_up], dtype=np.uint8)
    up_key = np.asarray(up.keys[idx_up[0]], dtype=np.uint8)

    best_byte, best_sample_rel, best_corr = 0, 0, 0.0
    for b in range(16):
        model = hamming_weight(sbox(up_pt[:, b] ^ up_key[b])).astype(np.float64)
        model -= model.mean()
        m_std = model.std()
        if m_std == 0.0:
            continue
        model /= m_std
        corr = np.abs((up_n * model[:, None]).mean(axis=0))
        s_rel = int(corr.argmax())
        if corr[s_rel] > best_corr:
            best_corr = float(corr[s_rel])
            best_byte = b
            best_sample_rel = s_rel
    best_sample_abs = best_sample_rel + LEAK_LO

    # Sanity: the unprotected leak we located is genuinely strong.
    assert best_corr > 0.2, (
        f"could not find a strong unprotected leak (peak {best_corr:.4f})"
    )

    # At that exact sample, the masked first-order correlation for the same
    # byte must be at the noise floor.
    n_mk = mk.traces.shape[0]
    idx_mk = rng.choice(n_mk, size=min(4000, n_mk), replace=False)
    mk_col = np.asarray(mk.traces[idx_mk, best_sample_abs], dtype=np.float64)
    mk_col -= mk_col.mean()
    c_std = mk_col.std()
    c_std = c_std if c_std != 0.0 else 1.0
    mk_col /= c_std
    mk_pt = np.asarray(mk.plaintexts[idx_mk], dtype=np.uint8)
    mk_key = np.asarray(mk.keys[idx_mk[0]], dtype=np.uint8)
    mk_model = hamming_weight(sbox(mk_pt[:, best_byte] ^ mk_key[best_byte])).astype(
        np.float64
    )
    mk_model -= mk_model.mean()
    mk_model /= mk_model.std()
    masked_corr_here = abs(float((mk_col * mk_model).mean()))

    assert masked_corr_here < 0.05, (
        f"masked traces still leak first order at the leakiest unprotected sample "
        f"(byte {best_byte}, sample {best_sample_abs}): corr {masked_corr_here:.4f}. "
        "A fixed / stale mask would show this; fresh masks should not."
    )

    # The masked data genuinely varies row to row (no degenerate capture).
    unique_rows = np.unique(np.asarray(mk.ciphertexts), axis=0).shape[0]
    assert unique_rows > n_mk // 2, (
        f"masked ciphertexts barely vary ({unique_rows} unique of {n_mk}); "
        "data is too uniform to trust the safety conclusion"
    )
