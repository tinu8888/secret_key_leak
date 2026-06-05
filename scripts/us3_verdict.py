"""US3 combined verdict.

Summarizes BOTH halves of the masking story in one place:

  CORRECTNESS: a subset of masked_fixedkey ciphertexts is decrypted with the
               reference AES and confirmed to equal the captured plaintexts
               (the masked firmware still computes AES correctly on hardware).

  SAFETY:      the four attack result JSONs show that CPA and CNN recover the
               unprotected key but fail on the masked key.

Writes results/masking_verdict.json and prints a short human summary.

Deterministic (seeded), no hardware, no network. Operates on saved traces and
saved result JSONs only. Run with:

    ./.venv/bin/python scripts/us3_verdict.py
"""

import json
import os

import numpy as np

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO_ROOT, "results")

SEED = 1234
N_ROUNDTRIP = 300  # pure-Python AES decryption is slow; check a small subset.


def _load_result(name):
    with open(os.path.join(RESULTS_DIR, name)) as fh:
        return json.load(fh)


def _key_recovered(result):
    """True only when the attack fully recovered the key."""
    return (
        result.get("traces_to_rank0") is not None
        and result.get("recovered_key") == result.get("known_key")
        and all(result.get("correct", []))
    )


def roundtrip_check(n_check=N_ROUNDTRIP, seed=SEED):
    """Decrypt a seeded subset of masked_fixedkey and confirm pt == decrypt(ct, key).

    Returns (ok, n_checked). If the trace file is missing, returns (None, 0).
    """
    try:
        from dlsca import dataset
        from dlsca.aes_ref import aes128_decrypt_block
    except Exception:  # noqa: BLE001
        return None, 0

    try:
        ts = dataset.load("masked_fixedkey")
    except Exception:  # noqa: BLE001 - missing trace file: report as unavailable
        return None, 0

    n = ts.traces.shape[0]
    rng = np.random.default_rng(seed)
    n_check = min(n_check, n)
    idx = rng.choice(n, size=n_check, replace=False)

    for i in idx:
        ct = np.asarray(ts.ciphertexts[i], dtype=np.uint8)
        key = np.asarray(ts.keys[i], dtype=np.uint8)
        pt = np.asarray(ts.plaintexts[i], dtype=np.uint8)
        recovered = np.asarray(aes128_decrypt_block(ct, key), dtype=np.uint8)
        if not np.array_equal(recovered, pt):
            return False, n_check
    return True, n_check


def build_verdict():
    """Assemble the combined correctness + safety verdict dict."""
    cpa_masked = _load_result("cpa_aes-masked.json")
    cnn_masked = _load_result("cnn_aes-masked.json")
    cpa_unprot = _load_result("cpa_aes-unprotected.json")
    cnn_unprot = _load_result("cnn_aes-unprotected.json")

    roundtrip_ok, n_checked = roundtrip_check()

    cpa_recovered = _key_recovered(cpa_masked)
    cnn_recovered = _key_recovered(cnn_masked)

    correctness_ok = roundtrip_ok is True
    safety_ok = (not cpa_recovered) and (not cnn_recovered)

    if correctness_ok and safety_ok:
        verdict = "PASS - data protected AND fully recoverable"
    elif not safety_ok:
        verdict = "FAIL - an attack recovered the masked key"
    elif roundtrip_ok is None:
        verdict = "INCOMPLETE - masked traces unavailable for roundtrip check"
    else:
        verdict = "FAIL - masked data did not decrypt back to plaintext"

    return {
        "correctness": {
            "roundtrip_ok": roundtrip_ok,
            "n_checked": n_checked,
        },
        "safety": {
            "cpa_recovered": cpa_recovered,
            "cnn_recovered": cnn_recovered,
            "cpa_traces_to_rank0": cpa_masked.get("traces_to_rank0"),
            "cnn_traces_to_rank0": cnn_masked.get("traces_to_rank0"),
        },
        # Sanity context: the same attacks DO break the unprotected target.
        "baseline_unprotected": {
            "cpa_recovered": _key_recovered(cpa_unprot),
            "cnn_recovered": _key_recovered(cnn_unprot),
            "cpa_traces_to_rank0": cpa_unprot.get("traces_to_rank0"),
            "cnn_traces_to_rank0": cnn_unprot.get("traces_to_rank0"),
        },
        "verdict": verdict,
    }


def main():
    verdict = build_verdict()
    out_path = os.path.join(RESULTS_DIR, "masking_verdict.json")
    with open(out_path, "w") as fh:
        json.dump(verdict, fh, indent=2)
        fh.write("\n")

    c = verdict["correctness"]
    s = verdict["safety"]
    b = verdict["baseline_unprotected"]
    print("US3 masking verdict")
    print("-------------------")
    print(
        f"correctness : roundtrip_ok={c['roundtrip_ok']} "
        f"(decrypted {c['n_checked']} masked ciphertexts)"
    )
    print(
        f"safety      : cpa_recovered={s['cpa_recovered']} "
        f"cnn_recovered={s['cnn_recovered']} "
        f"(cpa rank0={s['cpa_traces_to_rank0']}, cnn rank0={s['cnn_traces_to_rank0']})"
    )
    print(
        f"baseline    : unprotected cpa_recovered={b['cpa_recovered']} "
        f"(rank0={b['cpa_traces_to_rank0']}), "
        f"cnn_recovered={b['cnn_recovered']} (rank0={b['cnn_traces_to_rank0']})"
    )
    print(f"VERDICT     : {verdict['verdict']}")
    print(f"wrote {out_path}")
    return verdict


if __name__ == "__main__":
    main()
