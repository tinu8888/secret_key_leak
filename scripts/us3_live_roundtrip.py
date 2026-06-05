"""Live masked encrypt on the CW-Nano, then decrypt on the host: data must come back intact.

HARDWARE + APPROVAL GATE: this drives the board. Run it only with the masked
firmware flashed and a human approval logged in notes/approvals.md. It captures a handful of
fresh masked encryptions, confirms each on-chip ciphertext is correct AES, and decrypts each on
the host to confirm the original plaintext comes back.

Usage:  ./.venv/bin/python scripts/us3_live_roundtrip.py [N]   (default N=16)
"""
import sys
import time

import numpy as np

sys.path.insert(0, "src")
from dlsca import capture  # noqa: E402
from dlsca.aes_ref import aes128_decrypt_block  # noqa: E402
from dlsca.dataset import aes128_encrypt_block  # noqa: E402

APPROVAL_REF = "notes/approvals.md#2026-06-04-live-roundtrip-masked"
KEY = np.frombuffer(bytes(range(16)), dtype=np.uint8)  # 000102...0f


def main(n: int = 16) -> int:
    rng = np.random.default_rng(7)
    print("== connect (claims USB; gated) ==", flush=True)
    scope, target = capture.connect(approved=True, approval_ref=APPROVAL_REF)
    ok_ct = ok_rt = 0
    try:
        try:
            scope.io.nrst = "low"; time.sleep(0.1)
            scope.io.nrst = "high"; time.sleep(0.25)
            target.flush()
        except Exception as e:  # noqa: BLE001
            print("reset note:", e, flush=True)

        print(f"== {n} live masked encryptions, decrypt each on the host ==", flush=True)
        for i in range(n):
            pt = rng.integers(0, 256, 16, dtype=np.uint8)
            _, ct = capture.capture_trace(scope, target, KEY, pt)  # verifies ct==AES inline
            ct = np.asarray(ct, dtype=np.uint8)
            if np.array_equal(ct, aes128_encrypt_block(pt, KEY)):
                ok_ct += 1
            back = aes128_decrypt_block(ct, KEY)
            if np.array_equal(back, pt):
                ok_rt += 1
            if i < 3:
                print(f"  pt={bytes(pt.tolist()).hex()} ct={bytes(ct.tolist()).hex()} "
                      f"decrypt_ok={np.array_equal(back, pt)}", flush=True)

        print(f"\non-chip ciphertext correct : {ok_ct}/{n}", flush=True)
        print(f"host decrypt recovers data : {ok_rt}/{n}", flush=True)
        ok = ok_ct == n == ok_rt
        print("RESULT:", "PASS - masked chip output decrypts back to the original data"
              if ok else "FAIL", flush=True)
        return 0 if ok else 2
    finally:
        try:
            scope.dis(); target.dis()
            print("== disconnected ==", flush=True)
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    raise SystemExit(main(n))
