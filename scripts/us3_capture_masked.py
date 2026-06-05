import sys, time, platform
import numpy as np
sys.path.insert(0, "src")
from dlsca import seeds, capture, dataset

REF = "notes/approvals.md#2026-06-02-capture-masked"
FW_HASH = "sha256:9e6090554f31faf2e51611dfd20efd8fd1d33aacef4672c6e5717dd69cf40927"
SEED = 0
N_FIXED = 5000
N_RANDOM = 5000
FIXED_KEY = np.arange(16, dtype=np.uint8)

seeds.set_all(SEED)
import chipwhisperer as cw
base = {
    "firmware": "aes-masked",
    "firmware_hash": FW_HASH,
    "board": "ChipWhisperer-Nano (CWNANO)",
    "target": "STM32F0 (STM32F0_NANO, built-in)",
    "host_arch": platform.machine(),
    "scope": {"sample_rate": 7500000, "samples": 5000, "gain": None,
              "adc_clock": "7.5MHz", "trigger": "tio/simpleserial"},
    "cw_version": cw.__version__,
}

print("== connect ==", flush=True)
scope, target = capture.connect(approved=True, approval_ref=REF)
try:
    try:
        scope.io.nrst = "low"; time.sleep(0.1); scope.io.nrst = "high"; time.sleep(0.25)
        target.flush()
    except Exception as e: print("reset note:", e, flush=True)

    t0 = time.time()
    print(f"== fixed-key campaign N={N_FIXED} ==", flush=True)
    fixed = capture.campaign(scope, target, role="fixed-key", n=N_FIXED,
                             base_manifest=base, key_mode="fixed", fixed_key=FIXED_KEY,
                             seed=SEED, approved=True, approval_ref=REF)
    dataset.save("masked_fixedkey", fixed.traces, fixed.plaintexts, fixed.keys,
                 fixed.ciphertexts, fixed.manifest, overwrite=True)
    print("  fixed saved; validate:", dataset.validate(fixed, sample=500),
          f"({time.time()-t0:.0f}s)", flush=True)

    t1 = time.time()
    print(f"== random-key campaign N={N_RANDOM} ==", flush=True)
    rand = capture.campaign(scope, target, role="random-key", n=N_RANDOM,
                            base_manifest=base, key_mode="random", seed=SEED + 1,
                            approved=True, approval_ref=REF)
    dataset.save("masked_randomkey", rand.traces, rand.plaintexts, rand.keys,
                 rand.ciphertexts, rand.manifest, overwrite=True)
    print("  random saved; validate:", dataset.validate(rand, sample=500),
          f"({time.time()-t1:.0f}s)", flush=True)
    print("CAPTURE DONE", flush=True)
finally:
    try: scope.dis(); target.dis(); print("== disconnected ==", flush=True)
    except Exception: pass
