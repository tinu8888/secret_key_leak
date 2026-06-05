"""Run CPA + CNN on the MASKED traces (no hardware). Failure to recover = defense works."""
import os, sys, time, json
import numpy as np
sys.path.insert(0, "src")
from dlsca import seeds, dataset, cpa, model, attack
from dlsca.leakage import intermediate, sbox

SEED = 0
seeds.set_all(SEED)
FIX = "masked_fixedkey"; RND = "masked_randomkey"
EPOCHS = 15

print("=== CPA on masked ===", flush=True)
ts = dataset.load(FIX)
rep = dataset.validate(ts, sample=500); assert rep["ok"], rep["errors"]
known = ts.keys[0]
print("known key:", bytes(known).hex(), flush=True)
cres = cpa.run(ts.traces, ts.plaintexts, known, firmware="aes-masked",
               dataset=FIX, n_orderings=10, seed=SEED, with_ge=True)
cres["n_attack_traces"] = int(ts.n_traces)
attack.save_result(cres)  # results/cpa_aes-masked.json
nb_ok = sum(cres["correct"])
print(f"CPA recovered key : {bytes(cres['recovered_key']).hex()}", flush=True)
print(f"CPA bytes rank-0  : {nb_ok}/16   traces_to_rank0={cres['traces_to_rank0']}", flush=True)
print(f"CPA final GE (last): {cres['ge_curve'][-1] if cres['ge_curve'] else 'n/a'}", flush=True)

print("\n=== CNN on masked (train randomkey, attack fixedkey) ===", flush=True)
prof = dataset.load(RND); atk = dataset.load(FIX)
for nm, t in [(RND, prof), (FIX, atk)]:
    r = dataset.validate(t, sample=500); assert r["ok"], (nm, r["errors"])
kk = atk.keys[0].astype(int); N = atk.n_traces

# POI per byte via SNR on profiling set (same recipe as the unprotected notebook).
POI_HALF = 40
ptr = prof.traces.astype(np.float64); gvar = ptr.var(axis=0)
def byte_snr(b):
    lab = intermediate(prof.plaintexts, prof.keys, b)
    means = np.zeros((256, ptr.shape[1]))
    for c in range(256):
        m = lab == c
        if m.any(): means[c] = ptr[m].mean(axis=0)
    sig = np.var(means, axis=0)
    noise = np.where(gvar - sig <= 0, 1e-9, gvar - sig)
    return sig / noise
poi = {}
for b in range(16):
    pk = int(np.argmax(byte_snr(b)))
    poi[b] = (max(0, pk-POI_HALF), min(ptr.shape[1], pk+POI_HALF))

cand = np.arange(256)
pts_scores = np.zeros((16, N, 256)); scores = np.zeros((16, 256))
t0 = time.time()
for b in range(16):
    s, e = poi[b]
    labels = intermediate(prof.plaintexts, prof.keys, b)
    net = model.build(e - s)
    card = model.train(net, prof.traces, labels, (s, e), seed=SEED,
                       name=f"cnn_masked_byte{b}", target_byte=b,
                       label_model="identity-256", train_set=RND, epochs=EPOCHS,
                       batch_size=128, val_frac=0.1)
    logp = model.predict_log_proba(net, atk.traces, card)
    pb = atk.plaintexts[:, b].astype(int)
    hyp = sbox(pb[:, None] ^ cand[None, :])
    pts_scores[b] = logp[np.arange(N)[:, None], hyp]
    scores[b] = pts_scores[b].sum(axis=0)
    rb = attack.key_rank(scores, kk)[b]
    print(f"byte {b:2d} POI={poi[b]} val_acc={card['val_accuracy']:.3f} rank={rb} [{time.time()-t0:.0f}s]", flush=True)

nres = attack.run(scores, kk, method="cnn", firmware="aes-masked",
                  label_model="identity-256", dataset=FIX,
                  per_trace_scores=pts_scores, n_orderings=10, seed=SEED)
attack.save_result(nres)  # results/cnn_aes-masked.json
print(f"\nCNN recovered key : {bytes(nres['recovered_key']).hex()}", flush=True)
print(f"CNN bytes rank-0  : {sum(nres['correct'])}/16   traces_to_rank0={nres['traces_to_rank0']}", flush=True)
print(f"CNN final GE (last): {nres['ge_curve'][-1] if nres['ge_curve'] else 'n/a'}", flush=True)
print("\nATTACK DONE", flush=True)
