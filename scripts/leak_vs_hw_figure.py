"""Real-data figure: average chip power at the leak moment vs Hamming weight of the secret.

Builds results/leak_vs_hammingweight.png from traces/unprotected_fixedkey.npz (no hardware).
The near-straight line is direct evidence that the chip power depends on the data it handles.
"""
import sys; sys.path.insert(0,'src')
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from dlsca import dataset
from dlsca.leakage import sbox, hamming_weight

plt.rcParams.update({"font.size": 14})
ts = dataset.load("unprotected_fixedkey")
tr = ts.traces.astype(np.float64)
key0 = int(ts.keys[0,0]); p0 = ts.plaintexts[:,0].astype(int)
v = sbox(p0 ^ key0); hw = hamming_weight(v).astype(int)      # real secret intermediate, byte 0

# find the leakiest sample: |corr(HW, power)| over time
hwc = hw - hw.mean()
trc = tr - tr.mean(0)
corr = (hwc @ trc) / (np.sqrt((hwc**2).sum()) * np.sqrt((trc**2).sum(0)) + 1e-12)
leak = int(np.argmax(np.abs(corr)))
col = tr[:, leak]

# mean power at the leak point, grouped by Hamming weight (real data)
groups = sorted(set(hw))
means = [col[hw==g].mean() for g in groups]
errs  = [col[hw==g].std()/np.sqrt((hw==g).sum()) for g in groups]

fig, ax = plt.subplots(figsize=(8,6))
ax.errorbar(groups, means, yerr=errs, fmt="o-", color="#c0392b", ms=8, lw=2, capsize=4)
ax.set_xlabel("number of 1-bits in the secret value (Hamming weight)")
ax.set_ylabel("average power at the leak moment")
ax.set_title("The leak is real: more 1-bits in the secret\nmeans more power (measured on the chip)")
ax.grid(alpha=0.25)
for s in ("top","right"): ax.spines[s].set_visible(False)
fig.tight_layout(); fig.savefig("results/leak_vs_hammingweight.png", dpi=140, bbox_inches="tight")
print("leaky sample =", leak, "| corr =", round(float(corr[leak]),3))
print("HW groups:", groups)
print("means:", [round(m,4) for m in means])
print("wrote results/leak_vs_hammingweight.png")
