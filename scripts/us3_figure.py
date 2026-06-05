"""US3 before/after figure: GE vs #traces, unprotected (attack works) vs masked (defense holds)."""
import json, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def load(p):
    try:
        with open(p) as f: return json.load(f)
    except FileNotFoundError:
        return None

up_cpa = load("results/cpa_aes-unprotected.json")
up_cnn = load("results/cnn_aes-unprotected.json")
m_cpa  = load("results/cpa_aes-masked.json")
m_cnn  = load("results/cnn_aes-masked.json")

fig, (axL, axR) = plt.subplots(1, 2, figsize=(13, 4.5), sharey=True)

def plot_ge(ax, res, label, color, counts_key="ge_trace_counts"):
    if not res or not res.get("ge_curve"): return
    ge = res["ge_curve"]
    x = res.get(counts_key) or list(range(1, len(ge) + 1))
    ax.plot(x, ge, label=label, color=color, lw=1.6)

# Left: unprotected (the attack succeeds -> GE falls to 0)
plot_ge(axL, up_cpa, f"CPA (t2r0={up_cpa['traces_to_rank0'] if up_cpa else '?'})", "C0")
plot_ge(axL, up_cnn, f"CNN (t2r0={up_cnn['traces_to_rank0'] if up_cnn else '?'})", "C1")
axL.axhline(0, color="C2", ls="--", lw=0.8)
axL.set_title("Unprotected AES - attack SUCCEEDS\n(key rank falls to 0)")
axL.set_xlabel("#traces"); axL.set_ylabel("mean key rank (0 = recovered)")
axL.legend()

# Right: masked (the defense holds -> GE stays high, never 0)
plot_ge(axR, m_cpa, f"CPA (t2r0={m_cpa['traces_to_rank0'] if m_cpa else '?'})", "C0")
plot_ge(axR, m_cnn, f"CNN (t2r0={m_cnn['traces_to_rank0'] if m_cnn else '?'})", "C1")
axR.axhline(0, color="C2", ls="--", lw=0.8)
axR.set_title("First-order masked AES - attack FAILS\n(key rank stays high)")
axR.set_xlabel("#traces"); axR.legend()

fig.suptitle("US3: first-order masking defeats the first-order attacks (CW-Nano, STM32F0)", fontsize=12)
fig.tight_layout(rect=[0, 0, 1, 0.96])
fig.savefig("results/us3_defense_ge.png", dpi=120)
print("wrote results/us3_defense_ge.png")

# Console summary table
print("\n| method | unprotected t2r0 | masked t2r0 | masked bytes rank-0 |")
print("|--------|------------------|-------------|---------------------|")
for nm, up, m in [("CPA", up_cpa, m_cpa), ("CNN", up_cnn, m_cnn)]:
    upt = up["traces_to_rank0"] if up else "?"
    mt  = m["traces_to_rank0"] if m else "?"
    mb  = sum(m["correct"]) if m else "?"
    print(f"| {nm} | {upt} | {mt} | {mb}/16 |")
