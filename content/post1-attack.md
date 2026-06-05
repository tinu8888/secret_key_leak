# Reading a chip's secret key out of its power supply (Part 1: the attack)

*A side-channel project on hardware I own, for learning and defense. Part 1 is the attack;
[Part 2](post2-defense.md) is the masking countermeasure that's meant to stop it.*

---

## The short version (LinkedIn)

I pulled a secret AES-128 key out of a microcontroller without ever reading the key from
memory. I only watched how much power the chip drew while it encrypted.

Two attacks, same target, same captured traces:

- **Classical control (CPA):** recovered all 16 key bytes from about **100 power traces**.
- **Neural network (DLSCA):** recovered the same key from about **12 traces**, roughly
  **8× fewer**.

The key on the chip was `000102030405060708090a0b0c0d0e0f`. Both attacks returned exactly
that, byte for byte. I never told either attack the key; it came out of the power
measurements.

This is the whole point of side-channel analysis: a cipher can be mathematically sound and
still leak the key through a physical channel the math doesn't model. Part 2 is the defense
(masking), which is the reason I built the attack in the first place.

Target: a ChipWhisperer-Nano with its onboard STM32F0, running the unprotected
`simpleserial-aes` example. My board, my test key, isolated on a bench. This is not a
how-to against anyone's product.

Built on the shoulders of the ChipWhisperer SCA101/SCA201 tutorials and the deep-learning
side-channel literature (ASCAD-style profiling CNNs). Details, code, and every figure are in
the repo.

---

## The longer version (what actually leaks, and why)

### Why power tells you anything

A CMOS chip burns power when its transistors switch. Flipping a bit from 0 to 1 (or back)
costs energy, and that cost shows up as a tiny wiggle on the supply line. So the
instantaneous power draw depends, in part, on the *data* the chip is moving around at that
instant. If the data depends on a secret, the power does too. That's the side channel.

AES makes this exploitable because of how it starts. The first thing it does to each byte is
XOR it with a key byte, then push the result through a fixed 256-entry lookup table called
the S-box:

```
intermediate = Sbox(plaintext_byte XOR key_byte)
```

We always know the plaintext. So if we *guess* a key byte, we can compute what that
intermediate value would be, and predict how much power handling it should cost. The guess
that predicts the measured power best is the right key byte. Do that for all 16 bytes and you
have the key.

That's the idea both attacks share. They differ in how they turn "predict the power" into a
decision.

### Step 0: prove the leak is real before trusting anything fancy

Before any neural network, I ran a classical attack as a control. The project has a rule for
this ("measure, don't claim"): a well-understood method has to
demonstrate the leak first, so a flashier result later is believable rather than
self-deception.

Two sanity checks came first:

- The firmware was verified against the published AES test vector
  (`AES(00112233..eeff)` under key `000102..0e0f` = `69c4e0d8..b4c55a`) before a single trace
  was captured. So the target was definitely computing real AES.
- A raw capture confirmed the leak window. `results/bringup_trace.png` is an idle trace;
  `results/aes_unprotected_trace.png` is a trigger-aligned trace with the encryption visible.
  `results/snr_unprotected.png` shows the signal-to-noise ratio spiking right around the
  first round, which is exactly where the S-box leakage should sit.

### The classical attack: Correlation Power Analysis (CPA)

CPA models the power for each key guess with the **Hamming weight** of the S-box output: the
number of 1-bits in that byte. More 1s moving across a bus, more power. It's crude, and it
works, because the leakage is roughly linear in the number of bits.

Then it correlates that model against the measured power, sample by sample, across all
traces. For a wrong key guess the model is just noise against the real power and the
correlation stays low. For the right guess the model lines up with physics and the
correlation spikes. `results/cpa_corr_peak.png` shows it cleanly: the correct key candidate's
correlation curve stands well above the cloud of the 255 wrong guesses. That gap is the leak,
made visible.

The metric isn't a single number from one trace; it's **guessing entropy vs number of
traces**, the mean rank of the correct key across many random orderings of the trace set, as
you feed in more traces. Rank 0 means the correct key sits at the top of the candidate list.
`results/cpa_ge_curve.png` shows that rank dropping to 0. It got there by **100 traces**
(`traces_to_rank0 = 100` in `results/cpa_aes-unprotected.json`). The unprotected target leaks
hard.

### The learned attack: a profiling CNN (DLSCA)

CPA assumes the leakage looks like Hamming weight. That assumption is doing a lot of work, and
it's only approximately true. A profiling attack throws the assumption out and *learns* the
leakage from data instead.

The setup is the standard profiling split:

- **Profiling set:** traces captured with random keys, where I know everything. This is the
  training data.
- **Attack set:** the fixed-key traces, where the key is what I'm trying to recover.

I trained a small per-byte CNN with the **identity / 256-class** model: instead of collapsing
the S-box output to its Hamming weight (9 buckets), the network predicts which of the 256
possible S-box output values produced each trace. `results/cnn_snr_poi.png` shows the
points of interest the model keys on, per byte. At attack time, each byte's network turns a
trace into a probability over 256 values; those get folded back to a probability over the 256
key-byte guesses, and the log-likelihoods accumulate across traces (standard maximum-
likelihood key ranking).

Result: the full key, recovered by **12 traces** (`traces_to_rank0 = 12` in
`results/cnn_aes-unprotected.json`). `results/cnn_ge_curve.png` shows the guessing-entropy
curve falling to 0 far earlier than CPA's. Side by side, `results/cpa_vs_cnn_ge.png` overlays
both: ~12 traces for the CNN against ~100 for CPA, about an 8× reduction in the trace budget.

### One honest caveat about the CNN

If you look at the per-byte classifier's validation accuracy, it's low: roughly **3 to 7%** on a
256-class problem (from ~5k profiling traces). That sounds like a broken model, and on a
pure classification framing it would be. But classification accuracy is the wrong yardstick
here. The attack doesn't need to be confident about a single trace; it aggregates the *full
probability distribution* over many traces, and small, consistent biases toward the right
answer compound. The metric that matters is guessing entropy, not top-1 accuracy, and by
that metric the model is decisively better than CPA. Worth stating plainly so nobody reads
"7% accuracy" and "recovers the key in 12 traces" as a contradiction.

### Why the learned model wins

CPA is locked into one fixed power model (Hamming weight) and one combining rule
(correlation). The CNN learns the actual shape of this chip's leakage from the profiling set,
including parts a Hamming-weight model throws away, and it can lean on multiple sample points
at once. It uses more of the available signal and wastes less of it on a wrong assumption, so
it needs fewer traces to reach the same certainty. This matches what the DLSCA literature reports: learned models tend
to beat classical templates on the same data, especially as leakage gets messier. Here it's
8× on a clean, unprotected target. The gap usually grows on harder targets, which is part of
why the defense in Part 2 is interesting.

### It's reproducible

Both attacks re-run from the saved `.npz` traces with a fixed seed (`seed = 0`) and return the
identical key and identical trace counts. No hardware needed for the analysis step. That's a
project requirement, and it's also what lets anyone check the claims above rather
than take my word.

For the full CPA walkthrough (setup, how to run it, what to expect, how it was built), see
[`docs/US1_AES_KEY_RECOVERY.md`](../docs/US1_AES_KEY_RECOVERY.md).

### What's next: the defense

An attack-only writeup would miss the point. The reason to understand leakage this precisely
is to stop it. Part 2 covers **first-order Boolean masking**: split each sensitive
intermediate into randomized shares so that no single point in the trace correlates with the
secret, which is exactly the link both of these attacks depend on. I re-ran this same CPA and
CNN against a masked target on the same board, and both fail to reach rank 0 even at 5000
traces. The measured before/after is in [Part 2](post2-defense.md).

---

## Credits and scope

- **Prior work:** the ChipWhisperer SCA101 and SCA201 Jupyter tutorials (which ship with the
  kit) and the deep-learning side-channel analysis literature, including ASCAD-style profiling
  CNNs, are the foundation this builds on.
- **Scope:** every measurement here is on hardware I own, using a self-generated test key, on
  an isolated bench. This is education and defense, not a weaponized procedure against any
  deployed device. Every step that touched hardware (flashing, USB, capture) was explicitly
  approved and logged in [`notes/approvals.md`](../notes/approvals.md).

---

## Traceability

Every public claim and figure above maps to a repo artifact.
The generating notebooks are `notebooks/02_cpa_baseline.ipynb` (CPA) and
`notebooks/03_cnn_dlsca.ipynb` (CNN); the comparison figure is generated by the docs step
(`results/cpa_vs_cnn_ge.png`).

| Claim / figure in this post | Backing artifact |
|---|---|
| Target = CW-Nano + onboard STM32F0, unprotected `simpleserial-aes` (TINYAES128C) | `notes/hardware.md`, `notes/setup-verified.md` |
| Firmware verified vs FIPS-197 vector `69c4e0d8..b4c55a` before capture | `notes/setup-verified.md`, `docs/US1_AES_KEY_RECOVERY.md` §4 |
| Known key on chip = `000102..0e0f` | `known_key` in `results/cpa_aes-unprotected.json` and `results/cnn_aes-unprotected.json` |
| Idle vs trigger-aligned AES trace | `results/bringup_trace.png`, `results/aes_unprotected_trace.png` |
| Leakage spikes around round 1 (SNR) | `results/snr_unprotected.png` (`notebooks/02_cpa_baseline.ipynb`) |
| CPA correct key candidate towers over 255 wrong guesses | `results/cpa_corr_peak.png` (`notebooks/02_cpa_baseline.ipynb`) |
| CPA recovers full key, `traces_to_rank0 = 100` | `results/cpa_aes-unprotected.json` (`recovered_key`, `correct`, `traces_to_rank0`); `results/cpa_ge_curve.png` |
| CPA leakage model = Hamming weight of S-box output | `label_model: "hamming-weight"` in `results/cpa_aes-unprotected.json` |
| CNN model = identity / 256-class, profiling split | `label_model: "identity-256"`, `method: "cnn"` in `results/cnn_aes-unprotected.json`; `notebooks/03_cnn_dlsca.ipynb` |
| Per-byte points of interest | `results/cnn_snr_poi.png` (`notebooks/03_cnn_dlsca.ipynb`) |
| CNN recovers full key, `traces_to_rank0 = 12` | `results/cnn_aes-unprotected.json` (`recovered_key`, `correct`, `traces_to_rank0`); `results/cnn_ge_curve.png` |
| Per-byte CNN validation accuracy ~3 to 7% on 256 classes | `val_accuracy` printed per byte in `notebooks/03_cnn_dlsca.ipynb` |
| ~8× fewer traces (12 vs 100), side by side | `results/cpa_vs_cnn_ge.png` (derived from both result JSONs) |
| Reproducible from saved traces, fixed seed | `seed: 0` in both result JSONs; `docs/US1_AES_KEY_RECOVERY.md` §9d |
| Trained on Apple-Silicon MPS | `notes/hardware.md` (compute device = mps) |
