# Breaking the link the attack relies on (Part 2: the defense)

*Companion to [Part 1: the attack](post1-attack.md). Part 1 pulled an AES-128 key out of a
chip's power consumption two ways. Part 2 puts a first-order masking countermeasure on the same
chip and shows both attacks stop working. This is a measured result, not a plan: the numbers
and figure come from real captures on the board.*

---

## Result, up front

Part 1 recovered the key with CPA in ~100 traces and a CNN in ~12. Part 2 flashed a masked AES
onto the same ChipWhisperer-Nano and re-ran the exact same attacks:

| Attack | Unprotected (Part 1) | First-order masked (Part 2) |
|--------|----------------------|-----------------------------|
| CPA    | full key at ~100 traces | not recovered at 5000 traces |
| CNN/DLSCA | full key at ~12 traces | not recovered at 5000 traces |

With masking, the mean key rank never falls toward 0; it sits around 100 (out of 255) across
the whole 5000-trace budget, and the CNN's class accuracy stays at chance (about 1 in 256), so
the network learns nothing from the masked leakage. The spec's bar was "neither attack reaches
rank 0 within 10x the unprotected trace budget"; 5000 traces is roughly 50x the CPA budget and
400x the CNN budget, and both still fail. The before/after is in
[`results/us3_defense_ge.png`](../results/us3_defense_ge.png), with raw numbers in
[`results/cpa_aes-masked.json`](../results/cpa_aes-masked.json) and
[`results/cnn_aes-masked.json`](../results/cnn_aes-masked.json).

---

## What the attacks depend on

Both attacks in Part 1 lean on one fact: a single, predictable intermediate value
(`Sbox(plaintext XOR key)`) is present in the chip's data, and that value leaks into the power
at a predictable place in the trace.

- CPA correlates a model of *that one value* against the power.
- The CNN learns the leakage of *that one value* from profiling traces.

Cut that link and both attacks lose their footing. That is what masking does.

## How masking breaks it

First-order Boolean masking never lets the sensitive value exist in the clear. Each
intermediate `v` is split into two shares with a fresh random mask `m`:

```
v  =  (v XOR m)  XOR  m
       \______/        \_/
       masked value    mask
```

The chip computes on `(v XOR m)` and `m` separately and only recombines at the very end. The
random mask `m` is fresh per execution. So at any single point in the trace, what leaks is
either `v XOR m` or `m`, and on its own neither tells you anything about `v`, because `m` is
uniformly random. The intermediate value the attacks key on is never present at any single
moment for a first-order attack to grab. That is exactly what the right-hand panel of the
figure shows: the correlation peak and the learned signal that gave away the key in Part 1 are
simply not there anymore.

The standard caveat, stated honestly: masking raises the bar, it does not make the device
magic. A *higher-order* attack that combines two points (the masked value and the mask
together) can in principle defeat first-order masking, at the cost of far more traces and a
more careful capture. What this project demonstrates is the clean first-order before/after:
first-order masking defeats the first-order attacks from Part 1.

## The hardware twist (and an honest correction)

The original plan was to flash the ChipWhisperer kit's own masked AES. It does not build for
this board. The kit's masked implementations (ANSSI / RIOUBSAES / KNARFRANK) target Cortex-M4
(STM32F3/F4) or AVR, and the CW-Nano's onboard chip is an STM32F0, which is Cortex-M0. Building
for the Nano fails outright:

```
crypto/Makefile.maskedaes:81: *** Unsupported implementation for masked AES crypto: AES128C.
crypto/Makefile.maskedaes:62: *** Unsupported platform/hal for ANSSI masked AES crypto.
```

I had initially assumed this would be a one-line variant build; it was not, and I corrected
that in the notes rather than paper over it. The block, though, is specific to the kit's
hand-optimized M4/AVR assembly. Masking itself is just an algorithm, and plain C runs fine on a
Cortex-M0. So instead of buying new hardware, I wrote an own first-order Boolean-masked AES-128
in portable C for the M0 (the scheme, the fit numbers, and the limits are in
[`firmware/aes-masked/`](../firmware/aes-masked/)).

It carries every state byte as `(data XOR mask)` with the mask tracked through the linear
layers, uses a per-encryption recomputed masked S-box, and draws masks from a software
xorshift PRNG (the STM32F0 has no hardware RNG, an honest limitation noted in the firmware).
It is functionally exact (it reproduces the FIPS-197 ciphertext across 100,000 random mask
seeds) and small (ROM 17.9%, RAM 45.7% on the Nano, comparable to the unprotected AES). On
silicon it encrypts correctly (a known key/plaintext returns the right ciphertext), and then,
as the table above shows, it defeats both attacks.

## Why the comparison is clean

Everything is held identical except the leakage. The masked firmware speaks the same
simpleserial command/response and raises the same trigger as the unprotected build, so the
Part 1 attack code re-runs completely unchanged: same CPA, same CNN architecture, same
profiling/attack split, same guessing-entropy and `traces_to_rank0` metrics. The only thing
that changed is what the chip leaks. Capture and attack are reproducible from
[`scripts/`](../scripts/) (capture is approval-gated; the attacks run on saved traces with no
hardware).

## Honest bottom line

Part 1 showed how little it takes to read a key out of power. Part 2 shows that one well-placed
countermeasure, first-order masking, flattens exactly the signal both attacks relied on: the
key that fell in 12 to 100 traces is not recovered in 5000. The result is measured on the same
board, with the same code, and the win held even after the kit's masked AES turned out not to
build for this chip, because writing a portable one for the Cortex-M0 was the better answer
than waiting on different hardware.

---

## Scope and credits

Same as Part 1: own hardware, self-generated test key, isolated bench, education and defense.
The masking approach and the profiling-attack framing follow the ChipWhisperer SCA101/SCA201
tutorials and the DLSCA literature. Every hardware step remains approval-gated and logged in
[`notes/approvals.md`](../notes/approvals.md).
