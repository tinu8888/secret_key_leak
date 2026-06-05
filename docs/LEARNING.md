# A beginner's guide to this project

New to side-channel attacks, hardware, or machine learning? Start here. This is a plain
language, step by step walkthrough of what the project does and how it works, written for
someone seeing all of this for the first time. No prior security or ML background needed.

Read it top to bottom, or jump to a lesson. Each lesson builds on the one before it.

If you want the hands-on "how to run it" version after this, see
[`docs/US1_AES_KEY_RECOVERY.md`](US1_AES_KEY_RECOVERY.md).

## The lesson plan

1. The big idea: what a side-channel attack is
2. The players: the hardware, and what AES and a "key" mean
3. The measurement: what a power trace is and how we captured thousands
4. Attack #1, CPA: the classic statistics method that found the key
5. Attack #2, the CNN: how the neural network did it with fewer traces
6. The defense: masking, and why it could not run on our chip
7. The project itself: how the code, safety rules, and workflow fit together
8. Doing it yourself: running and reproducing the result

(Lessons are added here as we go through them together.)

---

## Lesson 1: The big idea

Normally, people who try to break encryption attack the **math**. AES (the encryption our
chip uses) has math so strong that guessing the key directly would take longer than the age
of the universe. So we did not attack the math at all. We did something sneakier.

**The core idea: a working chip leaks physical clues about what it is doing.**

A few everyday "side channels" to build the intuition:

- You can sometimes guess a safe's combination by listening to the clicks, without
  understanding the lock mechanism.
- You could tell which keypad buttons were just pressed by feeling which ones are warm.
- You can tell someone is home because the lights are on, without seeing them.

In each case you are not breaking the thing directly. You are watching a physical "tell"
that leaks information as a side effect. That leak is the **side channel**.

**Our side channel was electricity (power).**

When a computer chip does a calculation, it draws tiny amounts of electrical power. Here is
the key fact that makes the whole project work:

> The exact amount of power the chip uses depends on the actual data it is processing at
> that instant.

Processing a byte that is `00000000` uses a slightly different amount of power than
processing `11111111`. The difference is tiny, far too small to see by eye, but it is real
and measurable with the right equipment.

So while our chip was busy encrypting with its secret key, it was unknowingly "whispering"
hints about that key through its power consumption. Our whole job was to measure those power
whispers carefully and work backwards to the secret key, without ever being told the key.

The field has a name: **side-channel analysis**. When you use deep learning to do it, it is
called **DLSCA** (Deep-Learning Side-Channel Analysis). That is where the project name comes
from.

**Why this is defensive, not evil:** this is exactly how real attackers can steal keys from
smart cards, payment chips, and small connected devices. By doing it on our own chip, we
learn how the leak works so we can understand how to defend against it. That is why the plan
always included a Part 2 defense.

The one thing to remember from this lesson: the chip's power usage secretly depends on its
data, and we exploited that to recover the key.

---

## Lesson 2: The players

Now meet the actual things involved: the hardware on the desk, and what AES and the "key"
really are.

### The hardware

We used a **ChipWhisperer-Nano**. It is a small board built for exactly this kind of
learning and research. Think of it as two tools in one:

1. **A very precise power meter.** It samples the target chip's power use millions of times
   per second. A normal multimeter is far too slow and crude for this. The ChipWhisperer is
   like a stethoscope tuned to hear the chip's faint electrical "heartbeat."
2. **A chip programmer and conductor.** It can load our program onto the target chip, send
   it data to encrypt, and, crucially, start each power recording at the exact right moment
   so all the recordings line up.

On this particular board, the **target chip is built in**: a small **STM32F0**
microcontroller sitting right next to the measuring circuitry. (On bigger ChipWhisperer
kits the target is a separate plug-in board, but the idea is the same.) The exact board and
chip we used are recorded in [`notes/hardware.md`](../notes/hardware.md).

A **microcontroller** is a tiny, simple computer on a single chip, the kind found inside
appliances, toys, and sensors. We attack a microcontroller rather than a laptop because it
is simple and predictable: it does one thing at a time, so its power signal is clean and
easy to read. A laptop runs thousands of things at once, which would bury the signal in
noise.

### What AES is

**AES** is the worldwide standard recipe for scrambling data so others cannot read it. It is
**symmetric**, meaning the same secret key both locks (encrypts) and unlocks (decrypts) the
data. We used **AES-128**, where the key is 128 bits long. 128 bits is 16 bytes, so the key
is just 16 numbers, each from 0 to 255.

The three pieces of an encryption are:

- **Plaintext:** the input data (16 bytes for AES). We choose this.
- **Key:** the 16-byte secret. This is what we want to steal.
- **Ciphertext:** the scrambled output (16 bytes). The chip gives this back to us.

```text
   plaintext  +  key   --[ AES on the chip ]-->  ciphertext
  (we choose)  (secret)                           (we receive)
```

Here is the important asymmetry that makes the attack possible to *check*: in our setup we
know the plaintext (we send it) and the ciphertext (we read it back), but the attack is
**not allowed to use the key**. The attack tries to recover the key from power alone. Since
it is our own chip, we happen to know the real key, so we can confirm the attack got it
right. On a real target you would not have that luxury, but the method is identical.

### The one spot we attack: the S-box

AES does its scrambling in several rounds of small steps. One early step matters most for
us. For each byte, AES:

1. combines a plaintext byte with a key byte (a simple XOR, a kind of binary mixing), then
2. feeds the result through a fixed lookup table called the **S-box** (substitution box).

The S-box is just a fixed table: put a byte in, get a scrambled byte out, always the same
mapping. We attack the moment the chip computes and stores that S-box output, because:

- it depends on exactly one key byte and one (known) plaintext byte, and
- the chip's power use at that instant depends on that output value.

That combination is the leak we exploit. We attack one key byte at a time, repeat for all
16, and we have the full key. Exactly how we turn the power measurements into the key is
Lessons 4 and 5.

The AES program we actually flashed onto the chip lives in
[`firmware/aes-unprotected/`](../firmware/aes-unprotected/). "Unprotected" means it has no
defenses yet, which is the point: it is the easy target we attack first.

### A worked example with real numbers

Here is the real, whole-block encryption our chip actually performed (genuine project
values):

```text
KEY  (secret, 16 bytes):   00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
DATA (plaintext we sent):  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
                                    |  AES runs on the chip
                                    v
CIPHERTEXT (chip returns): 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
```

We send the data, the chip mixes it with its secret key, and returns the scrambled
ciphertext. The attacker's job is to recover the key from power, never having been shown it.

Now zoom into a single byte to see the leak. (Our real key's first byte is `0x00`, which
makes the XOR a no-op, so for teaching we use a livelier pair of bytes.)

**Step 1: combine one plaintext byte with one key byte using XOR.** XOR compares bit by bit.
The result bit is 1 if the two bits differ, 0 if they are the same.

```text
 plaintext byte p = 0x6A = 0 1 1 0 1 0 1 0
 key byte       k = 0x2B = 0 0 1 0 1 0 1 1   (the secret)
 ------------------------------- XOR --------
 result           = 0x41 = 0 1 0 0 0 0 0 1
```

**Step 2: push that result through the S-box lookup table** (a fixed table, same for
everyone). Looking up 0x41 gives:

```text
 S-box[0x41] = 0x83 = 1 0 0 0 0 0 1 1
```

**Step 3: the leak.** When the chip stores that value, its power use tracks the value's
**Hamming weight**, which is just the number of 1-bits:

```text
 0x83 = 1 0 0 0 0 0 1 1  ->  three 1s  ->  Hamming weight = 3
```

So with secret key byte 0x2B and plaintext 0x6A, the chip leaks a faint "power is about 3
units" signal at that instant. That 3 is the breadcrumb.

**How the attacker uses it.** The attacker knows the plaintext (0x6A) and measures the
power, but does not know k. So they try all 256 possible key bytes and see which guess's
prediction matches the measured power. For this one plaintext:

| Key guess k | 0x6A XOR k | S-box output | predicted Hamming weight |
|---|---|---|---|
| 0x00 (wrong) | 0x6A | 0x02 = 00000010 | 1 |
| **0x2B (correct)** | 0x41 | 0x83 = 10000011 | **3** |
| 0x6A (wrong) | 0x00 | 0x63 = 01100011 | 4 |

The catch, and the reason we need thousands of traces: with a single measurement you cannot
tell the right guess from a lucky wrong one (the predictions are just 1, 3, 4, nothing
obviously wins). The signal appears over many different plaintexts:

- For the **correct** key guess, the predicted Hamming weights line up with the measured
  power consistently, across thousands of traces.
- For every **wrong** guess, the predictions match only by luck sometimes and miss other
  times, so they average out to noise.

You collect a few thousand traces, and for each of the 256 guesses you measure how well its
predictions track the real power across all of them. One guess scores far higher than the
rest. That is the key byte. Repeat for all 16 bytes and you have the whole key. The "how
well do they track each other" measurement is called **correlation**, which is exactly what
CPA computes (Lesson 4). On our chip the correct guess stood out after only about 100
traces.

The one thing to remember from this lesson: the chip runs standard AES, and we target the
exact step where one key byte meets one known plaintext byte inside the S-box, because that
is where the power leak points straight at the key.

---

## Lesson 3: the measurement (power traces, and capturing thousands)

Lessons 1 and 2 said the chip leaks through its power. Now we see what that leak looks like
and how we recorded enough of it to attack.

### What a single power trace is

A power trace is just a list of numbers: the chip's power level measured at many tiny moments
in time, one after another. On our ChipWhisperer-Nano we recorded **5,000 measurements per
trace**, taken **7.5 million times per second**. So one trace captures less than a
millisecond of the chip's life, sliced into 5,000 time-steps.

Plotted, it is a wiggly line. That is `results/aes_unprotected_trace.png`:

```text
power
  ^        AES is running here
  |    /\    /\    /\    /\        (the bumps are the chip doing
  |   /  \  /  \  /  \  /  \        each round of AES, one after
  |__/    \/    \/    \/    \____   another)
  +------------------------------------> time
   0      1000    2000   3000   4000   (sample number, 0 to 4999)
```

The x-axis is time as sample number 0 to 4999. The y-axis is how much power the chip used at
that instant. The repeating bumps are the chip working through AES. Somewhere in there is the
exact moment it computes the S-box value for byte 0 (the leak from Lesson 2).

We also captured an idle trace (`results/bringup_trace.png`) before flashing AES, and it is
flat and featureless. The contrast is useful: no work, no structure; AES running, clear
structure.

### The trigger: why every trace lines up

To compare traces, the S-box step for byte 0 must happen at the same sample number in every
trace. If recordings started at random moments, the leak would smear across different
positions and the math would fail.

So our AES firmware raises a small signal pin (a **trigger**) the instant encryption starts,
and the ChipWhisperer begins recording exactly then. As a result, in every trace sample 0 is
"AES just started," and some fixed sample (say 1742) is always "byte 0's S-box result is
being stored." Everything is aligned.

### Stacking the traces into a grid

Picture stacking all the traces on top of each other. We captured 5,000 traces, each with a
different random plaintext but the same secret key. That is a grid:

```text
              time (5000 sample columns) ------>
            col0  col1  ...  col1742  ...  col4999
trace 1  [  0.02  0.05  ...   0.81    ...  0.03  ]
trace 2  [  0.01  0.06  ...   0.44    ...  0.02  ]
   ...
trace 5000[ 0.02  0.04  ...   0.79    ...  0.03  ]
                              ^^^^^
                       the leaky instant for byte 0
```

5,000 traces by 5,000 samples (the two 5,000s are a coincidence). The attack in Lesson 4
looks at one column at a time, for example column 1742, which holds 5,000 power readings, one
per trace, all at the same "store byte-0 S-box result" moment.

### Why we vary the plaintext

This is what makes correlation possible. We keep the key fixed but send a different random
plaintext each time. So from Lesson 2's chain (plaintext XOR key, then S-box, then Hamming
weight), the Hamming weight changes from trace to trace because the plaintext changes. That
means the leaky column's power values also move up and down across traces. Lesson 4 just
checks whether those power movements match the Hamming-weight movements a key guess predicts.
For the right key, they do.

### What we save with each trace

A bare power line is not enough; we also record what produced it. For every trace we store
the plaintext we sent, the key used, the ciphertext the chip returned (so we can confirm it
encrypted correctly), plus capture settings (board, sample rate, trigger) in a small manifest
file.

This lives in `traces/unprotected_fixedkey.npz` (the data, about 100 MB) and
`traces/unprotected_fixedkey.manifest.json` (the settings). Saving everything is what lets
the attack re-run later with no hardware: the chip's work is frozen on disk.

We captured two sets:

- fixed-key set (5,000 traces, one secret key): the one we attack.
- random-key set (5,000 traces, keys change too): used later to train the neural network in
  Lesson 5.

### Which moments actually leak (a preview)

Not all 5,000 columns carry the secret; most are unrelated chip activity. The picture
`results/snr_unprotected.png` measures where in time the leak is strongest (a signal-to-noise
view). CPA scans all columns and the leaky ones stand out on their own; the neural network
uses this to focus on the handful of leaky samples. More in Lesson 5.

### The capture loop, in plain steps

```text
repeat 5000 times:
    pick a random 16-byte plaintext
    send it to the chip and say "encrypt"
    chip raises trigger, ChipWhisperer records 5000 power samples
    chip returns the ciphertext
    save: trace + plaintext + key + ciphertext
```

That loop, run on real hardware (an approved step, since it drives the chip), produced the
dataset both attacks feed on.

The one thing to remember from this lesson: a power trace is a 5,000-number snapshot of the
chip's electricity over time; a trigger lines every trace up so the same AES moment sits in
the same column; we capture 5,000 of them with random plaintexts and a fixed key so the leaky
column visibly moves; and we save each trace with its plaintext, key, and ciphertext so the
attack can run from disk.

---

## Lesson 4: Attack #1, CPA (how statistics finds the key byte)

We now have everything we need: the leaky chain from Lesson 2 (plaintext XOR key, then
S-box, then Hamming weight) and the grid of 5,000 aligned traces from Lesson 3. CPA is the
method that turns those two things into a recovered key.

### We attack one key byte at a time

The full key is 16 bytes. CPA never guesses all 16 at once; that would be 256^16
combinations, hopeless. Instead it cracks byte 0 by itself, then byte 1 by itself, and so on.
For one byte there are only **256 possible values** (0 to 255), and 256 guesses is nothing for
a computer. So the whole problem shrinks from "impossible" to 16 easy little problems of 256
guesses each.

### The trick: predict the power for each guess, then see which prediction matches reality

We do not know the real key byte. But for each guess (say "maybe byte 0 is 0x2B") we can
compute, for every trace, what the Hamming weight would be if that guess were right:

```text
prediction for guess G, on trace i  =  HW( Sbox( plaintext_i[0] XOR G ) )
```

We know `plaintext_i[0]` (we sent it). We pick a guess G. The S-box and Hamming weight are
just the lookups from Lesson 2. So for each guess we get a column of 5,000 predicted numbers,
one per trace.

### Compare predictions to the real measured power

From Lesson 3 we have the real power at the leaky moment, one number per trace (a column of
the grid). For the correct guess, the predicted Hamming weights rise and fall in step with the
real power, because the chip really did compute that value and really did burn power related to
its Hamming weight. For a wrong guess, the predictions are scrambled and track nothing.

```text
        guess = 0x2B (CORRECT)              guess = 0x40 (WRONG)
trace  predicted HW  measured power      predicted HW  measured power
  1        4            0.81 (high)          2            0.81
  2        2            0.44 (low)           5            0.44
  3        5            0.92 (high)          3            0.92
  4        1            0.30 (low)           4            0.30
  ...
        predictions move WITH power      predictions vs power: no pattern
```

### "Correlation" is just a number that measures that match

We need a score for "do these two columns move together?" without eyeballing. That score is
the **Pearson correlation coefficient**, a number between -1 and +1:

- near **+1**: the two columns rise and fall together (strong match)
- near **0**: no relationship (random)

So the recipe for one key byte is:

```text
for each guess G in 0..255:
    build the prediction column (5000 predicted Hamming weights)
    correlation[G] = how well that column matches the real power column
the winning guess = the G with the highest correlation
```

The correct key byte stands out with a high correlation; the other 255 sit near zero. That
tall spike is the moment the byte is recovered.

### We do not need to know which time-column is leaky

In Lesson 3 the leak lived in one specific column (say sample 1742), but we do not actually
know which one in advance. CPA solves this for free: it computes the correlation at every one
of the 5,000 time samples, for every guess, and takes the peak. The correct key byte produces
a sharp spike at the true leaky moment; wrong guesses stay flat everywhere. So CPA finds both
the right key byte and the right moment in time, automatically. That is exactly what
`byte_correlations` and `byte_scores` do in `src/dlsca/cpa.py`: build a 256-by-5000
correlation grid, then take the max over time.

```text
correlation
   ^
   |                    *  <- correct guess, correct moment: tall spike
   |   .  . .  .  .  .  .  .  .  .   <- all 255 wrong guesses: flat noise
   +---------------------------------> time sample
```

### Why it needs many traces (the ~100 number)

With only a handful of traces, random noise can accidentally make a wrong guess look
correlated. The more traces you pile on, the more the noise averages out and only the true
relationship survives. On our data, after about **100 traces** the correct value wins for all
16 bytes at once. We measure this with the **guessing-entropy curve** (`ge_curve` in the code,
`results/cpa_ge_curve.png`): it re-runs CPA on the first 10, 20, 50, 100 traces and plots how
the key's rank falls to 0 (rank 0 means the correct key is the top guess for every byte). The
trace count where it first hits 0 is `traces_to_rank0 = 100`.

### Why we ran CPA at all

CPA is the classic, well-understood method. We ran it before trusting the neural network so we
could prove the leak is genuinely there and the key is genuinely recoverable. If the simple
statistics could not find the key, we would never believe the CNN's claim. CPA passing first is
what makes Lesson 5's result trustworthy.

The one thing to remember from this lesson: CPA cracks one key byte at a time by trying all
256 values; for each guess it predicts the Hamming weight on every trace and measures how well
that prediction correlates with the real power; the correct byte's prediction tracks the power
and spikes, the 255 wrong ones stay flat, and with about 100 traces all 16 bytes lock in.

---

## Lesson 5: Attack #2, the CNN (the network that learns the leak)

CPA worked, but notice what we had to hand it: the exact leakage rule from Lesson 2
(plaintext XOR key, then S-box, then Hamming weight). We assumed power tracks Hamming weight.
On a clean chip that is right. But if the chip leaks in some weirder way we did not guess, our
hand-written rule is wrong and CPA gets weaker. The neural network's pitch: do not assume the
rule, learn it from data.

### What the CNN is trying to predict

CPA predicted Hamming weight (a number 0 to 8). The CNN predicts something more precise: the
actual S-box output value itself, a number from 0 to 255 (the "identity / 256-class" label in
the notes). So the network's job is:

```text
input:  one power trace (the leaky samples)
output: a probability for each of the 256 possible S-box values
        "I'm 70% sure the S-box result was 0x83, 5% sure it was 0x12, ..."
```

It is a 256-way guess about what value the chip just computed, read straight off the power.

### Profiling: train on a chip you control, attack a chip you do not

This is the big idea that makes it powerful, and it is why we captured two datasets in Lesson 3.

```text
PROFILING (training) phase          ATTACK phase
random-key set (5000 traces)        fixed-key set (the secret key)
we KNOW every key here              we do NOT know the key
  -> we can compute the true          -> we just feed traces to the
     S-box value for each trace          trained model and read its
  -> teach the network:                  256-way guesses
     "this trace shape -> this value"
```

We train on traces where we know everything (so we can grade the network and correct it), and
we let it learn the chip's personal leakage signature. Then we point that trained network at
the secret-key traces. This mirrors the real threat: an attacker buys an identical chip,
studies it at leisure, then attacks the victim's device. The code splits exactly this way:
`train()` runs on the random-key profiling set, `predict_log_proba()` runs on the fixed-key
attack set.

### How "learning" actually happens (in plain terms)

The network (`CnnDLSCA` in `src/dlsca/model.py`) is a stack of layers with thousands of
adjustable knobs. Training is just:

```text
repeat for many rounds (epochs):
    show it a batch of traces whose true S-box value we know
    it guesses; we measure how wrong it was
    nudge every knob a little to make next time less wrong
```

After about 30 passes over the data, the knobs settle into a configuration that reliably maps
"trace shape" to "S-box value." Nobody told it about Hamming weight or XOR. It discovered
whatever pattern the chip actually leaks. That is the whole appeal: it adapts to the real
hardware instead of trusting our textbook assumption.

The layers themselves (two convolution blocks, then two dense layers) are built to scan a 1-D
signal for little tell-tale shapes, the same way image networks scan for edges. Here they scan
the power trace for the wiggle that betrays the S-box value. It is deliberately small (a few
thousand knobs) so it trains in seconds on the MacBook.

### Turning 256-way guesses into a key

The network predicts the S-box value, but we want the key byte. The bridge is the same
arithmetic as CPA. For each trace we know the plaintext byte, and for any key guess G the
S-box value would be `Sbox(plaintext XOR G)`. So:

```text
for each key guess G in 0..255:
    for each attack trace:
        v = Sbox(plaintext_byte XOR G)        # value implied by this guess
        add the network's reported probability for value v
    the guess that piled up the most probability across all traces wins
```

Each trace casts a weighted vote. The correct key is the only guess that lines up with the
network's confident predictions on every trace, so its total climbs steadily while wrong
guesses stay scattered. In the code this accumulation is the log-likelihood that feeds
`attack.key_rank` and `attack.guessing_entropy`, the same ranking engine CPA used, so the two
attacks are scored identically and fairly.

### Why it wins with ~12 traces instead of ~100

CPA only ever used one crude fact (Hamming weight) and threw away everything else in the
trace. The CNN uses the full shape of the leaky region and learns the chip's exact signature,
so each trace carries far more usable information. Result: the key falls in about 12 traces
versus CPA's 100, roughly 8x fewer. Same guessing-entropy curve, same rank-0 finish line;
`results/cpa_vs_cnn_ge.png` is that headline comparison.

### The reproducibility catch (the model card)

A trained network is only trustworthy if it behaves identically every time. Two things must be
frozen: which time-samples we fed it (the POI window) and how we scaled them
(standardization). The code saves both, plus the seed, framework versions, and architecture,
into a JSON **model card** next to the weights. Load the card, and inference re-applies the
exact same transform it trained on, so the ~12-trace result reproduces instead of drifting.
This is the same honesty discipline as everything else in the project: nothing is claimed that
cannot be re-run.

The one thing to remember from this lesson: instead of assuming the leakage rule like CPA, the
CNN learns the chip's real leakage by training on a known-key chip (profiling), then predicts
the 256-way S-box value on the secret-key traces; converting those predictions to a key uses
the same `Sbox(plaintext XOR guess)` bridge, and because it uses the full trace shape it
recovers the key in about 12 traces, roughly 8x fewer than CPA.

---

## Lesson 6: the defense (masking, and how it saved the key)

Lessons 4 and 5 broke the key in 100 traces (CPA) and 12 (CNN). This lesson is the other side:
a countermeasure called masking, which we put on the same chip and which made both attacks
fail, even with 5000 traces. And we did it on our own Cortex-M0 Nano, not new hardware.

### What the attack actually needed

Both attacks hung on one thing: the secret value from Lesson 2 physically showing up in the
chip's power.

```
secret value  v = S-box( plaintext XOR key )
```

The chip's power rises and falls with `v`, and the whole attack was: guess the key, predict
`v`, see whose prediction matches the power. Kill the part where `v` shows up, and the attacks
have nothing to grab.

### What masking does: hide the value behind a fresh coin flip

Before the chip ever touches `v`, masking splits it into two random pieces using a fresh random
number `m` (the "mask"), drawn new for every single encryption:

```
piece A = v XOR m     (the value, scrambled by the mask)
piece B = m           (the mask itself)
```

`A XOR B` gives back `v`, but the chip never does that XOR until the very end. It works on A
and B separately the whole time. So at any single instant, the power reflects A, or B, but
never `v` itself.

### A simple binary example

Say at one byte the real secret value is `v = 0x83 = 1000 0011` (Hamming weight 3, the Lesson 2
result).

Without masking, the chip holds `1000 0011` every time that plaintext is sent, so it always
leaks "3 bits set." The attacker correlates against that steady 3 and wins.

With masking, a fresh random `m` is drawn each time, and the chip actually holds `A = v XOR m`:

```
encryption 1:  m = 0101 1100  ->  A = 1000 0011 XOR 0101 1100 = 1101 1111   (HW 7)
encryption 2:  m = 1111 0000  ->  A = 1000 0011 XOR 1111 0000 = 0111 0011   (HW 5)
encryption 3:  m = 0000 0110  ->  A = 1000 0011 XOR 0000 0110 = 1000 0101   (HW 3)
encryption 4:  m = 1010 1010  ->  A = 1000 0011 XOR 1010 1010 = 0010 1001   (HW 3)
```

The real value was the same `0x83` every time, but the number the chip holds (and the power it
leaks) is different and random each time: 7, 5, 3, 3, ... Because `m` is random, `A` looks like
noise to the attacker. It says nothing about `v`.

### Why this defeats both attacks

```
CPA: predicts power from a key guess, then correlates.
     The power now tracks (v XOR m), and the attacker doesn't know m,
     so every key guess matches the noise equally -> no spike. The tall
     correlation peak from Lesson 4 flattens into the grass.

CNN: learns "this trace shape -> this value."
     The same secret v now looks different in every trace (scrambled by a
     fresh m), so there is no stable shape to learn. Training finds nothing;
     accuracy stays at chance (about 1 in 256, i.e. random guessing).
```

### The answer still comes out right

The two pieces recombine at the very end: `A XOR B = (v XOR m) XOR m = v`. The mask cancels
itself out, so the chip outputs the exact same ciphertext as before (we verified
`69c4e0d8...b4c55a` on the masked chip). Masking costs nothing in correctness; it only removes
the leak.

### What we measured on the real chip

We flashed the masked AES, captured fresh traces, and re-ran the unchanged CPA and CNN. The
before/after is `results/us3_defense_ge.png`:

```
                 unprotected (Lesson 4/5)      masked (this lesson)
   CPA           full key at ~100 traces        NOT recovered at 5000
   CNN           full key at ~12 traces         NOT recovered at 5000
```

On the masked target the mean key rank never falls toward 0; it sits around 100 (out of 255)
across the whole 5000-trace budget. The key that fell in 12 to 100 traces before now survives
50x to 400x that many. The defense holds.

### The honest caveat

This is a first-order defense: the secret is now split across two places (the masked value and
the mask). A simple attack that looks at one spot at a time sees only noise. A fancier
higher-order attack that grabs both spots and XORs them back together could in principle still
get there, but that is a much harder, more expensive attack, and beyond what we ran. Also, our
masks come from a software random-number generator (the chip has no hardware one); the attack
failing is the evidence it was random enough.

The one thing to remember from this lesson: masking makes the chip handle a freshly-randomized
version of the secret on every run (`v XOR m` with a new `m` each time), so the one value both
attacks were listening for is never actually present in the power; the pieces recombine to the
correct ciphertext at the end, and that is why the key survived all 5000 traces after falling
in 12 to 100 before.

---

## Lesson 7: the project itself (code, safety rules, and workflow)

You now understand the attacks and the defense. This lesson is the map: how the pieces on disk
fit together, the safety rules that shaped every hardware step, and the workflow we followed.

### The code, folder by folder

```
src/dlsca/        the brains (pure Python, mostly no hardware)
  leakage.py       the AES S-box, Hamming weight, the "intermediate" v = Sbox(pt XOR key)
  dataset.py       load/save trace sets (.npz) + manifests; validate them
  preprocess.py    pick the leaky samples (POI window) and standardize them
  cpa.py           Attack #1: correlation power analysis (Lesson 4)
  model.py         Attack #2: the profiling CNN (Lesson 5)
  attack.py        the shared scorekeeper: key rank, guessing entropy, traces_to_rank0
  capture.py       the ONLY file that touches hardware (claim USB, flash, capture)
  seeds.py         set every random seed so runs reproduce

firmware/
  aes-unprotected/ the normal AES we attacked (built from the kit)
  aes-masked/      our own Cortex-M0 masked AES (the defense), + host test + BUILD.md

notebooks/         00 bringup, 01 capture, 02 CPA, 03 CNN (the unprotected story)
scripts/           us3_* : capture, attack, and figure for the masked defense
traces/            the captured power data (.npz, big, not in git; rebuilt from manifests)
models/            trained CNN weights + model cards
results/           the JSON results and the figures (the evidence)
notes/             hardware.md, approvals.md, setup-verified.md (the lab notebook)
content/           the public writeups (post1 attack, post2 defense)
docs/              this file
tests/             host tests that check the math without any hardware
```

A useful split to notice: almost everything is **pure software that runs on saved data**. Only
`capture.py` touches the board. That is deliberate, and it is what the safety rules are built
around.

### The safety and honesty rules

The project follows a small set of written rules. The ones you felt in this series:

- **I. Hardware safety and explicit human approval.** Every step that flashes firmware, claims
  the USB device, installs software, or drives the chip is approved by a human, one action at a
  time, and logged. You saw this constantly: I stopped and asked before each flash and before
  the capture, and every "yes" was written into `notes/approvals.md` with what was approved and
  what happened. Consent to flash once was never consent to flash again.
- **II. Authorized and ethical scope.** Own hardware, self-generated test keys, an isolated
  bench. This is education and defense, not attacking anyone else's device.
- **III. Reproducibility end to end.** Pinned versions, fixed seeds, saved traces with
  manifests, and model cards, so a result can be re-run and lands the same.
- **IV. Verified baseline before building.** Confirm the chip really runs correct AES before
  trusting any attack result (the FIPS-197 ciphertext check).
- **V. Measure, do not claim.** Report honest success metrics (key rank, traces-to-recover),
  and if something is not recovered, say so. This is why "the masked attack failed" is reported
  as a number, not hand-waved.
- **VI. Verify on the real target.** The attacks were proven on actual silicon, not just in
  simulation.
- **VII. Clear, honest public communication.** The writeups map every claim to an artifact and
  admit limits (for example, the software PRNG, and first-order vs higher-order).

These were not decoration. When the kit's masked AES turned out not to build on our chip, the
rules are why we documented the blocker honestly and deferred rather than faking a result, and
later why we wrote our own masked AES and let the attack be the judge.

### How approval-gating actually works in the code

`capture.py` refuses to do anything risky unless you pass `approved=True` AND an
`approval_ref` pointing at the line in `notes/approvals.md` where a human said yes. The
reference gets stamped into the saved data's manifest, so months later you can trace any trace
file back to the exact approval that produced it. Pure-analysis code (CPA, CNN, scoring) has no
gate, because it only ever reads saved files.

### Decisions were written down first

We did not just start coding. Each goal and design choice was written down before it was built,
and every result was recorded with the artifact that produced it. The point: every decision and
every result is checkable, which is exactly what you want when the claims are about breaking
cryptography.

The one thing to remember from this lesson: the project is mostly pure software that runs on
saved data, with a single hardware-touching file (`capture.py`) wrapped in per-action human
approval; a small set of rules (own hardware, reproducible, measure-do-not-claim) shaped every
step; and decisions were written down so every claim maps back to an artifact.

---

## Lesson 8: doing it yourself (running and reproducing)

This last lesson is the hands-on one: how to actually run the project. The good news from
Lesson 7 applies here, almost everything reproduces with no hardware, because the traces are
saved.

### What you need

- A Mac (Apple Silicon is what we used; the CNN trains on its GPU via MPS, but CPU works too).
- Python 3.9 to 3.11.
- For the attacks: nothing else, just the saved traces (or their manifests).
- For capturing your own traces: a ChipWhisperer-Nano and the approval to drive it.

### Step 1: set up the environment

From the project root:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e . --no-deps
```

This creates an isolated Python with the exact pinned versions (chipwhisperer, numpy, scipy,
torch, jupyterlab, pytest) and makes the `dlsca` package importable.

### Step 2: check the math (no hardware)

```bash
pytest -q          # 39 host tests should pass
```

These verify the S-box, the Hamming weight, the CPA correlation, the key-ranking, and the CNN
plumbing, all without a chip. If these pass, the analysis layer is sound.

### Step 3: reproduce the attack (no hardware, needs the trace files)

With `traces/unprotected_fixedkey.npz` present, run the notebooks (Run All):

```
notebooks/02_cpa_baseline.ipynb   -> recovers 000102...0e0f, traces_to_rank0 = 100  (CPA)
notebooks/03_cnn_dlsca.ipynb      -> same key, traces_to_rank0 = 12                  (CNN)
```

Because the seeds are fixed, you should get the same key and the same trace counts we did.

### Step 4: reproduce the defense (no hardware, needs the masked trace files)

```bash
python scripts/us3_attack_masked.py   # CPA + CNN on the masked traces
python scripts/us3_figure.py          # builds results/us3_defense_ge.png
```

Expect the opposite of step 3: neither attack recovers the key (`traces_to_rank0 = None`),
which is the defense working.

### Step 5 (optional, hardware): capture your own traces

This is the only part that touches a board, and every step is human-approved (Lesson 7):

```
1. build the firmware (firmware/aes-unprotected or aes-masked; see BUILD.md)
2. flash it to the Nano           [approval: flash]
3. verify the test-vector ciphertext   [approval: HIL]
4. run notebooks/01_capture.ipynb or scripts/us3_capture_masked.py   [approval: capture]
```

Each approval gets logged in `notes/approvals.md`, and the captured files carry a manifest that
records the board, the settings, and the approval reference.

### Where to look when something surprises you

- A result number: `results/*.json` (the source of truth).
- A hardware detail: `notes/hardware.md` and `notes/setup-verified.md`.
- What was approved and when: `notes/approvals.md`.
- The masked AES design and its limits: `firmware/aes-masked/BUILD.md`.

The one thing to remember from this lesson: the whole result reproduces from saved data with
three commands (install, `pytest`, run the notebooks/scripts) and no hardware; capturing fresh
traces is the only board step, and it stays behind per-action human approval, with every run
traceable through its manifest back to the approval that allowed it.

---

*This completes the beginner's guide. You now have the full picture: why a chip leaks, what
leaks, how we captured it, two ways to turn that leak into a key, one way to stop it, and how
the whole project is built and reproduced.*
