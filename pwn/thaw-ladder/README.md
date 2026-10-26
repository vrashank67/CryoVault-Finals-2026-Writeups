# thaw-ladder

| | |
|---|---|
| **Event** | CryoVault Finals 2026 (ISFCR PES University) |
| **Date** | 2026-10-24 |
| **Category** | pwn |
| **Difficulty** | hard |
| **Points** | 500 |
| **Target** | `isfcrpesu-thaw-ladder.chals.io:443` (raw line protocol behind a TLS wrapper) |
| **Flag** | `isfcr{pod_seven_4bde_woke_4364d220_in_bay_c}` |

No binary was published: the challenge is a **black-box pwn** against a live
`thawd` pod controller. The kit for the 7.2 "bench" build (manual + a reference
Python implementation) documents the instruction set, but the remote runs the
undocumented 7.3 field build, and the field notes say so:
*"where the pod and the bench disagree, the pod is right."*

---

## 1. Reconnaissance

### 1.1 Transport

The service speaks a plain line protocol (`\n`-terminated) but only after a TLS
handshake:

```python
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
```

Banner:

```
thawd 7.3 pod 07 session 06eda03b409c9c65 meter 188458 ready
```

### 1.2 Verb enumeration

Verbs are **uppercase and arity-strict**: a verb with the wrong number of
arguments answers `ERR verb`, exactly like an unknown verb. Pipelining hundreds
of candidate lines per connection (the server accepts many lines before you
read) found exactly three verbs:

| Input | Answer |
|---|---|
| `HELP` | `OK PLAN <hex instruction words> \| QUIT` |
| `QUIT` | `BYE quit`, then the link closes |
| `PLAN <words>` | a verdict |

`PLAN` takes exactly one argument: 1..1024 words of *exactly* 8 hex digits each,
concatenated. Anything else is `ERR plan`; a line over ~8 KiB is `ERR line`.

### 1.3 Blind ISA discovery

Pipelining a few thousand single-word plans classified the word layout without a
binary:

* `PLAN 00000000` → `SETTLED` (HALT).
* every word with a nonzero *reserved* field → `FAULT` (decode fault).
* `PLAN C0000000` → `OVERRUN`, and `C0000000` is `JAL r0, r0, 0`, i.e. a jump to
  itself: an infinite loop that burns the 65536-instruction budget.

That pins the encoding to 32-bit words split as
`op[31:28] | a[27:24] | b[23:20] | c[19:16] | imm[15:0]`, and identifies the
verdicts `SETTLED` / `FAULT` / `OVERRUN` / `REJECT` / `THAWED <n> <key>`.

With the 7.2 handout (`FROSTLANG.md`, `frostbench.py`) the rest of the ISA is
known: a 16-bit register machine (`LDI/ALU/ALUI/LDB/LDW/STB/STW/BEQ/BNE/BLTU/
DJNZ/JAL/SEAL/ATT/NOP/HALT`), 64 KiB of byte memory, and a protected
"recorded-profile window" at `W = 0x9000` holding the pod's sealed 32-byte
profile `P`.

## 2. The three bugs

### 2.1 `SEAL` has a signedness bug (bounds check → pointer bug)

`SEAL a` must accept a window offset `0..32`; the field build implements
`(int16_t)offset <= 32`, so `0x8000..0xffff` pass as "negative". Verified live:

```
SEAL 0x0021 -> FAULT      (33, correctly rejected)
SEAL 0x8000 -> SETTLED    (should be out of range)
SEAL 0xffff -> SETTLED
```

The address math then wraps: `W + 0x8000 = 0x1000` (16-bit), so the 32
comparisons are redirected out of the protected area into **ordinary RAM**, which
the submitted plan fully controls. We still cannot *read* `P`, but we can steer
the comparison.

### 2.2 The meter is a one-unit work side channel

Every verdict carries the controller's cumulative work meter. On the 7.3 build
it is a quantised counter, not the retired-instruction count of the bench:

```
meter_new = meter_old + floor((residue + cost) / q)
```

`q` is a hidden per-session quantum (51 in our session), `cost` the plan's work,
`residue` the leftover. Calibrating with a run of `HALT` plans and a run of
`NOP;HALT` plans (the extra NOP kills scaled aliases) gave `q=51, halt_cost=9,
overhead=8`; a SEAL-only plan then measures SEAL's fixed charge.

SEAL short-circuits on the first rung that mismatches, so **each extra matching
rung adds exactly one hidden work unit**. Pad the plan with NOPs until the
residue sits at `q-1` and that single unit is exactly enough to click the visible
meter over by one:

```
hit  <=>  observed_meter > expected_meter
```

That is a prefix oracle: to test a candidate byte, fill the candidate RAM cells
with it, restore the already-known rungs, run `SEAL 0x8000`, and watch for the
tick.

### 2.3 The ladder is shuffled

Redirecting SEAL into RAM does **not** give a contiguous compare
(`RAM[A+i]` vs `P[i]`). The 7.3 build walks a **shuffled 32-rung ladder**: rung
`i` reads a session-random RAM address `src[i]`, and the 32 addresses are a
permutation of one contiguous 32-byte block (here `0x17c5..0x17e4`). Recovering a
byte alone is therefore not enough — every rung needs **its byte and its
address**, two separate searches.

Our session:

```
ladder order bytes : bfe6cbeef4f16f3669a245c1a4ae364b0cdc788efc2407e88f28dc8ed6cb0457
source addresses   : 17cd 17dd 17c5 17d3 17da 17d5 17d7 17de 17e1 17c6 17dc 17c8
                     17d8 17ca 17df 17e0 17d0 17db 17d4 17e2 17cc 17d6 17ce 17cf
                     17c9 17e3 17d1 17d9 17e4 17d2 17c7 17cb
fold order (sorted) : cba204c18fae57fcbf07e80cdccbee78f1246fa48ef4dc45e636364b698e28d6
```

## 3. Exploitation

### 3.1 Byte recovery (prefix oracle)

For rung `k`, fill the candidate window with guess `g`, restore the `k` known
rungs, `SEAL 0x8000`, pad NOPs to park the residue at `q-1`, `HALT`. Exactly one
`g` (the real `P[k]`) yields one extra comparison and one visible meter tick.
Byte `0` cannot be tested by filling (fresh RAM is already zero, so everything
"matches"), so the search runs `1..255` and treats "no hit" as `0`.

### 3.2 Address recovery (binary search over the surviving window)

With a rung's byte known, set the *unknown* candidate cells of the block window
to that byte, restore the known rungs, and SEAL: a tick means rung `k`'s source
lies in the filled half. Binary search halves the candidate set. For a rung whose
byte is `0` the test is inverted: poison all other candidate cells with `1`, so
the tick happens when the source is *not* in the poisoned set.

### 3.3 Final byte and final address via the gate

For rung 31 there is no "extra comparison" to observe: a wrong and a right final
byte both examine all 32 cells. Instead the **gate itself** is the 1-bit oracle:
fill, restore 31 rungs, `SEAL 0x8000`, try to store a valid `CONT` to `0x8200`,
`HALT`, and run one privileged `ATT`. Wrong final byte → gate closed → the CTL
store faults; right byte → store works → `ATT` draws a challenge → `SETTLED`.
The same gate/no-gate test binary-searches rung 31's source address.

### 3.4 The thaw

One final plan (262 words):

1. fill the 32-byte block with the last rung's byte, restore the 31 known rungs;
2. `SEAL 0x8000` — all 32 pass, the gate opens;
3. only now materialise the linear `K` table at `0x1000` (writing it earlier
   would clobber the scattered source block);
4. store a privileged continuation word `CONT = 0x8000|priv` at `0x8200`,
   `HALT` → the plan resumes in **privileged** mode;
5. run the documented 16-step fold for four `ATT` rounds:

```text
for t = 0..15:
    j = (t + (y >> 12)) & 15
    x = rotl16(x ^ K[j], y & 15)
    x = (x + N[t & 3]) & 0xffff
    y = (y * 0x9e35 + x + t) & 0xffff
    y = y ^ rotl16(x, 7)
```

The verdict:

```
FINAL THAWED 358107 isfcr{pod_seven_4bde_woke_4364d220_in_bay_c}
```

### 3.5 Performance: finishing inside the session cap

The published 7.2 technique fills all 32 KiB of RAM per probe (~49k retired
instructions, ~1.5 s/plan here). With a 3600 s / 16384-plan session cap and
~7150 probes that does not fit.

The ladder block is contiguous and every recovered address narrows the possible
block start to `S ∈ [max(known)-31, min(known)]`, so after the *first* address
the entire search only ever needs the ≤64-byte window that can still hold the
block. Filling just that window costs ~130 instructions instead of ~49k — the
run becomes RTT-bound at ~4 plans/s and completes the whole recovery in **5848
plans / ~25 minutes**, one session, no reconnects.

## 4. Validation

* The flag came straight from the service's `THAWED <n> <key>` line (the only
  path that emits it), inside a single session, after the attestation chain
  accepted four folded answers.
* The recovered 32 addresses were checked to form a permutation of one 32-byte
  block (`max-min == 31`, 32 distinct values) before the final plan ran — the
  structural invariant of the shuffled ladder.
* The standalone `exploit.py` also reproduces `THAWED ... bench-no-key` against
  the published 7.2 bench (`python exploit.py --bench`).
* No decoy: the reported string carries no self-labelled decoy marker, and the
  only decoy-style strings seen anywhere in the family were self-labelled.

## 5. Files

| File | What |
|---|---|
| `exploit.py` | standalone solve: assembler + TLS client + meter calibration + shuffled-ladder recovery + thaw. `--bench` runs the 7.2 self-test. |
| `solve_log.txt` | full live transcript of the winning run (5848 plans) |

## 6. Lessons

* **Bounds checks written on the wrong signedness turn into pointer bugs.**
  `(int16_t)off <= 32` accepted `0x8000`, and the subsequent 16-bit wrap pointed
  the secret comparison at attacker-controlled RAM.
* **Coarse telemetry is still telemetry.** A meter rounded down to a quantum was
  enough once the hidden residue could be parked at `q-1`, making a single extra
  comparison visible.
* **Black-box verdicts are evidence.** `SETTLED` vs `FAULT` vs `OVERRUN` mapped
  the whole ISA and, later, the gate state.
* **A prefix oracle does not imply a linear layout.** Bytes and their source
  addresses had to be recovered separately because the ladder is shuffled.
* **Exploit cost is part of the exploit.** With a per-session time/plan budget,
  shrinking each probe's work by ~500x was as important as the bug itself.
