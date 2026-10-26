# FROSTLANG - thaw plans for the thawd pod controller

**Revision 7.2 (bench).** This manual describes thaw plans and the controller protocol as
the 7.2 bench build runs them. `frostbench.py` in this kit is that bench build; where this
manual and `frostbench.py` disagree, `frostbench.py` is right. Pod 7 runs the 7.3 field
build (`FIELD-NOTES.md`).

CryoVault cold store, bay C. A pod controller, `thawd`, runs *thaw plans*: small programs
for a 16-bit register machine. It answers every plan with a verdict and a number.

## 1. Sessions

A session is one conversation with one controller. The bench runs one session on its
standard input and output.

## 2. Wire protocol

Lines end in `\n`; a `\r` before it is ignored.

When a session opens, the controller sends one line, its banner. The bench's banner is:

    frostbench 7.2 pod 07 bench session ready

Commands:

| Command | Answer |
|---|---|
| `PLAN <words>` | `<VERDICT> <n>` (section 7) |
| `QUIT` | `BYE quit`, then the session ends |
| `HELP` | one `OK ...` line |

`<words>` is the plan: 1 to 1024 instruction words, each written as exactly 8 hex digits,
most significant digit first, with nothing between words. Hex digits may be upper or lower
case.

Errors do not run anything:

| Line | Meaning |
|---|---|
| `ERR empty` | empty line |
| `ERR verb` | not a command |
| `ERR plan` | the words are not 8-digit hex groups, or there are more than 1024 |
| `ERR line` | a line longer than 8448 bytes |

Lines are taken strictly in order, so a client may send many lines before it reads any
answers.

## 3. The machine

### 3.1 Registers

Sixteen 16-bit registers `r0`..`r15`. `r0` always reads as zero; writes to it are
discarded. All arithmetic is modulo 2^16.

### 3.2 Code

A plan's words are its code. `pc` counts words from 0. Code is not data: no load or store
reaches it, and nothing changes it while a plan runs. Fetching from a `pc` outside the plan
faults (`fetch`), including running off its end.

### 3.3 Data memory

65536 cells (bytes), addresses `0x0000`..`0xffff`. A 16-bit word in memory is
**big-endian**: the word at address `a` is `mem[a] * 256 + mem[a+1]`. Address arithmetic
wraps modulo 65536.

| Range | Name | Load | Store |
|---|---|---|---|
| `0x0000`-`0x7fff` | RAM | yes | yes |
| `0x8000`-`0x80ff` | BOOT | yes | fault `write` |
| `0x8100`-`0x81ff` | MBOX | yes | yes |
| `0x8200`-`0x82ff` | CTL (control block) | yes | only while the gate is open, else fault `sealed` |
| `0x8300`-`0x8fff` | - | fault `read` | fault `write` |
| `0x9000`-`0x9fff` | controller area | fault `read` | fault `write` |
| `0xa000`-`0xffff` | - | fault `read` | fault `write` |

A word access checks both of its cells; a store that faults writes nothing.

BOOT, as every plan finds it:

| Address | Word |
|---|---|
| `0x8000` | `0x4652` |
| `0x8002` | revision, `0x0702` |
| `0x8004` | `x0`, the chain origin (section 6) |
| `0x8006` | `y0` |
| `0x8008` | `0x0007` (pod) |
| others | 0 |

CTL: the word at `0x8200` is the continuation word `CONT` (section 5). The rest of the
block is reserved; storing to it is allowed whenever storing to `CONT` is, and has no
effect.

### 3.4 The recorded-profile window

The controller area holds the pod's recorded-profile window: the 64 cells starting at
address `W = 0x9000`.

### 3.5 Every plan starts from

All registers 0, RAM / MBOX / CTL all zero, the gate closed, unprivileged, nothing
retired. Only BOOT and the controller area hold the session's values. One plan cannot
leave anything for the next.

## 4. Instructions

### 4.1 Encoding

    31      28 27     24 23     20 19     16 15                              0
    +---------+---------+---------+---------+--------------------------------+
    |   op    |    a    |    b    |    c    |              imm               |
    +---------+---------+---------+---------+--------------------------------+

Fields an instruction does not use must be zero; otherwise it faults (`decode`). `HALT` is
therefore exactly `00000000` and `NOP` exactly `f0000000`.

`simm` below is `imm` read as a two's-complement 16-bit number.

### 4.2 Reference

Each instruction that completes retires 1. An instruction that faults does not retire.

| op | Name | Uses | Effect |
|---|---|---|---|
| `0` | `HALT` | - | end of plan, see section 5 |
| `1` | `LDI` | a imm | `r[a] = imm` |
| `2` | `ALU` | a b c imm | `r[a] = F(imm)(r[b], r[c])`; `imm` must be a function code (4.3) |
| `3` | `ALUI` | a b c imm | `r[a] = F(c)(r[b], imm)`; `c` must be a function code |
| `4` | `LDB` | a b imm | `r[a] = mem[r[b] + imm]` |
| `5` | `LDW` | a b imm | `r[a] = word at r[b] + imm` |
| `6` | `STB` | a b imm | `mem[r[b] + imm] = r[a] & 0xff` |
| `7` | `STW` | a b imm | `word at r[b] + imm = r[a]` |
| `8` | `BEQ` | a b imm | if `r[a] == r[b]`: `pc = pc + 1 + simm` |
| `9` | `BNE` | a b imm | if `r[a] != r[b]`: `pc = pc + 1 + simm` |
| `a` | `BLTU` | a b imm | if `r[a] < r[b]` (unsigned): `pc = pc + 1 + simm` |
| `b` | `DJNZ` | a imm | `t = r[a] - 1; r[a] = t`; if `t != 0`: `pc = pc + 1 + simm` |
| `c` | `JAL` | a b imm | `t = r[b] + imm; r[a] = pc + 1; pc = t` |
| `d` | `SEAL` | a | section 4.6 |
| `e` | `ATT` | a b c | section 6; privileged only, else fault `priv` |
| `f` | `NOP` | - | nothing |

Notes: a branch that is not taken continues at `pc + 1`; `DJNZ` tests the value after the
decrement, and on `r0` (which stays 0) it always branches; `JAL` computes its target before
it writes the link, so `JAL r1, r1, 0` jumps to the old `r1`.

### 4.3 ALU function codes

| Code | Name | `F(x, y)` |
|---|---|---|
| 0 | `ADD` | `x + y` |
| 1 | `SUB` | `x - y` |
| 2 | `AND` | `x & y` |
| 3 | `OR` | `x \| y` |
| 4 | `XOR` | `x ^ y` |
| 5 | `SHL` | `x << (y & 15)` |
| 6 | `SHR` | `x >> (y & 15)`, logical |
| 7 | `ROL` | `x` rotated left by `y & 15` |
| 8 | `MUL` | low 16 bits of `x * y` |
| 9 | `MULH` | high 16 bits of `x * y`, unsigned |
| 10 | `SLTU` | `1` if `x < y` (unsigned) else `0` |

Codes 11-15 fault (`decode`).

### 4.4 Budget

A plan may retire 65536 instructions. Before each instruction the controller checks the
count; at 65536 or more the plan ends with `OVERRUN`.

### 4.5 Loads and stores

The address is `r[b] + imm` modulo 65536, checked against the table in 3.3.

### 4.6 SEAL

`SEAL a` checks 32 cells of the recorded-profile window against the pod's sealed profile
`P[0..31]`.

- The cells are `W + r[a]` .. `W + r[a] + 31`; the cell at `W + r[a] + i` is checked
  against `P[i]`. `r[a]` must be 0 to 32; anything else faults (`span`).
- If all 32 cells equal their profile cells, the gate opens: CTL accepts stores for the
  rest of the plan. Otherwise nothing changes.
- A plan may execute SEAL once; a second SEAL faults (`reseal`).

In the bench session the window holds the bench profile at offset 0 (section 8), so `SEAL`
with `r[a] = 0` opens the gate.

## 5. HALT, the continuation word and privileged mode

When a plan executes `HALT`, the controller reads `CONT`, the word at `0x8200`.

- If bit 15 of `CONT` is set and this plan has not been resumed yet, the controller
  resumes the plan at instruction `CONT & 0x7fff`, in **privileged** mode, with registers
  and memory unchanged. The HALT retires 1. If that instruction is outside the plan, the
  HALT faults (`resume`).
- Otherwise the plan ends: `SETTLED`.

A plan is resumed at most once; after that every `HALT` ends it.

## 6. ATT and the attestation chain

The thaw monitor keeps a chain state `(X, Y)`, which starts at `(x0, y0)` from BOOT, a
round counter starting at 0, and at most one outstanding challenge `N[0..3]` (four 16-bit
words). `ATT a, b, c` does this:

1. If a challenge is outstanding, `(r[b], r[c])` is the plan's answer to it. The monitor
   computes `(X', Y') = fold(X, Y, N)`. If `r[b] != X'` or `r[c] != Y'` the plan ends:
   `REJECT`. Otherwise `(X, Y) = (X', Y')` and the round counter goes up by one; when it
   reaches 4 the plan ends: `THAWED`, and the answer line carries the thaw key.
2. The monitor draws a fresh challenge, writes it to MBOX `0x8100`..`0x8107` as four
   big-endian words (`N[0]` at `0x8100`), and sets `r[a]` to the round counter.

The first ATT of a plan only does step 2. ATT retires 1.

The fold, with `K[j] = P[2j] * 256 + P[2j+1]` for `j = 0..15` (`P` is the sealed profile
of section 4.6) and `rotl16(v, s)` rotating a 16-bit `v` left by `s & 15`:

    fold(X, Y, N):
        x = X; y = Y
        for t = 0 .. 15:
            j = (t + (y >> 12)) & 15
            x = rotl16(x ^ K[j], y & 15)
            x = (x + N[t & 3]) & 0xffff
            y = (y * 0x9e35 + x + t) & 0xffff
            y = y ^ rotl16(x, 7)
        return (x, y)

## 7. Verdicts

| Answer | When |
|---|---|
| `SETTLED <n>` | the plan halted (section 5) |
| `FAULT <n>` | an instruction faulted |
| `OVERRUN <n>` | the budget ran out |
| `REJECT <n>` | the monitor refused an answer |
| `THAWED <n> <key>` | the attestation chain is complete |

`<n>` is the number of instructions the plan retired (decimal). The answer never says which
instruction faulted or why; `frostbench.py --trace` does.

## 8. The bench

    python3 frostbench.py [--regs] [--trace]

`frostbench.py` runs one bench session on standard input and output, with the protocol of
section 2. `--regs` prints each plan's final registers and flags to standard error;
`--trace` prints every instruction it executes. The bench session's values:

| | |
|---|---|
| bench profile `P` | `a1729f19f335a4e6c3e3c96a5d192d15abfbf4030595259e5e10130ff1fa60b5` |
| window | `W = 0x9000`; cells 0-31 hold the bench profile, cells 32-63 hold `a24edd790cad642e6515118dfe8bab6b127b139e7c6c7d6b3bc9a18647ea7f1a` |
| chain origin | `x0 = 0x7b7b`, `y0 = 0x8176` |

The bench holds no thaw key: its `THAWED` carries `bench-no-key` in its place.

## 9. Conformance vectors

Each plan below was run on `frostbench.py`, and the answer and final registers shown are
what it printed (`--regs`, registers that stayed 0 omitted). They are here so you can check
an assembler against the bench.

**V01 - HALT**

    HALT

    PLAN 00000000
    -> SETTLED 1
       (all registers 0)

**V02 - two NOPs, then HALT**

    NOP
    NOP
    HALT

    PLAN f0000000f000000000000000
    -> SETTLED 3
       (all registers 0)

**V03 - running off the end of the plan**

    NOP

    PLAN f0000000
    -> FAULT 1
       (all registers 0)

**V04 - a reserved field set (LDI with b = 1)**

    (LDI r1 with field b = 1)

    PLAN 1110f548
    -> FAULT 0
       (all registers 0)

**V05 - r0 discards writes**

    LDI r0, 0x515a
    ALUI r1, r0, ADD, 3
    HALT

    PLAN 1000515a3100000300000000
    -> SETTLED 3
       r1=0003

**V06 - a taken branch skips a word**

    BEQ r0, r0, 1
    LDI r1, 1
    HALT

    PLAN 800000011100000100000000
    -> SETTLED 2
       (all registers 0)

**V07 - ALU SUB**

    LDI r1, 0x947b
    LDI r2, 0x8af6
    ALU r3, r1, r2, SUB
    HALT

    PLAN 1100947b12008af62312000100000000
    -> SETTLED 4
       r1=947b r2=8af6 r3=0985

**V08 - ALU ROL**

    LDI r1, 0x3c20
    LDI r2, 0x80af
    ALU r3, r1, r2, ROL
    HALT

    PLAN 11003c20120080af2312000700000000
    -> SETTLED 4
       r1=3c20 r2=80af r3=1e10

**V09 - ALU MULH**

    LDI r1, 0x53dc
    LDI r2, 0x0e8e
    ALU r3, r1, r2, MULH
    HALT

    PLAN 110053dc12000e8e2312000900000000
    -> SETTLED 4
       r1=53dc r2=0e8e r3=04c4

**V10 - ALUI SLTU**

    LDI r1, 0xae5f
    ALUI r3, r1, SLTU, 0x2167
    HALT

    PLAN 1100ae5f331a216700000000
    -> SETTLED 3
       r1=ae5f

**V11 - ALUI SHR**

    LDI r1, 0xccbd
    ALUI r3, r1, SHR, 0x0000
    HALT

    PLAN 1100ccbd3316000000000000
    -> SETTLED 3
       r1=ccbd r3=ccbd

**V12 - DJNZ counts down to zero**

    LDI r1, 11
    L: DJNZ r1, L
    HALT

    PLAN 1100000bb100ffff00000000
    -> SETTLED 13
       (all registers 0)

**V13 - words are big-endian**

    LDI r1, 0x4128
    STW r1, r0, 0x0100
    LDB r2, r0, 0x0100
    LDB r3, r0, 0x0101
    HALT

    PLAN 1100412871000100420001004300010100000000
    -> SETTLED 5
       r1=4128 r2=0041 r3=0028

**V14 - JAL writes pc + 1**

    NOP
    JAL r1, r0, 3
    HALT
    HALT

    PLAN f0000000c10000030000000000000000
    -> SETTLED 3
       r1=0002

**V15 - BOOT**

    LDW r1, r0, 0x8002
    LDW r2, r0, 0x8004
    LDW r3, r0, 0x8006
    HALT

    PLAN 51008002520080045300800600000000
    -> SETTLED 4
       r1=0702 r2=7b7b r3=8176

**V16 - load from the controller area**

    LDB r1, r0, 0x9424

    PLAN 41009424
    -> FAULT 0
       (all registers 0)

**V17 - store to BOOT**

    STB r0, r0, 0x8000

    PLAN 60008000
    -> FAULT 0
       (all registers 0)

**V18 - store to CTL with the gate closed**

    STW r0, r0, 0x8200

    PLAN 70008200
    -> FAULT 0
       (all registers 0)

**V19 - a word store across the end of RAM**

    LDI r1, 0xffff
    STW r1, r0, 0x7fff
    HALT

    PLAN 1100ffff71007fff00000000
    -> FAULT 1
       r1=ffff

**V20 - SEAL at offset 0, then a CTL store**

    LDI r1, 0
    SEAL r1
    STW r1, r0, 0x8202
    HALT

    PLAN 11000000d10000007100820200000000
    -> SETTLED 4
       gate

**V21 - SEAL at offset 1, then a CTL store**

    LDI r1, 1
    SEAL r1
    STW r1, r0, 0x8202
    HALT

    PLAN 11000001d10000007100820200000000
    -> FAULT 2
       r1=0001

**V22 - SEAL at offset 33**

    LDI r1, 33
    SEAL r1
    HALT

    PLAN 11000021d100000000000000
    -> FAULT 1
       r1=0021

**V23 - SEAL at offset 0xffff**

    LDI r1, 0xffff
    SEAL r1
    HALT

    PLAN 1100ffffd100000000000000
    -> FAULT 1
       r1=ffff

**V24 - a second SEAL**

    LDI r1, 0
    SEAL r1
    SEAL r1
    HALT

    PLAN 11000000d1000000d100000000000000
    -> FAULT 2
       gate

**V25 - ATT outside privileged mode**

    ATT r1, r2, r3

    PLAN e1230000
    -> FAULT 0
       (all registers 0)

**V26 - resume privileged through CONT, then one ATT**

    LDI r1, 0
    SEAL r1
    LDI r2, 0x8005
    STW r2, r0, 0x8200
    HALT
    ATT r3, r0, r0
    HALT

    PLAN 11000000d1000000120080057200820000000000e300000000000000
    -> SETTLED 7
       r2=8005  gate priv

**V27 - a resume target outside the plan**

    LDI r1, 0
    SEAL r1
    LDI r2, 0x8040
    STW r2, r0, 0x8200
    HALT

    PLAN 11000000d1000000120080407200820000000000
    -> FAULT 4
       r2=8040  gate

**V28 - a loop that never ends**

    L: BEQ r0, r0, L

    PLAN 8000ffff
    -> OVERRUN 65536
       (all registers 0)

