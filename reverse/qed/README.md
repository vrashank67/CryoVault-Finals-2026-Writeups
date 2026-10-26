---
title: "Q.E.D. — Prove the Impossible"
ctf: "CryoVault Finals"
date: 2026-10-24
category: reverse
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "solver"
---

# Q.E.D. — Prove the Impossible

## Summary

`qedvm` is a small Rust proof checker for intuitionistic propositional logic (QPL).
The inference rules themselves are sound, but the `case` rule is memoised in a
hash map whose cache key fingerprints the local context only by
`(length, first assumption, last assumption)` — the assumptions in the *middle*
of the context are not part of the key. Because terms are hash-consed, the exact
same `case` term can be checked once in `[top, bot, top]` (genuine, using the
`bot` assumption) and then accepted without checking in `[top, top, top]`
(spurious cache hit). Wrapping that term in lambdas yields
`top → top → top → bot`, which is then applied to three `tt` proofs to derive
`bot` in the empty context.

## Solution

### Step 1: Reverse the verifier and find the memo key

`qedvm` is a stripped static-PIE Rust binary. Loading it in Ghidra and following
the `case` handler (`FUN_001124b0` at file offset `0x124b0`) shows that, for a
`case` node with `aux[term] >= 11`, the checker probes a map before checking:

```
cmp ebp,   [entry-0xc]    ; case-node term id  (stale reg = term id, NOT f2)
cmp r14d,  [entry-8]      ; expected formula id
cmp r13d,  [entry-4]      ; local context length
cmp word [entry-0x1c], 1  ; "non-empty context"
cmp r12d,  [entry-0x18]   ; LC[0]   = first (outermost) assumption
cmp word [entry-0x14], 1
cmp r10d,  [entry-0x10]   ; LC[len-1] = last (innermost) assumption
```

A hit returns success immediately. The key never mentions the middle
assumptions (`LC[1..len-2]`). Terms are hash-consed, so the same source term has
the same id everywhere: the same `case` term can inherit a success proved in a
different context of the same length with the same endpoints.

### Step 2: Build the two contexts and apply

`T = (case top (atom q) (inl tt) BIG BIG)` where `BIG` proves `bot` from
`(var 2)` (padded so `aux(T) >= 11`).

* `p1 : top → bot → top → bot` checks `T` under `[top, bot, top]` genuinely
  (`var 2` is the `bot` assumption) and caches the success.
* `p2 : top → top → top → bot` reuses the identical term id under
  `[top, top, top]`; the endpoints (`top`, `top`), length (3) and expected
  formula (`bot`) match, so the checker skips the body and accepts it.
* `(app top (app top (app top (ref p2) tt) tt) tt) : bot`.

### Step 3: Solve script

```python
#!/usr/bin/env python3
"""Q.E.D. — Prove the Impossible (CryoVault Finals 2026).

The kernel memoises `case` checks keyed by (context length, first assumption,
last assumption, case-term id, expected formula) — the middle of the context is
ignored.  Share one hash-consed `case` term between two contexts with the same
length/endpoints to turn a proof under `bot` into a proof in the empty context.
"""
import socket, sys, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "0.cloud.chals.io"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 24225
PAD = 12  # case aux (node count) must be >= 11 to use the memo path


def big_bot(k, depth):
    """Term of type bot under a context where (var k) : bot; aux == depth."""
    t = f"(var {k})"
    for _ in range(depth):
        t = f"(snd top (pair tt {t}))"
    return t


def build_module(nonce):
    big = big_bot(2, PAD)
    case = f"(case top (atom q) (inl tt) {big} {big})"   # ONE shared term
    return f"""(module qed1 {nonce}
  (def p1
    (imp top (imp bot (imp top bot)))
    (lam top (lam bot (lam top {case}))))
  (def p2
    (imp top (imp top (imp top bot)))
    (lam top (lam top (lam top {case}))))
  (def go bot
    (app top (app top (app top (ref p2) tt) tt) tt))
  (export go))
""".encode()


def recv_until(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)
    banner = recv_until(s, 3.0)
    sys.stderr.write(banner.decode(errors="replace"))
    m = re.search(rb"nonce\s+([0-9a-fA-F]{32})", banner)
    if not m:
        return 1
    module = build_module(m.group(1).decode())
    s.sendall(module)
    s.sendall(b"\n.qed\n")
    out = recv_until(s, 8.0).decode(errors="replace")
    s.close()
    sys.stderr.write(out)
    flag = re.search(r"isfcr\{[^}]*\}", out)
    if flag:
        print(flag.group(0))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

Local verification with the shipped checker (same module, dummy nonce):

```console
$ python3 gen.py 00000000000000000000000000000000 12 > exp/e1.qed
$ ./qedvm exp/e1.qed
ACCEPT
```

Remote run:

```console
$ python3 solve.py
[*] nonce ae001ded6c2fc21e24cbc015668567c3, module 1344 bytes
ACCEPT
isfcr{5h4p3_15_n07_c0n73n7_00799bea4d4f3d183abe0ee7}
```

## Flag

```
isfcr{5h4p3_15_n07_c0n73n7_00799bea4d4f3d183abe0ee7}
```
