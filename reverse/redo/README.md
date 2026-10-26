---
title: "REDO"
ctf: "CryoVault Finals"
date: 2026-10-24
category: reverse
difficulty: insane
points: 500
flag_format: "isfcr{...}"
author: ""
---

# REDO

## Summary

`journal.r17` is a self-describing `R17J` container: a JSON manifest followed by
CRC32-framed records from an R17 batch controller. The log contains 200 `T`
aggregate-monitor frames, 19 quiescent `S` state snapshots, 94 commits and one
encrypted `V` capsule.

Recovering the eight physical-unit profiles from the `T` equations and
brute-forcing the controller's 576 configuration combinations against the `S`
snapshots yields a unique configuration and a unique final
`arena || route || dispatch` state. The capsule key is
`SHA256("R17/capsule/2" || state)`, the HMAC tag verifies exactly, and the
SHAKE256 stream decrypts to the receipt.

## Solution

### Step 1: Recover the unit profiles

Each `T` frame reports only the sum, modulo 65536, of two or three physical-unit
responses. The frames are paired so that one unit's input is held fixed while
the other varies, and vice versa. Differences of the totals therefore cancel
the partner's response (including its bias) and expose 24 response differences
per unit.

Brute-forcing `(family, r, flip, salt)` against those differences gives a
unique profile for every unit:

```
unit  family  r   flip  salt    bias
0     7       3   0     50019   46665
1     3       13  1     2123    34426
2     1       13  1     34386   1654
3     0       3   1     2075    14155
4     4       11  1     13440   60132
5     6       15  1     59610   35660
6     2       11  0     15861   34143
7     5       5   0     21525   27891
```

The biases are then fixed by the four pair sums and four 3-unit sums. All 200
`T` totals verify with these profiles.

### Step 2: Recover the controller configuration

The controller has eight global domains: `address_binding` (3), `dispatch_binding`
(3), `forward_reads`, `live_writeback`, `restore_metadata`, `reverse_issue`,
`source_at_begin`, `swap_routes` — 576 combinations.

For each candidate, simulate the log from the first `S` snapshot. Comparing the
result against all 18 later quiescent `S` snapshots leaves exactly one match:

```
address_binding=2  dispatch_binding=1
forward_reads=1    live_writeback=1
restore_metadata=0 reverse_issue=1
source_at_begin=1  swap_routes=0
```

The first binding is the "first-use lease" mode; reads see the scratch copy,
writes update the live output, and the queued operations are issued
back-to-front.

### Step 3: Derive the capsule key and decrypt

After simulating the final `tid=62000` transaction, the controller state is 104
bytes: `arena u16le[32] || route[32] || dispatch[8]`. The capsule header itself
specifies the rest:

```python
state = pack("<32H", *arena) + bytes(route) + bytes(dispatch)
key   = sha256(b"R17/capsule/2" + state).digest()

nonce, tag = v[:24], v[-32:]
ct = v[24:-32]
assert hmac.new(key, nonce + ct, sha256).digest() == tag

stream = hashlib.shake_256(key + nonce).digest(len(ct))
receipt = bytes(a ^ b for a, b in zip(ct, stream)).decode()
```

The HMAC tag matches exactly, which both validates the reconstructed state and
proves the receipt. The complete standalone solver — frame parsing, profile
verification, configuration brute-force, simulation and capsule decryption — is
`solve.py` in this folder.

## Flag

```
isfcr{70c2a6dd54ad43fe43383df42957b7e56119155f82a2bbe9}
```
