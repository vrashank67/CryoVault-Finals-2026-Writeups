---
title: CUTLINE
ctf: null
date: 2026-10-24
category: reverse engineering
points: 500
flag_format: isfcr{...}
author: ""
---

# CUTLINE

## Summary

The APK contains a SQLite archive and a recovery-code checker. Recovering a solution to its modular linear constraints produces the AES-GCM key that opens the encrypted receipt.

## Solution

Extract `classes.dex` and `assets/archive.db` from the APK. Disassembling the DEX reveals that `a.e` reads 112 transformation records and 24 checkpoint records from Android Parcel blobs stored in SQLite. The database query orders these records by handle, which must be preserved when replaying the scheduler.

The recovery code is 256 hexadecimal characters: 64 unsigned values below 65521. Each transformation updates one coordinate as `x[dst] += multiplier*x[src] + constant`, modulo 65521. Four lane clocks and dependency vectors determine the execution order.

Each checkpoint checks three dot products after replaying its selected transformations. It accepts either the complete replay or a replay that omits one designated update. Both replays still advance the scheduler clocks.

Represent every replay as an affine matrix. The difference between the two checkpoint alternatives has rank one, so eliminating that difference yields two shared linear equations per checkpoint. These provide 48 independent constraints. Reduce the remaining branch equations to the 16 free coordinates, then search the binary choices using incremental modular elimination and reject inconsistent branches immediately.

Serialize the recovered coordinates as 64 little-endian shorts. The AES key is SHA-256 of `cutline/recovery/v1\0` followed by those bytes. The receipt begins with a 12-byte nonce; its remainder is ciphertext and a 16-byte GCM tag. The authenticated additional data is `cutline/archive/v1`.

## Reproduce

Requires Python and `cryptography`:

```powershell
python solve.py cutline.apk
```

## Verification

All 24 checkpoint checks passed, and AES-GCM authentication succeeded.

Input SHA-256: `cf03524595bb5e79e2491b76c1b1787fabc33df652dafa6059b9823148e83301`.

Submission: not submitted; no competition destination was established in this session.

## Flag

```text
isfcr{32175c64a486f66f3cd9321052115edbe762cfbdfba599fd}
```
