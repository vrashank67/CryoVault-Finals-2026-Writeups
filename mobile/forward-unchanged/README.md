---
title: Forward Unchanged
ctf: CryoVault Finals
date: 2026-10-24
category: mobile
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# Forward Unchanged

## Summary

The archive contains three Android APKs (`intake`, `relay`, `archive`), a sealed
note (`note.bin`), a 128-byte `sample.req` and `transfer.py`. The request is the
key material for the note (`HMAC(salt, request)` → AES-256-GCM), so the flag can
only be recovered by reconstructing the exact 128-byte "recovery message" that
all three endpoints accept.

All three APKs share the same `classes.dex`; only `assets/p.dat` differs. Each
`p.dat` holds a stage id `s` (1/2/3), an anchor record, two data-dependent plan
arrays, a key schedule `k`, salts, a matrix and a `want` array. An endpoint
gathers a subset of the request's 32 little-endian words (8 records of 4 words),
runs them through `C.c` and compares the result with `want`.

The twist is in the `Parcelable` code: every record read out of a `Parcel` is
passed through `C.b(record, mode)`, where `mode` is the parcel tag of that
record. Because Android `Bundle` values are lazy, **records an endpoint never
touches are copied byte-for-byte into the next blob** with their old tag and
values ("forward unchanged"). So the relay does not see a uniformly transformed
request: some records are the intake's transformed values (mode 1), others are
still the raw request (mode 0). The archive sees a mixture of modes 0, 1 and 2.

The resulting 32 constraints are invertible: `C.c` and `C.b` use only `+`,
multiplication by a constant, `^` and `<<`, so bit *b* of every value depends
only on input bits ≤ *b*. Solving plane by plane over GF(2) recovers the unique
request, which decrypts the note.

## Solution

**1. Reversing the endpoints.** `jadx`/`apktool` show identical code in all
three APKs:

* `C.a` loads `assets/p.dat` (magic `FWP2` / `844126022`).
* `Endpoint.b` reads 128 bytes as 32 LE words into 8 `R` records, marshals the
  bundle and immediately unmarshals it again.
* `R(Parcel)` reconstructs a record and applies `this.v = C.b(iArr, mode)`.
* `Endpoint` picks `plans[(v[2] ^ rotl(v[0], 9)) & 1]` from its anchor record,
  gathers 4 words per plan entry, computes `C.c` and compares with `want`.
* The (possibly failing) bundle is re-marshalled and forwarded as `blob`.

`R.writeToParcel` uses tag `0` for fresh objects and `C.s` otherwise, and the
`C.b` transform is skipped only when `mode == s`. Hence intake reads tag 0
(`C.b_intake(·,0)`), the relay reads tag 1 (`C.b_relay(·,1)`) and the archive
reads tag 2 (`C.b_archive(·,2)`).

**2. The lazy-Bundle leak.** Dumping the real blob produced by the intake on an
emulator showed *mixed* tags: records the intake read are mode 1 (transformed),
records it never read are still mode 0 with the raw request words. Android
unparcels `Parcelable` values lazily, and `Bundle.writeToParcel` writes untouched
values from their original parcelled bytes. Consequently:

* intake reads anchor 0 plus its plan groups → `b1[g] = C.b_intake(w[g], 0)`
* relay reads anchor 6 plus its plan groups, applying `C.b_relay(·, mode)` with
  each record's stored tag (1 for groups the intake touched, 0 otherwise)
* archive reads all its plan groups, applying `C.b_archive(·, mode)` with tags
  2 (touched by relay), 1 (touched only by intake) or 0 (untouched)

This model was validated against the three real APKs running on an Android
emulator: for an arbitrary request, the simulated receipts matched the device
output exactly for all three stages.

**3. Inverting the fingerprints.** With the plan bits guessed (8 combinations),
the 11 + 11 + 10 = 32 equations are exactly determined in the 32 unknown words.
Every operation is left-shifting, so the system is triangular by bit position and
becomes an affine GF(2) system when solved LSB-first plane by plane. Gaussian
elimination per plane recovers the request; the note's GCM tag confirms it.

Core of the solver (full script in `solve.py`):

```python
def plane_solve(piv, free_assign, bv, x):
    out = [0] * 32
    for f, v in free_assign.items():
        out[f] = v
    for p in sorted(piv):
        m, r = piv[p]
        v = r
        mm = m & ~(1 << p)
        while mm:
            q = mm.bit_length() - 1
            v ^= out[q]
            mm ^= (1 << q)
        out[p] = v
    nx = list(x)
    for i in range(32):
        if out[i]:
            nx[i] |= 1 << bv
    return nx

def solve_combo(S, sel, limit=4):
    out = []
    def rec(bv, x):
        if len(out) >= limit:
            return
        if bv == 32:
            out.append(list(x)); return
        piv = eliminate(model_rows(S, sel, bv, x))   # affine equations, plane bv
        if piv is None:
            return
        free = [i for i in range(32) if i not in piv]
        if not free:
            rec(bv + 1, plane_solve(piv, {}, bv, x)); return
        for ch in range(1 << len(free)):
            fa = {f: (ch >> j) & 1 for j, f in enumerate(free)}
            rec(bv + 1, plane_solve(piv, fa, bv, x))
    rec(0, [0] * 32)
    return out

for sel in itertools.product([0, 1], repeat=3):
    for x in solve_combo(S, sel):
        req = b''.join(struct.pack('<I', w) for w in x)
        # req must satisfy all three endpoints and the note's GCM tag
```

The winning plan combination is `(intake 0, relay 1, archive 0)`. The recovered
request is

```
5bf263fbc0853d1e161ad96955821bce243383aba97f94536d0d1739c890dbba
1e7906acf468ecabef92786cb2f5203a892d23dc0366c156624a203382a760eb
5fba9c873964e310acd1ba80ab93abe93f81b76d1ae5e56ab2c10acc4fc8a43
73bd4976b86b58d62fa2cf8908528bacbefa2812b66e970de3bb0cfb57faf0ef1
```

Feeding it through the three APKs on the emulator returns `ok = true` from
`intake`, `relay` and `archive`, and the key `HMAC(salt, request)` derived
exactly as `transfer.py` does decrypts `note.bin`.

## Flag

```
isfcr{4ea71ebfcaff133619fa18ffb69d946f372509ea82a29497}
```
