---
title: "GLACIER SERVICE CARD"
ctf: "CryoVault Finals"
date: 2026-10-24
category: reverse
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "solo"
---

# GLACIER SERVICE CARD

## Summary

The artifacts describe a custom 56-bit "nanoword" microsequencer (Frostline FPC-3) and a time-lock escrow
that only opens with a release code derived from that hardware. Emulating the 128-word store in `cradle.nano`
from the datasheet rules yields the 28-byte service code (confirmed by the card's `lx` check pair) and, after
asserting PAIR at the HALT word, the six pairing bytes that spell the release code. The escrow itself is a
vanilla RSW time-lock: 480,000,000 sequential squarings modulo a 2048-bit unfactorable N (~12 min with gmpy2).

## Solution

### Step 1: Rebuild the FPC-3 and read the release code out of `cradle.nano`

`cradle.nano` is exactly 128 × 7 = 896 bytes, the store image described in the card. Nanoword 0x00 decodes
with `SPEC = STAMP` and `LIT = 0x0C`, so the image is **rev C** silicon: LIT is 8 bits at [28:21], NCOND at
[20:18], NSEQ at [17:16], NTARG at [15:8], and NCRC (CRC-8/poly 0x07 over bits [55:8]) stays at [7:0].
Rev C also takes ADC/SBC carry-in from the word's CIN bit, not the latched C flag.

Two independent on-card checks prove the emulator is right:

- after nanoword 0x0E the self-test gives `R8..R15 = 00 00 00 57 00 B8 00 FF`, `C = 0` (section 4);
- the 28 EMIT bytes `2wi699afn8od4698zxpzhhr8rs4d` give `P = l, Q = x`, exactly the "check pair as stamped"
  for the Pod 7 head (section 5).

At the HALT word 0x36 the flags are held with `N = 1` and the word's NSEQ is `BR / NCOND=N=1 / NTARG=0x4B`,
so PAIR resumes at 0x4B (not at 0x37 — that is the dead branch, and the FF hole at words 0x45-0x4A is a
NANOTRAP). The 13-word routine there EMITs `F5 85 FF FF 40 38`, giving the release code
`FL-F585-FFFF-4038`.

### Step 2: Open the escrow lock

`escrow.py` is a textbook Rivest-Shamir-Wagner time-lock: `x = SHA-512(salt || code) mod N`, then
`x <- x^(2^T) mod N` for T = 480,000,000, and the final value keys a SHA-256 stream that decrypts `sealed`
(the `tag` is the authenticity check). N is a 2048-bit composite with no small factors, so there is no
fast-forward: the squarings must actually be run. gmpy2 does ~700k mod-squarings/s here, so the whole chain
is about 12 minutes, and `solve.py` does it inline. The progress-file trick in `escrow.py` is only a
convenience; the parameter set exposes no shortcut (t is bound to the code only through the tag).

```python
# solve.py (repo: writeups/glacier-card-escrow/solve.py) -- condensed
import hashlib, json, os, gmpy2

def crc8(bs):
    c = 0
    for b in bs:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

def decode(w):                       # rev C field layout
    return dict(ASEL=(w>>52)&15, BSEL=(w>>48)&15, DSEL=(w>>44)&15, FOP=(w>>40)&15,
                BSRC=(w>>39)&1, ASRC=(w>>38)&1, DWE=(w>>37)&1, FLE=(w>>36)&1,
                CIN=(w>>35)&1, MEMOP=(w>>32)&7, SPEC=(w>>29)&7, LIT=(w>>21)&0xFF,
                NCOND=(w>>18)&7, NSEQ=(w>>16)&3, NTARG=(w>>8)&0xFF, NCRC=w&0xFF)

class Nano:
    def __init__(self, image):
        self.w = [int.from_bytes(image[7*i:7*i+7], "big") for i in range(128)]
        self.R = [0]*16; self.C=self.Z=self.N=self.V=0
        self.MAR=self.MDR=0; self.ls=bytearray(256)
        self.latch=bytearray(); self.halted=False

    def step(self, na):
        d = decode(self.w[na])
        assert crc8(self.w[na].to_bytes(7, "big")[:6]) == d["NCRC"], "NANOTRAP"
        A = self.MDR if d["ASRC"] else self.R[d["ASEL"]]
        B = d["LIT"] if d["BSRC"] else self.R[d["BSEL"]]
        f, cin, s8 = d["FOP"], d["CIN"], lambda v: v-256 if v > 127 else v
        C = V = 0
        if   f == 0x0: res = A
        elif f == 0x1: res = B
        elif f in (0x2,0x3):
            t = A + B + (cin if f == 0x3 else 0); res, C = t & 0xFF, int(t > 0xFF)
            V = int(not -128 <= s8(A)+s8(B)+(cin if f == 0x3 else 0) <= 127)
        elif f in (0x4,0x5):
            res = (A - B - (cin if f == 0x5 else 0)) & 0xFF
            C = int(A < B + (cin if f == 0x5 else 0))
            V = int(not -128 <= s8(A)-s8(B)-(cin if f == 0x5 else 0) <= 127)
        elif f == 0x6: res = A & B
        elif f == 0x7: res = A | B
        elif f == 0x8: res = A ^ B
        elif f == 0x9: res = A & (~B & 0xFF)
        elif f == 0xA: res = ~A
        elif f == 0xB: res, C = A << 1, (A >> 7) & 1
        elif f == 0xC: res, C = A >> 1, A & 1
        elif f == 0xD: res, C = (A << 1) | (A >> 7), (A >> 7) & 1
        elif f == 0xE: res, C = (A >> 1) | ((A & 1) << 7), A & 1
        else:          res = (A << 4) | (A >> 4)
        res &= 0xFF
        if d["DWE"]: self.R[d["DSEL"]] = res
        if d["FLE"]: self.C, self.Z, self.N, self.V = C, int(res == 0), (res >> 7) & 1, V
        if d["MEMOP"] == 1: self.MDR = self.ls[self.MAR]
        elif d["MEMOP"] == 2: self.ls[self.MAR] = res
        elif d["MEMOP"] == 3: self.MAR = res
        if d["SPEC"] == 2: self.latch.append(res)          # EMIT
        if d["SPEC"] == 4: self.halted = True              # HALT
        nq = d["NSEQ"]
        if nq == 0: return na + 1
        if nq == 1:
            ok = [True, self.C == 1, self.C == 0, self.Z == 1, self.Z == 0,
                  self.N == 1, self.V == 1, False][d["NCOND"]]
            return d["NTARG"] if ok else na + 1
        return d["NTARG"]                                  # JMP

m = Nano(open("cradle.nano", "rb").read())
pc, snap = 0, None
while True:
    cur, pc = pc, m.step(pc)
    if cur == 0x0E: snap = ([m.R[i] for i in range(8, 16)], m.C)   # self test
    if m.halted: halt = cur; break
assert snap == ([0, 0, 0, 0x57, 0, 0xB8, 0, 0xFF], 0)
code = bytes(m.latch).decode()
print("service code:", code)                 # 2wi699afn8od4698zxpzhhr8rs4d
assert code == "2wi699afn8od4698zxpzhhr8rs4d"

m.latch.clear(); m.halted = False            # assert PAIR at the HALT word
d = decode(m.w[halt]); assert (d["NSEQ"], d["NTARG"]) == (1, 0x4B) and m.N == 1
m.run(0x4B)                                  # follows the halted word's branch
pair = bytes(m.latch)
release = "FL-" + "-".join(pair.hex().upper()[i:i+4] for i in (0, 4, 8))
print(release)                               # FL-F585-FFFF-4038

lock = json.load(open("release.lock"))
n, t, salt = int(lock["n"], 16), int(lock["t"]), bytes.fromhex(lock["salt"])
norm = "".join(release.split()).upper().encode()
x = int.from_bytes(b"".join(hashlib.sha512(salt + i.to_bytes(4, "big") + norm).digest()
                            for i in range(5)), "big") % n
for done in range(0, t, 1 << 20):             # 480M squarings, ~12 min
    x = int(gmpy2.powmod(gmpy2.mpz(x), gmpy2.mpz(1) << (1 << 20), gmpy2.mpz(n)))
w = (n.bit_length() + 7) // 8
key = hashlib.sha256(b"frostline-escrow-key" + x.to_bytes(w, "big")).digest()
ct = bytes.fromhex(lock["sealed"])
assert hashlib.sha256(b"frostline-escrow-tag" + key + ct).hexdigest()[:32] == lock["tag"]
ks = b"".join(hashlib.sha256(key + c.to_bytes(8, "big")).digest() for c in range(9))[:len(ct)]
print(bytes(a ^ b for a, b in zip(ct, ks)).decode())
```

Output (the real `solve.py` in this folder does the same, simply with a proper 1 MB chunk loop):

```text
HALT at nanoword 0x36
self-test R8..R15 + C: 00 00 00 57 00 B8 00 FF 0
service code (28 bytes): 2wi699afn8od4698zxpzhhr8rs4d
check pair: lx (card stamps 'lx')
pairing bytes: F585FFFF4038 -> release code FL-F585-FFFF-4038
running 480000000 squaring steps mod a 2048-bit N (~12 min)
Release approved by Frostline escrow, pod 7 re-pair authority: isfcr{4o5sf7cwpxkm9wewxqdjy9sh}
```

The dead branch was checked as a control: resuming at 0x37 would yield `FL-E200-7CF2-3479`, which the escrow
rejects after its full chain ("release refused: that code does not open this lock"), so the NSEQ-following
rule in section 7 is load-bearing, not cosmetic.

## Flag

```
isfcr{4o5sf7cwpxkm9wewxqdjy9sh}
```
