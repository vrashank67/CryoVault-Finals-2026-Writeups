#!/usr/bin/env python3
"""GLACIER SERVICE CARD - CryoVault Finals 2026 (reverse, 500).

Full solve from the shipped artifacts:
  1. emulate the FPC-3 nanoword store (cradle.nano, 128 x 7-byte words, rev C layout)
  2. run power-on -> service code (28 EMIT bytes, checked against the 'lx' pair on the card)
  3. assert PAIR at the HALT word, follow its NSEQ branch -> 6 pairing bytes -> release code
  4. open release.lock with escrow.py's scheme (sequential squaring, ~480M steps, ~12 min)

usage: python solve.py [--no-chain]
needs: pip install gmpy2   (strongly recommended: 480M 2048-bit squarings)
"""
import hashlib
import json
import os
import sys

try:
    import gmpy2

    def _sqrsteps(x, k, n):
        return int(gmpy2.powmod(gmpy2.mpz(x), gmpy2.mpz(1) << k, gmpy2.mpz(n)))
except ImportError:  # several times slower
    def _sqrsteps(x, k, n):
        return pow(x, 1 << k, n)

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(HERE, "..", "..", "challenges", "glacier-service-card", "input")


# ---------------------------------------------------------------- FPC-3 core
def crc8(bs):
    c = 0
    for b in bs:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c


def decode(w):
    return dict(ASEL=(w >> 52) & 15, BSEL=(w >> 48) & 15, DSEL=(w >> 44) & 15,
                FOP=(w >> 40) & 15, BSRC=(w >> 39) & 1, ASRC=(w >> 38) & 1,
                DWE=(w >> 37) & 1, FLE=(w >> 36) & 1, CIN=(w >> 35) & 1,
                MEMOP=(w >> 32) & 7, SPEC=(w >> 29) & 7, LIT=(w >> 21) & 0xFF,
                NCOND=(w >> 18) & 7, NSEQ=(w >> 16) & 3, NTARG=(w >> 8) & 0xFF,
                NCRC=w & 0xFF)


class Nano:
    def __init__(self, image):
        assert len(image) == 896, "store image must be 128 x 7 bytes"
        self.w = [int.from_bytes(image[7 * i:7 * i + 7], "big") for i in range(128)]
        self.R = [0] * 16
        self.C = self.Z = self.N = self.V = 0
        self.MAR = self.MDR = 0
        self.ls = bytearray(256)
        self.latch = bytearray()
        self.halted = False

    def s8(self, x):
        return x - 256 if x > 127 else x

    def step(self, na):
        d = decode(self.w[na])
        if crc8(self.w[na].to_bytes(7, "big")[:6]) != d["NCRC"]:
            raise RuntimeError("NANOTRAP: bad NCRC at %02X" % na)
        A = self.MDR if d["ASRC"] else self.R[d["ASEL"]]
        B = d["LIT"] if d["BSRC"] else self.R[d["BSEL"]]
        fop, cin = d["FOP"], d["CIN"]
        C = V = 0
        if fop == 0x0:
            res = A
        elif fop == 0x1:
            res = B
        elif fop in (0x2, 0x3):
            s = A + B + (cin if fop == 0x3 else 0)
            res, C = s & 0xFF, int(s > 0xFF)
            V = int(not -128 <= self.s8(A) + self.s8(B) + (cin if fop == 0x3 else 0) <= 127)
        elif fop in (0x4, 0x5):
            s = A - B - (cin if fop == 0x5 else 0)
            res = s & 0xFF
            C = int(A < B + (cin if fop == 0x5 else 0))
            V = int(not -128 <= self.s8(A) - self.s8(B) - (cin if fop == 0x5 else 0) <= 127)
        elif fop == 0x6:
            res = A & B
        elif fop == 0x7:
            res = A | B
        elif fop == 0x8:
            res = A ^ B
        elif fop == 0x9:
            res = A & (~B & 0xFF)
        elif fop == 0xA:
            res = ~A
        elif fop == 0xB:
            res, C = (A << 1), (A >> 7) & 1
        elif fop == 0xC:
            res, C = A >> 1, A & 1
        elif fop == 0xD:
            res, C = (A << 1) | (A >> 7), (A >> 7) & 1
        elif fop == 0xE:
            res, C = (A >> 1) | ((A & 1) << 7), A & 1
        else:
            res = (A << 4) | (A >> 4)
        res &= 0xFF
        if d["DWE"]:
            self.R[d["DSEL"]] = res
        if d["FLE"]:
            self.C, self.Z, self.N, self.V = C, int(res == 0), (res >> 7) & 1, V
        if d["MEMOP"] == 1:
            self.MDR = self.ls[self.MAR]
        elif d["MEMOP"] == 2:
            self.ls[self.MAR] = res
        elif d["MEMOP"] == 3:
            self.MAR = res
        elif d["MEMOP"] > 3:
            raise RuntimeError("NANOTRAP: MEMOP")
        sp = d["SPEC"]
        if sp == 2:
            self.latch.append(res & 0xFF)          # EMIT
        elif sp not in (0, 1, 4):
            raise RuntimeError("NANOTRAP: SPEC")
        if sp == 4:
            self.halted = True                     # HALT, stop after this word
        nq = d["NSEQ"]
        if nq == 0:
            return na + 1
        if nq == 1:
            ok = [True, self.C == 1, self.C == 0, self.Z == 1, self.Z == 0,
                  self.N == 1, self.V == 1, False][d["NCOND"]]
            return d["NTARG"] if ok else na + 1
        if nq == 2:
            return d["NTARG"]
        raise RuntimeError("NANOTRAP: NSEQ 3")

    def run(self, pc):
        for _ in range(1 << 20):
            nxt = self.step(pc)
            if self.halted:
                return pc
            pc = nxt
        raise RuntimeError("runaway")


def sym_value(c):
    return int(c) if c.isdigit() else (ord(c) - 87 if c.isalpha() else 36)


def sym_char(x):
    return str(x) if x < 10 else (chr(87 + x) if x < 36 else "_")


def main():
    image = open(os.path.join(INPUT, "cradle.nano"), "rb").read()
    m = Nano(image)

    # power-on run; snapshot the datapath on completion of nanoword 0x0E (section 4)
    pc, snap = 0x00, None
    while True:
        cur, pc = pc, m.step(pc)
        if cur == 0x0E:
            snap = ([m.R[i] for i in range(8, 16)], m.C)
        if m.halted:
            halt = cur
            break
    service_code = bytes(m.latch).decode()
    print("HALT at nanoword 0x%02X" % halt)
    print("self-test R8..R15 + C: %s %d" % (" ".join("%02X" % v for v in snap[0]), snap[1]))
    assert snap == ([0x00, 0x00, 0x00, 0x57, 0x00, 0xB8, 0x00, 0xFF], 0)
    print("service code (%d bytes): %s" % (len(service_code), service_code))
    v = [sym_value(c) for c in service_code]
    P, Q = sum(v) % 37, sum((i + 1) * v[i] for i in range(len(v))) % 37
    print("check pair: %s%s (card stamps 'lx')" % (sym_char(P), sym_char(Q)))
    assert (sym_char(P), sym_char(Q)) == ("l", "x")

    # PAIR: latch cleared, registers and flags held at the HALT word
    m.latch.clear()
    m.halted = False
    d = decode(m.w[halt])
    nq = d["NSEQ"]
    if nq == 0:
        resume = halt + 1
    elif nq == 1:
        ok = [True, m.C == 1, m.C == 0, m.Z == 1, m.Z == 0, m.N == 1, m.V == 1, False][d["NCOND"]]
        resume = d["NTARG"] if ok else halt + 1
    else:
        resume = d["NTARG"]
    m.run(resume)
    pairing = bytes(m.latch)
    code = "FL-" + "-".join(pairing.hex().upper()[i:i + 4] for i in (0, 4, 8))
    print("pairing bytes: %s -> release code %s" % (pairing.hex().upper(), code))
    assert len(pairing) == 6

    if "--no-chain" in sys.argv:
        return 0

    # ------------------------------------------------------------ escrow
    lock = json.load(open(os.path.join(INPUT, "release.lock")))
    n, t = int(lock["n"], 16), int(lock["t"])
    salt = bytes.fromhex(lock["salt"])
    norm = "".join(code.split()).upper().encode()
    h = b"".join(hashlib.sha512(salt + i.to_bytes(4, "big") + norm).digest() for i in range(5))
    x = int.from_bytes(h, "big") % n
    print("running %d squaring steps mod a %d-bit N (~12 min)" % (t, n.bit_length()))
    done = 0
    while done < t:
        step = min(1 << 20, t - done)
        x = _sqrsteps(x, step, n)
        done += step
        print("\r  %5.1f%%" % (100 * done / t), end="", flush=True)
    print()

    width = (n.bit_length() + 7) // 8
    key = hashlib.sha256(b"frostline-escrow-key" + x.to_bytes(width, "big")).digest()
    ct = bytes.fromhex(lock["sealed"])
    tag = hashlib.sha256(b"frostline-escrow-tag" + key + ct).hexdigest()[:32]
    assert tag == lock["tag"], "wrong release code"
    ks = b""
    ctr = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(key + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    text = bytes(a ^ b for a, b in zip(ct, ks)).decode()
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
