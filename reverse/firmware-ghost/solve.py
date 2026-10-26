#!/usr/bin/env python3
"""FIRMWARE GHOST solver.

Inputs (challenge download): config-backup.jcfg, manufacturing.pvr, uart.log
(policies are the three 64-byte r4.policy blobs embedded below; they are
extracted from the generations inside gateway-update.img).

The journal is a 6-shard GF(256) MDS container with corrupted parity; repair it,
then walk the commissioning key chain and decrypt the committed SCV3 gen-42
record.  Pure standard library.
"""
import binascii
import hashlib
import hmac
import itertools
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- AES-128 ----
SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)
RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36)

def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return r

def _expand(key):
    w = list(key)
    for i in range(4, 44):
        t = w[(i - 1) * 4:i * 4]
        if i % 4 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 4 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        w += [w[(i - 4) * 4 + j] ^ t[j] for j in range(4)]
    return w

def _encrypt_block(rk, block):
    s = list(block)
    def addrk(r):
        for i in range(16):
            s[i] ^= rk[r * 16 + i]
    addrk(0)
    for r in range(1, 11):
        s = [SBOX[x] for x in s]
        t = s[:]
        for c in range(4):
            for row in range(4):
                s[c * 4 + row] = t[((c + row) % 4) * 4 + row]
        if r != 10:
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                s[c * 4 + 0] = _mul(a[0],2) ^ _mul(a[1],3) ^ a[2] ^ a[3]
                s[c * 4 + 1] = a[0] ^ _mul(a[1],2) ^ _mul(a[2],3) ^ a[3]
                s[c * 4 + 2] = a[0] ^ a[1] ^ _mul(a[2],2) ^ _mul(a[3],3)
                s[c * 4 + 3] = _mul(a[0],3) ^ a[1] ^ a[2] ^ _mul(a[3],2)
        addrk(r)
    return bytes(s)

def aes_ctr_le32(key, iv, data):
    """CTR with a little-endian 32-bit counter in the first word (firmware form)."""
    rk = _expand(key)
    out = bytearray()
    ctr = int.from_bytes(iv[:4], "little")
    for off in range(0, len(data), 16):
        block = (ctr & 0xFFFFFFFF).to_bytes(4, "little") + iv[4:]
        ks = _encrypt_block(rk, block)
        out += bytes(a ^ b for a, b in zip(data[off:off + 16], ks))
        ctr = (ctr + 1) & 0xFFFFFFFF
    return bytes(out)

# -------------------------------------------------------- custom SHA-256 ----
# nvstored's SHA-256 uses the rotated IV below (the enrollment build uses the
# standard IV; that distinction is part of the chain).
IVROT = [0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,
         0x9b05688c,0x1f83d9ab,0x5be0cd19,0x6a09e667]
KC = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
M32 = 0xFFFFFFFF
def _ror(x, n): return ((x >> n) | (x << (32 - n))) & M32

def sha_rot(data):
    n = len(data)
    data += b"\x80" + b"\x00" * ((55 - n) % 64) + struct.pack(">Q", n * 8)
    h = list(IVROT)
    for s in range(0, len(data), 64):
        w = list(struct.unpack(">16I", data[s:s + 64]))
        for j in range(16, 64):
            s0 = _ror(w[j-15],7) ^ _ror(w[j-15],18) ^ (w[j-15] >> 3)
            s1 = _ror(w[j-2],17) ^ _ror(w[j-2],19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & M32)
        a, b, c, d, e, f, g, hh = h
        for j in range(64):
            t1 = (hh + (_ror(e,6) ^ _ror(e,11) ^ _ror(e,25)) +
                  ((e & f) ^ ((~e) & g)) + KC[j] + w[j]) & M32
            t2 = ((_ror(a,2) ^ _ror(a,13) ^ _ror(a,22)) +
                  ((a & b) ^ (a & c) ^ (b & c))) & M32
            a, b, c, d, e, f, g, hh = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
        h = [(x + y) & M32 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return struct.pack(">8I", *h)

def hmac_rot(key, msg):
    kb = key[:32].ljust(64, b"\x00")
    return sha_rot(bytes(x ^ 0x5c for x in kb) +
                   sha_rot(bytes(x ^ 0x36 for x in kb) + msg))

# ------------------------------------------------------- journal repair -----
def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 256:
            a ^= 0x12D
    return r

def repair_journal(raw):
    """Repair the 5 stripes of the 6-shard MDS container and return logical bytes."""
    inv = {a: next(b for b in range(1, 256) if _gf_mul(a, b) == 1) for a in range(1, 256)}
    entries = [struct.unpack_from("<HHIIII12s", raw, 64 + i * 32) for i in range(9)]
    logical = bytearray()
    for s in range(5):
        shards = [raw[384 + s * 384 + i * 64:384 + s * 384 + (i + 1) * 64] for i in range(6)]
        p, q = (5 - s) % 6, ((5 - s) % 6 + 1) % 6
        ds = [(q + 1 + i) % 6 for i in range(4)]
        coeff = [None] * 6
        coeff[p], coeff[q] = (1, 0), (0, 1)
        for i, d in enumerate(ds):
            coeff[d] = (1, 2 << i)
        syn = [bytearray(64), bytearray(64)]
        for i, block in enumerate(shards):
            for j, x in enumerate(block):
                syn[0][j] ^= _gf_mul(coeff[i][0], x)
                syn[1][j] ^= _gf_mul(coeff[i][1], x)
        cands = {}
        for i, j in itertools.combinations(range(6), 2):
            ai, bi = coeff[i]
            aj, bj = coeff[j]
            det = _gf_mul(ai, bj) ^ _gf_mul(aj, bi)
            ei = bytes(_gf_mul(_gf_mul(x, bj) ^ _gf_mul(y, aj), inv[det]) for x, y in zip(*syn))
            ej = bytes(_gf_mul(_gf_mul(x, bi) ^ _gf_mul(y, ai), inv[det]) for x, y in zip(*syn))
            fixed = list(shards)
            fixed[i] = bytes(a ^ c for a, c in zip(shards[i], ei))
            fixed[j] = bytes(a ^ c for a, c in zip(shards[j], ej))
            stripe = b"".join(fixed[d] for d in ds)
            contained = [e for e in entries if s * 256 <= e[3] and e[3] + e[4] <= (s + 1) * 256]
            if all(binascii.crc32(stripe[e[3] - s * 256:e[3] - s * 256 + e[4]]) & M32 == e[5]
                   for e in contained):
                cands[stripe] = (i, j)
        assert len(cands) == 1, "journal repair ambiguous"
        logical += next(iter(cands))
    assert binascii.crc32(bytes(logical)) & M32 == struct.unpack_from("<I", raw, 52)[0]
    return bytes(logical), entries

# ------------------------------------------------------------------ solve ---
POL = {
    5: bytes.fromhex("42504c34050000004119a487a77d6f78ed7400c3f16486f8aa4f1a35e7d0229b"
                     "dcfb14eb3066b50e6e4c5f7280fb50166d417ed97f2c110ca15a75e177967782"),
    6: bytes.fromhex("42504c34060000007a81768e6795c6751d25d64efe541151307a46e601e850d4"
                     "c3450067b2538a134d1e3854910d1391b696942d2e5228c03358f2b7a9d56389"),
    7: bytes.fromhex("42504c3407000000c99b7a1263ffc1b1429ec24489ee30dcee1596ddcfad8112"
                     "756d0ee6a7779a680896666374b472f7a356a59c589d8753270149632424b679"),
}
# PVR-derived DIE4 stage identities (verified against the ledger check fields)
ID0 = bytes.fromhex("8a9e520ca8279c2bd3c03223e9989813")
ID1 = bytes.fromhex("a45feaad2d4bfec0826d92b7320990fa")
ID2 = bytes.fromhex("18ac6fabb21622cb566b36862e665534")
# RTC GP[3], recovered by the 2^32 search over the stage-0 enrollment tag
GP3 = 0xB62747BC

def solve(challenge_dir: Path):
    raw = (challenge_dir / "config-backup.jcfg").read_bytes()
    pvr = (challenge_dir / "manufacturing.pvr").read_bytes()
    logical, entries = repair_journal(raw)

    recs = {}
    for t, f, g, o, ln, crc, _ in entries:
        v = logical[o:o + ln]
        assert binascii.crc32(v) & M32 == crc
        recs[(t, g)] = v
    ldr0, ldr1, ldr2 = recs[(0x21, 0)], recs[(0x21, 1)], recs[(0x21, 2)]
    scv, cmt = recs[(0x81, 42)], recs[(0x40, 42)]

    entries_pvr = {}
    count = struct.unpack_from("<H", pvr, 6)[0]
    for i in range(count):
        r = pvr[0x10 + i * 0x40:0x10 + (i + 1) * 0x40]
        entries_pvr[struct.unpack_from("<H", r, 0)[0]] = r

    ret = struct.pack("<8I", 0xeb4380fa, 0x289348e5, 0x967e358a, GP3,
                      0xf2e4ecf8, 0x88380a17, 0x6308cb25, 0x000004d2)

    # stage 0: enrollment build, standard SHA-256, seal = retention[0:16]
    k0 = hmac.new(POL[5][0x10:0x30],
                  ID0 + entries_pvr[7][0x20:0x30] + ret[:16] + struct.pack("<I", 3),
                  hashlib.sha256).digest()
    assert hashlib.sha256(k0 + b"\x00").digest()[:8] == ldr0[0x14:0x1c]

    # stage 1: migration build, rotated-IV SHA-256
    msg1 = (ldr1[0x1c:0x2c] + struct.pack("<I", struct.unpack_from("<I", ldr1, 8)[0]) +
            POL[6][0x10:0x30] + ret[0x10:0x1c] + ID1)
    k1 = hmac_rot(k0, msg1)
    assert sha_rot(k1 + b"\x01")[:8] == ldr1[0x14:0x1c]

    # stage 2: committed state
    msg2 = (ID2 + ldr2[0x1c:0x2c] + struct.pack("<I", struct.unpack_from("<I", ldr2, 8)[0]) +
            entries_pvr[12][0x20:0x30] + POL[7][0x30:0x40])
    k2 = hmac_rot(k1, msg2)
    assert sha_rot(k2 + b"\x02")[:8] == ldr2[0x14:0x1c]
    assert sha_rot(scv) == cmt[0x0c:0x2c]          # CMT4 commits to SCV3 gen 42

    # SCV3 key schedule and AES-128-CTR
    k1s = hmac_rot(POL[7][0x10:0x30], k2 + ret[:0x1c])
    k2s = hmac_rot(k1s, b"GWK7" + ID2 + struct.pack("<I", 42) + scv[0x10:0x20] + b"\x01")
    iv = sha_rot(b"CTR5" + scv[0x10:0x20] + scv[4:8] + scv[8:12])
    pt = aes_ctr_le32(k2s[:16], iv[:16], scv[0x20:0xe0])
    assert pt[:4] == b"CMAT"
    assert struct.unpack_from("<I", pt, 4)[0] == 1
    assert struct.unpack_from("<I", pt, 8)[0] == 1
    assert struct.unpack_from("<I", pt, 0xc)[0] == 42

    receipt = sha_rot(b"GWR7" + pt[0x10:0x30] + ID2 + struct.pack("<I", 42) + pt[0x30:0x40])[:16]
    return "isfcr{" + receipt.hex() + "}"

if __name__ == "__main__":
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    flag = solve(d)
    print(flag)
    assert __import__("re").fullmatch(r"isfcr\{[0-9a-f]{32}\}", flag)
