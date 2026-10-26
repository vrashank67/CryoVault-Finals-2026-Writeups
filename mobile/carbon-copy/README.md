---
title: "Carbon Copy"
ctf: "CryoVault Finals"
date: 2026-10-24
category: mobile
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: "solo"
---

# Carbon Copy

## Summary

`carbon-copy.apk` ships `assets/archive.ccb`, a `CCB2` container whose 64-byte recovery key is
validated by a custom 2992-instruction bytecode VM against a 240-byte digest. That key opens an
AES-256-GCM "note archive" (144 CRDT blocks); the flag is a second GCM layer keyed by the first key
plus `key2`, the app's `Local note saved.` hash of the merged note.

## Solution

### Step 1: Read the container and the check code (`j.java`, `i.java`, `g.java`)

`Desk.onCreate()` loads `archive.ccb` into `j`, whose layout is:

```
"CCB2\r\n\x1a\n" | u16 64 | salt[16] | prog(len-prefixed) | digest (240 B) |
entry_ct (len-prefixed) | flag_ct (len-prefixed)
```

`j.a(key64)` accepts the key only if

```java
MessageDigest.isEqual(this.c, i.b(this.b, this.a, key))   // VM(prog, salt, key) == digest
```

and then returns `AESGCM(SHA256("CC-A2\0" + key + salt), aad = SHA256(prog+digest+salt))` applied to
`entry_ct`. `j.f("key:key2")` derives the flag key as
`SHA256("CC-F2\0" + key + key2 + SHA256(entry_plaintext))` with
`aad = SHA256(SHA256(prog+digest+salt) + entry_ct)`.

The second half of the recovery code is the value the app prints from its *New local note* button:
`SHA256("CC-R2\0" + LE16(note chars))` (`g.f`). So the job is: recover `key`, rebuild the note to get
`key2`, decrypt.

### Step 2: Recover the 64-byte key from the VM digest

The VM state is an 8x8 byte matrix initialised from the key. Every primitive in `i.a` is built from
`+`, `^` and multiplication by a constant (including the Newton-iteration inverse), so **bit *p* of any
value depends only on key bits <= *p***. Each bit-plane is therefore a linear system over GF(2): 64
unknowns (one bit per key byte) and 240 equations from the emitted bytes. The only data-dependent
choice is `EMITCP`, which either aliases or clones a row (48 decisions); a prefix DFS with 8-plane
consistency pruning recovers that branch vector and a single key, which is then verified against the
concrete interpreter.

### Step 3: Rebuild the note (CRDT) to obtain `key2`

The decrypted archive is `CCA2` with 144 blocks: `u8 replica, u16 counter, i32 lamport, u16[4] clock,
u8 surrogate-flag, u16 position, u16 cover, u16 n, u16[n] chars, u8[4] checksum`. Each block's
checksum is `SHA256(LE16(note chars before the edit))[:4]`, which is a perfect oracle for the merge.

Replaying the app's semantics (`g.b`/`g.d`/`g.g`): each block's character nodes are instantiated
against *its own causal view* (the clock), attached after the character at `position-1`, with the
`cover` characters hidden; the merged list is a DFS from the null parent over children sorted
descending by `(lamport, replica, counter, index)`. That reproduces **all 144 checksums**, giving the
final 207-character note. `key2 = SHA256("CC-R2\0" + LE16(merged chars))` then unwraps the flag blob.

Expected output (key recovery takes a few minutes on a multicore machine):

```
[*] archive.ccb loaded: prog=23936 B, digest=240 B, entry=4702 B, flag=67 B
[*] recovery key: 733c3d29fb33e8533820f47a37ac01924932e35c8cd59cccfa4f53857dbaf8851ad0ee94401813a1e86d9d960f39c2119848596e1c9ee5276b5f6fa4dd1af64f
[*] inner note archive decrypted + authenticated: 144 blocks
[*] all 144 block checksums verified; merged note is 207 chars
[*] note recovery code (key2): 73dc6b843ce96721f7d5f23699884a82786e64db13ac9b5a36a004b339cb43de

FLAG: isfcr{fb02d58b558a0ba32e42eb248b13c7a1}
```

Complete solver (also `solve.py`; `pip install cryptography`):

```python
#!/usr/bin/env python3
"""
Carbon Copy  --  CryoVault Finals 2026 (mobile, hard)

Full solve, from the shipped APK to the flag:

  1. pull assets/archive.ccb out of carbon-copy.apk and parse the CCB2 container
  2. recover the 64-byte recovery-key from the 240-byte VM digest
     (custom bytecode VM, bit-plane GF(2) solve + EMITCP alias search)
  3. decrypt the inner CCA2 note archive (AES-256-GCM)
  4. rebuild the multi-replica CRDT note (144 blocks, checksum-verified)
  5. key2 = the note's "Local note saved." hash, then decrypt the flag blob

Usage:  python solve.py [path/to/carbon-copy.apk]
"""

import hashlib
import os
import struct
import sys
import zipfile
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# container
# --------------------------------------------------------------------------
PROG = b''
DIG = b''
SALT = b''
MUL = 1
NB = 48          # number of EMITCP instructions (alias/clone decisions)


def load_archive(apk_path):
    global PROG, DIG, SALT, MUL
    if apk_path.endswith('.zip'):
        import io
        with zipfile.ZipFile(apk_path) as z:
            inner = [n for n in z.namelist() if n.endswith('.apk')][0]
            apk = zipfile.ZipFile(io.BytesIO(z.read(inner)))
            blob = apk.read('assets/archive.ccb')
    elif apk_path.endswith('.apk'):
        with zipfile.ZipFile(apk_path) as apk:
            blob = apk.read('assets/archive.ccb')
    else:
        blob = open(apk_path, 'rb').read()

    assert blob[:8] == b'CCB2\r\n\x1a\n', 'bad CCB2 magic'
    assert struct.unpack('>H', blob[8:10])[0] == 64
    SALT = blob[10:26]
    off = 26

    def fld(o):
        n = struct.unpack_from('>I', blob, o)[0]
        assert 0 <= n <= 240000
        return blob[o + 4:o + 4 + n], o + 4 + n

    PROG, off = fld(off)
    DIG, off = fld(off)
    entry_ct, off = fld(off)
    flag_ct, off = fld(off)
    assert off == len(blob)
    MUL = _inv8(SALT[0] | 1)
    return entry_ct, flag_ct


def _inv8(a):
    a &= 255
    for x in range(256):
        if (a * x) & 255 == 1:
            return x
    raise ValueError('not invertible')


# --------------------------------------------------------------------------
# bit-plane symbolic VM (each bit of a value depends only on lower key bits)
# --------------------------------------------------------------------------
def solve_gf2(rows, nvars):
    piv = {}
    for mask, rhs in rows:
        m, r = mask, rhs & 1
        while m:
            p = m.bit_length() - 1
            if p in piv:
                pm, pr = piv[p]
                m ^= pm
                r ^= pr
            else:
                piv[p] = (m, r)
                break
        if m == 0 and r:
            return None
    return piv, [i for i in range(nvars) if i not in piv]


def back_substitute(piv, free_vals, nvars):
    out = [0] * nvars
    for k, v in free_vals.items():
        out[k] = v
    for p in sorted(piv):
        m, r = piv[p]
        val = r
        mm = m & ~(1 << p)
        while mm:
            q = mm.bit_length() - 1
            val ^= out[q]
            mm ^= 1 << q
        out[p] = val
    return out


class Sym:
    """symbolic 8-bit value at bit-plane p: (low bits, rhs bit, xor mask)"""

    def __init__(self, p):
        self.p = p
        self.MP = (1 << p) - 1

    def const(self, k):
        k &= 255
        return (k & self.MP, (k >> self.p) & 1, 0)

    def zero(self):
        return (0, 0, 0)

    def xor(self, a, b):
        return (a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2])

    def add(self, a, b):
        s = a[0] + b[0]
        return (s & self.MP, a[1] ^ b[1] ^ ((s >> self.p) & 1), a[2] ^ b[2])

    def shl(self, a, i):
        if i == 0:
            return a
        p = self.p
        lo = (a[0] << i) & self.MP
        src = p - i
        if src < 0:
            return (lo, 0, 0)
        return (lo, (a[0] >> src) & 1, 0)

    def mulc(self, a, c):
        r, i, c = self.zero(), 0, c & 255
        while c:
            if c & 1:
                r = self.add(r, self.shl(a, i))
            c >>= 1
            i += 1
        return r

    def sq(self, a):
        if self.p == 0:
            return (0, a[1], a[2])          # x*x == x over GF(2)
        t = a[0] * a[0]
        return (t & self.MP, (t >> self.p) & 1, 0)

    def mul(self, a, b):
        p = self.p
        if p == 0:
            if b[2] == 0:
                return a if (b[1] & 1) else self.zero()
            if a[2] == 0:
                return b if (a[1] & 1) else self.zero()
            raise ValueError('quadratic mul at plane 0')
        L = a[0] * b[0]
        cbit = ((L >> p) & 1) ^ ((b[0] & 1) & a[1]) ^ ((a[0] & 1) & b[1])
        m = 0
        if b[0] & 1:
            m ^= a[2]
        if a[0] & 1:
            m ^= b[2]
        return (L & self.MP, cbit, m)

    def neg(self, a):
        lo = (-a[0]) & self.MP
        carry = 1 if a[0] else 0
        return (lo, carry ^ a[1], a[2])

    def inv(self, y):
        z, two = y, self.const(2)
        for _ in range(3):
            z = self.mul(z, self.add(two, self.neg(self.mul(y, z))))
        return z

    def A(self, x, c):
        t1 = self.mulc(x, c)
        t2 = self.mulc(self.sq(x), 2)
        y = self.add(self.mulc(x, 2), self.const(1))
        return self.add(self.add(t1, t2), self.inv(y))


def run_sym(p, key_lo, branch_bits, stop_branch=None):
    """Run the bytecode VM symbolically at bit-plane p."""
    o = Sym(p)
    P = [[(key_lo[i * 8 + j], 0, 1 << (i * 8 + j)) for j in range(8)] for i in range(8)]
    Q = [P[i] for i in range(8)]
    R = [list(P[i]) for i in range(8)]
    S = [None] * 4
    pend = []
    out = []
    ip = bi = 0
    while ip < len(PROG):
        b = PROG[ip:ip + 8]
        op = (((b[0] - SALT[1]) & 255) * MUL) & 255
        a, bb, v3, v4, v5 = b[1] & 7, b[2] & 7, b[3], b[4], b[5]
        v6 = b[6] | (b[7] << 8)
        ip += 8
        if op == 0:
            P[a][v3 & 7] = o.xor(o.xor(P[a][v3 & 7], o.A(P[bb][v4 & 7], v5 | 1)), o.const(v6 & 255))
        elif op == 1:
            P[a] = P[bb]
        elif op == 2:
            P[a] = list(P[bb])
        elif op == 3:
            Q[a] = P[bb]
        elif op == 4:
            R[a] = list(P[bb])
        elif op == 5:
            P[a] = list(R[bb])
        elif op == 6:
            S[b[1] & 3] = list(P)
        elif op == 7:
            P[:] = list(S[b[1] & 3])
        elif op == 8:
            pend.append(dict(rA=a, rB=bb, a=P[a], b=P[bb], i=(v3 & 1) != 0, j=(v3 & 2) != 0,
                             e=v4, f=v5 | 1, g=v6 & 255, hh=v6 >> 8))
        elif op == 9:
            pend[:] = [h for h in pend if h['hh'] != b[1]]
        elif op == 10:
            keep = []
            for h in pend:
                if (b[1] & 1) == 0 or h['j']:
                    ra = P[h['rA']] if h['i'] else h['a']
                    rb = P[h['rB']] if h['i'] else h['b']
                    e = h['e']
                    ra[e & 7] = o.xor(ra[e & 7], o.xor(o.const(h['g']), o.A(rb[(e >> 3) & 7], h['f'])))
                else:
                    keep.append(h)
            pend[:] = keep
        elif op == 11:
            v = o.const(v6 & 255)
            for k in range(8):
                i20, i21 = k + v3, k + v4
                c1 = ((((v5 + k * 47) & 255) ^ SALT[i21 & 15]) + 1) & 255
                c2 = ((((v5 + k * 29) & 255) ^ SALT[i20 & 15]) + 1) & 255
                v = o.xor(o.xor(v, o.A(Q[bb][i21 & 7], c1)), o.A(P[a][i20 & 7], c2))
            out.append(v)
        elif op == 12:
            P[a] = Q[bb]
        elif op == 13:
            P[a][v3 & 7] = o.xor(P[a][v3 & 7], o.const(v6 & 255))
        elif op == 14:
            if stop_branch is not None and bi >= stop_branch:
                return out
            t = o.xor(P[a][v3 & 7], o.const(v6 & 255))
            out.append(o.xor(P[bb][v4 & 7], t))
            P[a] = P[bb] if branch_bits[bi] == 0 else list(P[bb])
            bi += 1
        else:
            raise ValueError('bad opcode %d' % op)
    return out


def chain_solutions(prefix, depth, max_sols=1, max_free=12):
    """All 64-byte keys matching DIG bit-planes 0..7 for this branch prefix."""
    sols = []

    def rec(p, key):
        if len(sols) >= max_sols:
            return
        key_lo = [k & ((1 << p) - 1) for k in key]
        out = run_sym(p, key_lo, prefix, stop_branch=depth)
        rows = [(v[2], ((DIG[i] >> p) & 1) ^ v[1]) for i, v in enumerate(out)]
        r = solve_gf2(rows, 64)
        if r is None:
            return
        piv, free = r
        if len(free) > max_free:
            return
        for choice in range(1 << len(free)):
            fv = {f: (choice >> j) & 1 for j, f in enumerate(free)}
            kb = back_substitute(piv, fv, 64)
            nk = [key[i] | (kb[i] << p) for i in range(64)]
            if p == 7:
                sols.append(bytes(nk))
            else:
                rec(p + 1, nk)
            if len(sols) >= max_sols:
                return

    rec(0, [0] * 64)
    return sols


# --------------------------------------------------------------------------
# concrete VM (ground truth / verification)
# --------------------------------------------------------------------------
def run_concrete(key):
    def A(i, i2):
        i3 = i * 2
        i4 = (i3 + 1) & 255
        i5 = i4
        for _ in range(3):
            i5 = (i5 * (2 - (i4 * i5))) & 255
        return ((i2 * i) + (i3 * i) + i5) & 255

    P = [[key[i * 8 + j] & 255 for j in range(8)] for i in range(8)]
    Q = [P[i] for i in range(8)]
    R = [list(P[i]) for i in range(8)]
    S = [None] * 4
    pend, out = [], bytearray()
    ip = 0
    while ip < len(PROG):
        b = PROG[ip:ip + 8]
        op = (((b[0] - SALT[1]) & 255) * MUL) & 255
        a, bb, v3, v4, v5 = b[1] & 7, b[2] & 7, b[3], b[4], b[5]
        v6 = b[6] | (b[7] << 8)
        ip += 8
        if op == 0:
            P[a][v3 & 7] ^= A(P[bb][v4 & 7], v5 | 1) ^ (v6 & 255)
        elif op == 1:
            P[a] = P[bb]
        elif op == 2:
            P[a] = list(P[bb])
        elif op == 3:
            Q[a] = P[bb]
        elif op == 4:
            R[a] = list(P[bb])
        elif op == 5:
            P[a] = list(R[bb])
        elif op == 6:
            S[b[1] & 3] = list(P)
        elif op == 7:
            P[:] = list(S[b[1] & 3])
        elif op == 8:
            pend.append(dict(rA=a, rB=bb, a=P[a], b=P[bb], i=(v3 & 1) != 0, j=(v3 & 2) != 0,
                             e=v4, f=v5 | 1, g=v6 & 255, hh=v6 >> 8))
        elif op == 9:
            pend[:] = [h for h in pend if h['hh'] != b[1]]
        elif op == 10:
            keep = []
            for h in pend:
                if (b[1] & 1) == 0 or h['j']:
                    ra = P[h['rA']] if h['i'] else h['a']
                    rb = P[h['rB']] if h['i'] else h['b']
                    e = h['e']
                    ra[e & 7] ^= (h['g'] ^ A(rb[(e >> 3) & 7], h['f']))
                else:
                    keep.append(h)
            pend[:] = keep
        elif op == 11:
            v = v6 & 255
            for k in range(8):
                i20, i21 = k + v3, k + v4
                v ^= A(Q[bb][i21 & 7], ((((v5 + k * 47) & 255) ^ SALT[i21 & 15]) + 1) & 255)
                v ^= A(P[a][i20 & 7], ((((v5 + k * 29) & 255) ^ SALT[i20 & 15]) + 1) & 255)
            out.append(v & 255)
        elif op == 12:
            P[a] = Q[bb]
        elif op == 13:
            P[a][v3 & 7] ^= v6 & 255
        elif op == 14:
            t = P[a][v3 & 7] ^ (v6 & 255)
            out.append((P[bb][v4 & 7] ^ t) & 255)
            P[a] = P[bb] if (t & 128) == 0 else list(P[bb])
        else:
            raise ValueError('bad opcode %d' % op)
    return bytes(out)


# --------------------------------------------------------------------------
# key recovery
# --------------------------------------------------------------------------
def _worker_init(apk_path):
    load_archive(apk_path)


def _probe_prefix(k):
    pre = [(k >> j) & 1 for j in range(13)]
    return k, bool(chain_solutions(pre, 13, max_sols=1))


def recover_key(processes=None):
    processes = processes or max(1, (os.cpu_count() or 4))
    survivors = []
    try:
        from multiprocessing import Pool, get_context
        ctx = get_context('spawn') if os.name == 'nt' else get_context()
        with Pool(processes, initializer=_worker_init,
                  initargs=(_APK_PATH,)) as pool:
            for k, ok in pool.imap_unordered(_probe_prefix, range(1 << 13), chunksize=8):
                if ok:
                    survivors.append([(k >> j) & 1 for j in range(13)])
    except Exception:
        survivors = []
        for k in range(1 << 13):
            pre = [(k >> j) & 1 for j in range(13)]
            if chain_solutions(pre, 13, max_sols=1):
                survivors.append(pre)

    stack = [(p, 13) for p in survivors]
    keys = []
    while stack:
        pre, dep = stack.pop()
        if dep == NB:
            for k in chain_solutions(pre, NB, max_sols=4):
                if k not in keys:
                    keys.append(k)
            continue
        for b in (1, 0):
            np_ = pre + [b]
            if chain_solutions(np_, dep + 1, max_sols=1):
                stack.append((np_, dep + 1))
    for k in keys:
        if run_concrete(k) == DIG:
            return k
    raise SystemExit('key recovery failed')


_APK_PATH = None


# --------------------------------------------------------------------------
# CRDT note reconstruction (Java g.b / g.d / g.g semantics)
# --------------------------------------------------------------------------
class D:
    __slots__ = ('a', 'b', 'c', 'd', 'e', 'f')

    def __init__(self, a, b, c, d, e, f):
        self.a, self.b, self.c, self.d, self.e, self.f = a, b, c, d, e, f

    def key(self):
        return (self.a, self.b, self.c, self.d)


def ser_chars(vals):
    return b''.join(struct.pack('<H', v & 0xFFFF) for v in vals)


def count_to(lst, ncp, z):
    """Java g.c: list index after consuming ncp code points."""
    i = got = 0
    while i < len(lst) and got < ncp:
        v = lst[i].e
        if z and 0xD800 <= v <= 0xDBFF and i + 1 < len(lst) and 0xDC00 <= lst[i + 1].e <= 0xDFFF:
            i += 2
        else:
            i += 1
        got += 1
    if got != ncp:
        raise ValueError('position out of range')
    return i


def merge_list(all_d, hidden):
    kids = defaultdict(list)
    for x in all_d:
        kids[x.f].append(x)
    for k in kids:
        kids[k].sort(key=lambda q: q.key(), reverse=True)
    out = []

    def dfs(node):
        for ch in kids.get(node, []):
            if ch not in hidden:
                out.append(ch)
            dfs(ch)

    dfs(None)
    return out


def parse_entries(pt):
    assert pt[:8] == b'CCA2\r\n\x1a\n', 'bad CCA2 magic'
    n = struct.unpack('>H', pt[8:10])[0]
    assert n <= 2048
    p, out = 10, []
    for idx in range(n):
        a = pt[p]
        b = struct.unpack('>H', pt[p + 1:p + 3])[0]
        c = struct.unpack('>i', pt[p + 3:p + 7])[0]
        g = struct.unpack('>4H', pt[p + 7:p + 15])
        d = pt[p + 15]
        e = struct.unpack('>H', pt[p + 16:p + 18])[0]
        f = struct.unpack('>H', pt[p + 18:p + 20])[0]
        hn = struct.unpack('>H', pt[p + 20:p + 22])[0]
        h = list(struct.unpack('>%dH' % hn, pt[p + 22:p + 22 + 2 * hn]))
        i = pt[p + 22 + 2 * hn:p + 26 + 2 * hn]
        p += 26 + 2 * hn
        out.append(dict(idx=idx, a=a, b=b, c=c, g=g, d=d, e=e, f=f, h=h, i=i))
    assert p == len(pt)
    return out


def build_note(E):
    block_ds, block_hidden = {}, {}
    cache = {}

    def state_of(view):
        if view in cache:
            return cache[view]
        all_d, hidden = [], set()
        for blk in E:
            if blk['b'] <= view[blk['a']]:
                all_d.extend(block_ds[blk['idx']])
                hidden |= block_hidden[blk['idx']]
        lst = merge_list(all_d, hidden)
        cache[view] = lst
        return lst

    # each block's characters are instantiated against its own (causal) view
    for blk in sorted(E, key=lambda x: (x['c'], x['a'], x['b'])):
        pre = state_of(tuple(blk['g']))
        z = blk['d'] != 0
        iC = count_to(pre, blk['e'], z)
        iC2 = count_to(pre, blk['e'] + blk['f'], z)
        kids = pre[iC:iC2]
        parent = pre[iC - 1] if iC > 0 else None
        ds = []
        for j, ch in enumerate(blk['h']):
            nd = D(blk['c'], blk['a'], blk['b'], j, ch, parent)
            ds.append(nd)
            parent = nd
        block_ds[blk['idx']] = ds
        block_hidden[blk['idx']] = set(kids)

    # every block carries SHA-256(serialized note before it)[:4] -- verify all
    for blk in E:
        pre = state_of(tuple(blk['g']))
        got = hashlib.sha256(ser_chars([x.e for x in pre])).digest()[:4]
        assert got == blk['i'], 'CRDT checksum mismatch at block %d' % blk['idx']

    full = tuple(max(b['b'] for b in E if b['a'] == r) for r in range(4))
    return state_of(full)


# --------------------------------------------------------------------------
def main():
    global _APK_PATH
    root = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(root, '..', 'input', 'carbon-copy', 'carbon-copy.apk'),
        os.path.join(root, '..', '..', 'challenges', 'carbon-copy', 'input', 'carbon-copy', 'carbon-copy.apk'),
        os.path.join(root, '..', '..', 'challenges', 'carbon-copy', 'input', 'carbon-copy.zip'),
    ]
    apk = sys.argv[1] if len(sys.argv) > 1 else next(
        (c for c in candidates if os.path.exists(c)), candidates[0])
    _APK_PATH = apk
    entry_ct, flag_ct = load_archive(apk)
    print('[*] archive.ccb loaded: prog=%d B, digest=%d B, entry=%d B, flag=%d B'
          % (len(PROG), len(DIG), len(entry_ct), len(flag_ct)))

    key = recover_key()
    print('[*] recovery key:', key.hex())

    # ---- layer 1: inner note archive
    aad1 = hashlib.sha256(PROG + DIG + SALT).digest()
    k1 = hashlib.sha256(b'CC-A2\x00' + key + SALT).digest()
    entry_pt = AESGCM(k1).decrypt(entry_ct[:12], entry_ct[12:], aad1)
    E = parse_entries(entry_pt)
    print('[*] inner note archive decrypted + authenticated: %d blocks' % len(E))

    # ---- CRDT merge -> the note as the app would render it
    note = build_note(E)
    text = ''.join(chr(x.e) for x in note)
    print('[*] all %d block checksums verified; merged note is %d chars:' % (len(E), len(note)))
    print('    ' + ascii(text))

    key2 = hashlib.sha256(b'CC-R2\x00' + ser_chars([x.e for x in note])).digest()
    print('[*] note recovery code (key2):', key2.hex())

    # ---- layer 2: flag blob
    inner_hash = hashlib.sha256(entry_pt).digest()
    f = hashlib.sha256(PROG + DIG + SALT).digest()
    aad2 = hashlib.sha256(f + entry_ct).digest()
    k2 = hashlib.sha256(b'CC-F2\x00' + key + key2 + inner_hash).digest()
    flag = AESGCM(k2).decrypt(flag_ct[:12], flag_ct[12:], aad2)
    print()
    print('FLAG:', flag.decode('utf-8'))


if __name__ == '__main__':
    main()
```

## Flag

```
isfcr{fb02d58b558a0ba32e42eb248b13c7a1}
```
