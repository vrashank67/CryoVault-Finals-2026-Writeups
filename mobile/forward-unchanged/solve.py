#!/usr/bin/env python3
"""Forward Unchanged (CryoVault Finals, Mobile 500) - full solve.

From the challenge zip to the flag:

  1. Each APK contains assets/p.dat: (s, rounds, anchor, plans, k, salt, matrix, want).
  2. Endpoints parse/verify a 128-byte "recovery request" (32 little-endian words)
     in 8 records of 4 words.  Every record read from a Parcel is passed through
     C.b(record, mode) where `mode` is the parcel tag of that record; records the
     endpoint never touches are forwarded to the next blob byte-for-byte (Android
     keeps Bundle values lazy), i.e. "forward unchanged".
  3. Each stage compares C.c(gathered words) with its `want` array.
  4. C.b / C.c only use +, *const, ^, << (no right shifts), so bit b of every
     intermediate depends only on input bits <= b.  Solving plane by plane turns
     the 32 equations into affine GF(2) systems (Gaussian elimination).
  5. Enumerate the three data-dependent plan bits, solve, and try the resulting
     128-byte request as the note key (HMAC-SHA256 -> AES-GCM).

Prints the flag.
"""
import hashlib, hmac, io, itertools, struct, sys, zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

M32 = 0xFFFFFFFF
NAMES = ('intake', 'relay', 'archive')


# ---------------------------------------------------------------- p.dat ----
def parse_pdat(data: bytes) -> dict:
    o = 0
    def gi():
        nonlocal o
        v = struct.unpack_from('<i', data, o)[0]
        o += 4
        return v
    magic = gi()
    assert magic == 844126022
    s = gi(); rounds = gi(); anchor = gi(); nplan = gi(); nrow = gi()
    plans = [[gi() for _ in range(nplan)] for _ in range(2)]
    k = [gi() for _ in range(rounds * 4)]
    salt = [gi() for _ in range(nrow)]
    matrix = [[gi() for _ in range(nplan * 4)] for _ in range(nrow)]
    want = [gi() for _ in range(nrow)]
    assert o == len(data)
    return dict(s=s, rounds=rounds, anchor=anchor, plans=plans, k=k,
                salt=salt, matrix=matrix, want=want, nrow=nrow)


def rotl(v, r):
    v &= M32
    return ((v << r) | (v >> (32 - r))) & M32


# ------------------------------------------------------------- concrete ----
def cb(info, w4, mode):
    """C.b: per-record ARX permutation keyed by the stage's k/s."""
    if mode == info['s']:
        return list(w4)
    k = info['k']; rounds = info['rounds']; s = info['s']
    v0, v1, v2, v3 = w4
    for i in range(rounds):
        q = i * 4
        t = (v0 + ((k[q] ^ v1) * (k[q + 1] | 1)) + (-1640531527) * mode) & M32
        t1 = (v2 ^ ((t << (((i + mode) % 11) + 1)) & M32)) & M32
        t2 = ((k[q + 2] ^ t1) * (k[q + 3] | 1)) & M32
        t3 = (v3 + t2 + 1779033703 * s) & M32
        t4 = (v1 ^ ((t3 << (((s + i) % 13) + 1)) & M32)) & M32
        v0, v1, v2, v3 = t1, t3, t4, t
    return [v0, v1, v2, v3]


def cc(info, xs):
    """C.c: the fingerprint checked against `want`."""
    nrow = info['nrow']; salt = info['salt']; M = info['matrix']; s = info['s']
    out = []
    for i in range(nrow):
        t = salt[i] & M32
        for j, x in enumerate(xs):
            kk = ((j * 7 + i * 3) % 19) + 1
            t = ((t + (M[i][j] & M32) * x) & M32) ^ ((x << kk) & M32)
            t &= M32
        y = (t ^ ((t << 13) & M32)) & M32
        u = (y + (salt[(i + 1) % len(salt)] & M32)) & M32
        z = (u ^ ((u << 7) & M32)) & M32
        out.append(rotl(z, ((i * 7 + s * 3) % 31) + 1))
    return out


# ------------------------------------------------------------- the chain ---
def chain(S, W):
    """Exact endpoint chain with lazy-Bundle record forwarding.

    W: 8 lists of 4 words (the request records).
    Returns per-stage (sel, gathered words) and the per-record states.
    """
    i_info, r_info, a_info = S['intake'], S['relay'], S['archive']

    # intake: only the anchor record and its plan records are read (and so
    # get CB_intake(.,0)); everything else stays raw in the forwarded blob.
    b1_anchor = cb(i_info, W[0], 0)
    i_sel = (b1_anchor[2] ^ rotl(b1_anchor[0], 9)) & 1
    i_plan = i_info['plans'][i_sel]
    i_acc = set(i_plan) | {0}
    rec = [(cb(i_info, W[g], 0), 1) if g in i_acc else (list(W[g]), 0) for g in range(8)]

    # relay: reads its anchor (6) + plan records, applying CB_relay(.,mode);
    # touched records become mode 2, untouched ones are forwarded unchanged.
    v6 = cb(r_info, rec[6][0], rec[6][1])
    r_sel = (v6[2] ^ rotl(v6[0], 9)) & 1
    r_plan = r_info['plans'][r_sel]
    r_acc = set(r_plan) | {6}
    relay_view = [cb(r_info, rec[g][0], rec[g][1]) for g in range(8)]
    newrec = [(relay_view[g], 2) if g in r_acc else rec[g] for g in range(8)]

    # archive: reads its anchor (3) + plan records with their stored modes.
    v3 = cb(a_info, newrec[3][0], newrec[3][1])
    a_sel = (v3[2] ^ rotl(v3[0], 9)) & 1
    a_plan = a_info['plans'][a_sel]
    archive_view = [cb(a_info, newrec[g][0], newrec[g][1]) for g in range(8)]

    def gather(vals, plan):
        out = []
        for e in plan:
            out.extend(vals[e])
        return out

    ints = {'intake': (i_plan, [rec[g][0] for g in range(8)]),
            'relay': (r_plan, relay_view),
            'archive': (a_plan, archive_view)}
    got = {}
    for n in NAMES:
        plan, vals = ints[n]
        got[n] = gather(vals, plan)
    sels = {'intake': i_sel, 'relay': r_sel, 'archive': a_sel}
    return sels, got


def receipts(S, W):
    sels, got = chain(S, W)
    res = {}
    for n in NAMES:
        out = cc(S[n], got[n])
        res[n] = (sels[n], out, out == [w & M32 for w in S[n]['want']])
    return res


# ------------------------------------------------- affine bit-plane algebra --
# A value is (val, mask): `val` holds the exact known bits < b and the constant
# term of bit b; `mask` is a bitmask of the plane-b unknown variables.
def a_add(a, b, bv):
    lm = (1 << bv) - 1
    s = (a[0] & lm) + (b[0] & lm)
    carry = (s >> bv) & 1
    bit = ((a[0] >> bv) & 1) ^ ((b[0] >> bv) & 1) ^ carry
    return ((s & lm) | (bit << bv), a[1] ^ b[1])


def a_xor(a, b, bv):
    return ((a[0] ^ b[0]) & ((1 << (bv + 1)) - 1), a[1] ^ b[1])


def a_mulc(a, m, bv):
    lm = (1 << bv) - 1
    p = (m & M32) * (a[0] & lm)
    bit = ((p >> bv) & 1) ^ (((m & 1) & ((a[0] >> bv) & 1)))
    return ((p & lm) | (bit << bv), a[1] if (m & 1) else 0)


def a_shl(a, k, bv):
    lm = (1 << bv) - 1
    bit = ((a[0] >> (bv - k)) & 1) if bv >= k else 0
    return ((((a[0] & lm) << k) & lm) | (bit << bv), 0)


def a_const(v):
    return (v & M32, 0)


def cb_sym(info, w4, mode, bv):
    if mode == info['s']:
        return list(w4)
    k = info['k']; rounds = info['rounds']; s = info['s']
    v0, v1, v2, v3 = w4
    for i in range(rounds):
        q = i * 4
        t = a_add(a_add(v0, a_mulc(a_xor(a_const(k[q]), v1, bv), k[q + 1] | 1, bv), bv),
                  a_const((-1640531527 * mode) & M32), bv)
        t1 = a_xor(v2, a_shl(t, ((i + mode) % 11) + 1, bv), bv)
        t2 = a_mulc(a_xor(a_const(k[q + 2]), t1, bv), k[q + 3] | 1, bv)
        t3 = a_add(a_add(v3, t2, bv), a_const((1779033703 * s) & M32), bv)
        t4 = a_xor(v1, a_shl(t3, ((s + i) % 13) + 1, bv), bv)
        v0, v1, v2, v3 = t1, t3, t4, t
    return [v0, v1, v2, v3]


def stage_rows(info, xsym, bv):
    nrow = info['nrow']; salt = info['salt']; M = info['matrix']; s = info['s']
    rows = []
    for i in range(nrow):
        t = a_const(salt[i])
        for j, x in enumerate(xsym):
            kk = ((j * 7 + i * 3) % 19) + 1
            t = a_add(t, a_mulc(x, M[i][j], bv), bv)
            t = a_xor(t, a_shl(x, kk, bv), bv)
        y = a_xor(t, a_shl(t, 13, bv), bv)
        u = a_add(y, a_const(salt[(i + 1) % len(salt)]), bv)
        z = a_xor(u, a_shl(u, 7, bv), bv)
        r = ((i * 7 + s * 3) % 31) + 1
        target = ((info['want'][i] & M32) >> ((bv + r) % 32)) & 1
        rows.append((z[1], target ^ ((z[0] >> bv) & 1)))
    return rows


def model_rows(S, sel, bv, x):
    """Symbolic equations for one guessed (intake, relay, archive) plan combo."""
    sel_i, sel_r, sel_a = sel
    W = [[(x[g * 4 + t], 1 << (g * 4 + t)) for t in range(4)] for g in range(8)]
    i_info, r_info, a_info = S['intake'], S['relay'], S['archive']

    i_plan = i_info['plans'][sel_i]
    i_acc = set(i_plan) | {0}
    rec = [(cb_sym(i_info, W[g], 0, bv), 1) if g in i_acc else (list(W[g]), 0)
           for g in range(8)]

    r_plan = r_info['plans'][sel_r]
    r_acc = set(r_plan) | {6}
    relay_view = [cb_sym(r_info, rec[g][0], rec[g][1], bv) for g in range(8)]
    newrec = [(relay_view[g], 2) if g in r_acc else rec[g] for g in range(8)]

    a_plan = a_info['plans'][sel_a]
    archive_view = [cb_sym(a_info, newrec[g][0], newrec[g][1], bv) for g in range(8)]

    rows = []
    # intake sees its own records transformed with CB_intake(.,0)
    gi = []
    for e in i_plan:
        gi.extend(cb_sym(i_info, W[e], 0, bv))
    rows.extend(stage_rows(i_info, gi, bv))
    gr = []
    for e in r_plan:
        gr.extend(relay_view[e])
    rows.extend(stage_rows(r_info, gr, bv))
    ga = []
    for e in a_plan:
        ga.extend(archive_view[e])
    rows.extend(stage_rows(a_info, ga, bv))
    return rows


def eliminate(rows):
    piv = {}
    for mask, rhs in rows:
        m, r = mask, rhs & 1
        while m:
            p = m.bit_length() - 1
            if p in piv:
                pm, pr = piv[p]
                m ^= pm; r ^= pr
            else:
                piv[p] = (m, r)
                break
        if m == 0 and r:
            return None
    return piv


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
        piv = eliminate(model_rows(S, sel, bv, x))
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


# ------------------------------------------------------------------ main ----
def find_zip():
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    here = Path(__file__).resolve().parent
    for c in (here / 'forward-unchanged.zip',
              here.parent.parent / 'challenges' / 'forward-unchanged' / 'input' / 'forward-unchanged.zip',
              Path('challenges/forward-unchanged/input/forward-unchanged.zip')):
        if c.exists():
            return c
    raise SystemExit('pass the challenge zip path')


def main():
    zpath = find_zip()
    z = zipfile.ZipFile(zpath)
    names = z.namelist()

    def read(suffix):
        for n in names:
            if n.endswith(suffix):
                return z.read(n)
        raise SystemExit('missing ' + suffix)

    note = read('note.bin')
    S = {}
    for n in NAMES:
        apk = z.read(next(x for x in names if x.endswith(n + '.apk')))
        with zipfile.ZipFile(io.BytesIO(apk)) as az:
            S[n] = parse_pdat(az.read('assets/p.dat'))

    salt, nonce = note[9:25], note[25:37]

    def key(request):
        prk = hmac.new(salt, request, hashlib.sha256).digest()
        return hmac.new(prk, b'forward-unchanged/v1\x01', hashlib.sha256).digest()

    for sel in itertools.product([0, 1], repeat=3):
        for x in solve_combo(S, sel):
            words = [x[i] for i in range(32)]
            W = [words[g * 4:g * 4 + 4] for g in range(8)]
            r = receipts(S, W)
            if not all(r[n][2] for n in NAMES):
                continue
            req = b''.join(struct.pack('<I', w) for w in words)
            try:
                pt = AESGCM(key(req)).decrypt(nonce, note[37:], note[:37])
            except Exception:
                continue
            print('request:', req.hex())
            print('flag:', pt.decode())
            return
    raise SystemExit('no solution')


if __name__ == '__main__':
    main()
