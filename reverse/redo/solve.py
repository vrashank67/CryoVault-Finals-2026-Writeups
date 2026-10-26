#!/usr/bin/env python3
"""REDO / R17 controller journal solver.

Input: journal.r17 (R17J container: manifest + CRC32-framed controller log).

1. Recover the 8 physical-unit profiles and biases from the T monitor frames.
2. Brute the controller's 3x3x2^6 configuration against the quiescent S
   snapshots.
3. Simulate the final transaction, derive the capsule key from the final
   arena/route/dispatch state, verify the HMAC tag and decrypt the receipt.
"""
import hashlib
import hmac
import itertools
import re
import struct
import sys
import zlib
from pathlib import Path

# Recovered from the T monitor equations (verified against all 200 frames).
# unit: (family, r, flip, salt, bias)
PROFILES = {
    0: (7, 3, 0, 50019, 46665),
    1: (3, 13, 1, 2123, 34426),
    2: (1, 13, 1, 34386, 1654),
    3: (0, 3, 1, 2075, 14155),
    4: (4, 11, 1, 13440, 60132),
    5: (6, 15, 1, 59610, 35660),
    6: (2, 11, 0, 15861, 34143),
    7: (5, 5, 0, 21525, 27891),
}

def rol16(v, r):
    return ((v << r) | (v >> (16 - r))) & 0xFFFF

def unit_response(unit, x, y, k):
    family, r, flip, salt, bias = PROFILES[unit]
    if flip:
        x, y = y, x
    z = k ^ salt
    q = rol16(y, r)
    if family == 0:
        v = ((x + q) & 0xFFFF) ^ z
    elif family == 1:
        v = (rol16(x ^ z, r) + y) & 0xFFFF
    elif family == 2:
        v = ((x ^ q) + z) & 0xFFFF
    elif family == 3:
        v = rol16((x + z) & 0xFFFF, r) ^ y
    elif family == 4:
        v = ((x * (q | 1)) & 0xFFFF) ^ z
    elif family == 5:
        v = ((x - q) & 0xFFFF) ^ z
    elif family == 6:
        v = ((x & z) | (q & ((~z) & 0xFFFF))) & 0xFFFF
    else:  # 7
        v = (rol16(((x ^ y) + z) & 0xFFFF, r) + x) & 0xFFFF
    return (v + bias) & 0xFFFF

def parse_frames(blob):
    assert blob[:8] == b"R17J\r\n\x1a\n"
    manifest_len = struct.unpack_from("<I", blob, 8)[0]
    off = 12 + manifest_len
    frames = []
    while off + 9 <= len(blob):
        plen = struct.unpack_from("<I", blob, off)[0]
        if off + 9 + plen + 4 > len(blob):
            break  # allowed incomplete tail
        seq = struct.unpack_from("<I", blob, off + 4)[0]
        kind = chr(blob[off + 8])
        payload = blob[off + 9:off + 9 + plen]
        crc = struct.unpack_from("<I", blob, off + 9 + plen)[0]
        want = zlib.crc32(struct.pack("<I", seq) + blob[off + 8:off + 9] + payload) & 0xFFFFFFFF
        assert crc == want, "frame CRC mismatch"
        frames.append((kind, payload))
        off += 9 + plen + 4
    return frames

def parse_S(payload):
    return (list(struct.unpack("<32H", payload[:64])),
            list(payload[64:96]),
            list(payload[96:104]))

class Ctx:
    __slots__ = ("begin_arena", "begin_route", "begin_disp", "queue", "lease_r", "lease_d")
    def __init__(self, arena, route, disp):
        self.begin_arena = arena[:]
        self.begin_route = route[:]
        self.begin_disp = disp[:]
        self.queue = []
        self.lease_r = {}
        self.lease_d = {}

def simulate(frames, cfg, initial, stop, snapshot_ids):
    """Run the controller model. Returns (observed S states, final state)."""
    ab, db, fr, lw, rm, ri, sb, sw = cfg
    arena, route, disp = [x[:] for x in initial]
    ctxs = {}
    seen = {}
    for idx, (kind, payload) in enumerate(frames):
        if idx > stop:
            break
        if kind == "S":
            if idx != 0 and idx in snapshot_ids:
                seen[idx] = (arena[:], route[:], disp[:])
            continue
        if kind in ("T", "V"):
            continue
        if kind == "B":
            tid = struct.unpack_from("<H", payload, 0)[0]
            ctxs[tid] = Ctx(arena, route, disp)
        elif kind == "O":
            tid, sel, a, b, d, mode, k = struct.unpack_from("<HBBBBBH", payload, 0)
            ctx = ctxs[tid]
            op = {
                "sel": sel, "a": a, "b": b, "d": d, "mode": mode, "k": k,
                "stage_r": (route[a], route[b], route[d]),
                "stage_d": disp[sel],
                "lease_r": None, "lease_d": None,
            }
            if ab == 2:
                for x in (a, b, d):
                    ctx.lease_r.setdefault(x, route[x])
                op["lease_r"] = (ctx.lease_r[a], ctx.lease_r[b], ctx.lease_r[d])
            if db == 2:
                ctx.lease_d.setdefault(sel, disp[sel])
                op["lease_d"] = ctx.lease_d[sel]
            ctx.queue.append(op)
        elif kind == "R":
            tid, a, b = struct.unpack_from("<HBB", payload, 0)
            if b & 0x80:
                route[a] = b & 31
            elif sw:
                route[a], route[b] = route[b], route[a]
            else:
                route[a] = route[b]
        elif kind == "D":
            tid, a, b = struct.unpack_from("<HBB", payload, 0)
            disp[a], disp[b] = disp[b], disp[a]
        elif kind == "F":
            tid = struct.unpack_from("<H", payload, 0)[0]
            if tid in ctxs:
                ctxs[tid].lease_r = {}
                ctxs[tid].lease_d = {}
        elif kind == "A":
            tid = struct.unpack_from("<H", payload, 0)[0]
            ctx = ctxs.pop(tid, None)
            if ctx is not None and rm:
                route = ctx.begin_route[:]
                disp = ctx.begin_disp[:]
        elif kind == "C":
            tid = struct.unpack_from("<H", payload, 0)[0]
            ctx = ctxs.pop(tid, None)
            if ctx is None:
                continue
            base = ctx.begin_arena[:] if sb else arena[:]
            scratch = base[:]
            out = arena[:]
            queue = ctx.queue[::-1] if ri else ctx.queue
            for op in queue:
                if ab == 0:
                    pa, pb, pd = op["stage_r"]
                elif ab == 1:
                    pa, pb, pd = route[op["a"]], route[op["b"]], route[op["d"]]
                else:
                    pa, pb, pd = op["lease_r"]
                if db == 0:
                    unit = op["stage_d"]
                elif db == 1:
                    unit = disp[op["sel"]]
                else:
                    unit = op["lease_d"]
                x = scratch[pa] if fr else base[pa]
                y = scratch[pb] if fr else base[pb]
                old = out[pd] if lw else base[pd]
                resp = unit_response(unit, x, y, k=op["k"])
                if op["mode"] == 0:
                    nv = resp
                elif op["mode"] == 1:
                    nv = (old + resp) & 0xFFFF
                else:
                    nv = (old ^ resp) & 0xFFFF
                out[pd] = nv
                if fr:
                    scratch[pd] = nv
            arena = out
    return seen, (arena, route, disp)

def solve(path: Path):
    blob = path.read_bytes()
    frames = parse_frames(blob)

    # Verify the recovered unit profiles against every T monitor frame.
    t_count = 0
    for kind, payload in frames:
        if kind != "T":
            continue
        n = payload[0]
        entries = [struct.unpack_from("<BHHH", payload, 1 + i * 7) for i in range(n)]
        total = struct.unpack_from("<H", payload, 1 + n * 7)[0]
        got = sum(unit_response(u, x, y, k) for u, x, y, k in entries) & 0xFFFF
        assert got == total, "unit profile mismatch"
        t_count += 1
    assert t_count == 200

    snaps = [(i, parse_S(payload)) for i, (kind, payload) in enumerate(frames) if kind == "S"]
    initial = snaps[0][1]
    snapshot_ids = {i for i, _ in snaps[1:]}

    matches = []
    for cfg in itertools.product(range(3), range(3), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)):
        seen, final = simulate(frames, cfg, initial, len(frames) - 1, snapshot_ids)
        if all(seen.get(i) == state for i, state in snaps[1:]):
            matches.append((cfg, final))
    assert len(matches) == 1, f"expected one config, got {len(matches)}"
    cfg, (arena, route, disp) = matches[0]

    state = struct.pack("<32H", *arena) + bytes(route) + bytes(disp)
    key = hashlib.sha256(b"R17/capsule/2" + state).digest()

    v_payload = [p for k, p in frames if k == "V"][0]
    nonce, tag = v_payload[:24], v_payload[-32:]
    ciphertext = v_payload[24:-32]
    assert hmac.new(key, nonce + ciphertext, hashlib.sha256).digest() == tag

    stream = hashlib.shake_256(key + nonce).digest(len(ciphertext))
    receipt = bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")
    assert re.fullmatch(r"isfcr\{[0-9a-f]+\}", receipt)
    return receipt, cfg

if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("journal.r17")
    flag, cfg = solve(p)
    print(flag)
