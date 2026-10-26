#!/usr/bin/env python3
"""
CryoVault Finals -- "Carbon Without an Original" (mobile, hard, 500)
Data-first solve: the restored work-profile export is the whole story.

Input : input/carbon-without-an-original.zip  (Carbon.apk + export.tar)
Output: the note plaintext / flag

Chain
-----
 1. cache.db itself has its slot capsules zeroed by the restore, but
    cache.db-wal still carries 89 historical `slots` rows (33 unique
    (serial, boot, generation) capsules).  Layout of a capsule:

        "CP2\0" | 32-byte per-installation header  | 32-byte mutable value

    The header, read as 16 little-endian u16, is that installation's 4x4
    basis matrix over GF(65521) (every header is in SL(4,65521)).
    The mutable value V seals that boot's delivery wires.

 2. journal.db.deliveries[*].wire is a 176-byte blob: 16-byte IV +
    128-byte AES-CBC ciphertext + 32-byte trailer.  AES key is
    SHA256(V||0x00); the plaintext is a 120-byte Journal v2 Entry
    (magic "CCJ2") + PKCS#5 padding.  The trailing 32 bytes are not the
    Envelope MAC (checked: no AAD/AES-key combination reproduces it), so
    decryption is validated by the magic + padding, not the tag.

 3. Journal.archiveKey() (v12 APK) derives a per-document archive key from
    the visible entry set.  The journal spans a long history, so the key
    that sealed the 12->23 migration object is the *historical* state:
    authors {29,64} with entry height <= 114.  Testing candidates against
    objects/5a10... with AAD "carbon/migrate/23" gives the unique v2 key.

 4. Envelope-open 5a10... -> Sequence v23 payload ("CS23").
    Sequence.recover(v2, document_id, payload) -> v23 key.

 5. Envelope-open b5b5... with v23 + AAD "carbon/migrate/31" -> Dispatch
    v31 program ("CD31").  Replaying it (preconditions + per-checkpoint
    observation mask + HMAC commitment) has exactly one valid interleaving
    and yields the v31 recovery code.

 6. The recovery code opens Carbon.apk's assets/archive.bin
    (AAD "carbon/note/v31") -> the note text = flag.

Usage: python3 solve.py [path/to/carbon-without-an-original.zip]
"""
import hashlib
import hmac
import itertools
import os
import sqlite3
import struct
import sys
import tarfile
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

P = 65521
N = 4
M32 = 0xFFFFFFFF
NOTE_DOC = "c308d2dff2e68f2d2e85dce5417c20bc"
OBJ_V23 = "5a101c139eb4b858fe5ab0859070c2d8bcbd97615600087fa69d06186fcadf46"
OBJ_V31 = "b5b5940115d804cf351a66909986b3ea2a8ba394b4c1ffe9ea9d611e90607730"


def H(b):
    return hashlib.sha256(b).digest()


# --------------------------------------------------------------- Envelope
def envelope_open(key, blob, aad):
    """Envelope.open: AES-CBC + HMAC-SHA256(key||1) over aad||iv||ct."""
    if len(blob) < 64 or (len(blob) - 48) % 16:
        raise ValueError("envelope length")
    body = blob[:-32]
    mac = hmac.new(H(key + b"\x01"), aad + body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, blob[-32:]):
        raise ValueError("receipt")
    dec = Cipher(algorithms.AES(H(key + b"\x00")), modes.CBC(blob[:16])).decryptor()
    pt = dec.update(blob[16:-32]) + dec.finalize()
    pad = pt[-1]
    if not (1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad):
        raise ValueError("padding")
    return pt[:-pad]


# ------------------------------------------------- Journal v2 linear algebra
def mod(x):
    return x % P


def matmul(A, B):
    return [[mod(sum(A[i][k] * B[k][j] for k in range(N))) for j in range(N)]
            for i in range(N)]


_INV = {}


def matinv(A):
    k = tuple(tuple(r) for r in A)
    if k in _INV:
        return _INV[k]
    m = [row[:] + [1 if i == j else 0 for j in range(N)] for i, row in enumerate(A)]
    for c in range(N):
        piv = next(r for r in range(c, N) if m[r][c] % P)
        m[c], m[piv] = m[piv], m[c]
        inv = pow(m[c][c], P - 2, P)
        m[c] = [mod(v * inv) for v in m[c]]
        for r in range(N):
            if r != c:
                f = m[r][c]
                m[r] = [mod(m[r][kk] - f * m[c][kk]) for kk in range(2 * N)]
    out = [row[N:] for row in m]
    _INV[k] = out
    return out


def matapply(A, v):
    return [mod(sum(A[i][k] * v[k] for k in range(N))) for i in range(N)]


def jheight(e):
    return sum(e["clock"])


def archive_key(sel, doc, bases):
    """dev.sr.carbon.Journal.archiveKey() from the cached v12 APK."""
    map2 = {e["identity"]: e for e in sel}
    arr = sorted(sel, key=lambda e: (jheight(e), bytes.fromhex(e["identity"])))
    vis = {e["identity"]: True for e in arr}
    # erase entries retract their target, walking the sorted list backwards
    for i in range(len(arr) - 1, -1, -1):
        e = arr[i]
        if e["kind"] == 2 and vis[e["identity"]]:
            t = e["target"]
            if t not in map2 or jheight(map2[t]) >= jheight(e):
                raise ValueError("erase")
            vis[t] = not vis[t]
    state = [0] * N
    attr = bytearray()
    cache = {}

    def basis(e):
        if all(b == 0 for b in bytes.fromhex(e["basis"])):
            return bases[e["author"]]              # installation capsule header
        bh = e["basis"]
        if bh not in cache:                        # basis frame: B = B(parent)*M
            par = map2.get(bh)
            if par is None or par["kind"] != 0:
                raise ValueError("frame")
            cache[bh] = matmul(basis(par), par["matrix"])
        return cache[bh]

    for e in arr:
        if not vis[e["identity"]]:
            continue
        attr += bytes.fromhex(e["identity"])
        attr.append(e["kind"])
        if e["kind"] == 2:
            continue
        B = basis(e)
        MB = matmul(matmul(B, e["matrix"]), matinv(B))
        av = matapply(B, e["vector"])
        av2 = matapply(MB, state)
        state = [mod(av2[k] + av[k]) for k in range(N)]
    out = b"carbon/archive/v2\x00" + bytes.fromhex(doc)
    for v in state:
        out += bytes([v & 255, (v >> 8) & 255])
    out += H(bytes(attr))
    return H(out)


# ------------------------------------------------------- SQLite WAL capsules
def read_varint(buf, off):
    v = 0
    for i in range(9):
        b = buf[off + i]
        if i == 8:
            return (v << 8) | b, off + 9
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            return v, off + i + 1
    raise ValueError("varint")


def parse_leaf(page):
    if not page or page[0] != 0x0D:
        return []
    ncell = struct.unpack(">H", page[3:5])[0]
    rows = []
    for c in range(ncell):
        ptr = struct.unpack(">H", page[8 + 2 * c:10 + 2 * c])[0]
        plen, o = read_varint(page, ptr)
        _rid, o = read_varint(page, o)
        rows.append(page[o:o + plen])
    return rows


def parse_record(payload):
    hlen, o = read_varint(payload, 0)
    types = []
    while o < hlen:
        t, o = read_varint(payload, o)
        types.append(t)
    vals = []
    p = hlen
    for t in types:
        if t == 0:
            vals.append(None)
        elif t <= 6:
            sz = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}[t]
            vals.append(int.from_bytes(payload[p:p + sz], "big", signed=True))
            p += sz
        elif t in (8, 9):
            vals.append(t - 8)
        elif t >= 12:
            sz = (t - 12) // 2
            b = payload[p:p + sz]
            p += sz
            vals.append(b if t % 2 == 0 else b.decode("utf-8", "replace"))
        else:
            vals.append(None)
    return vals


def wal_capsules(path):
    """Replay every WAL frame touching page 2 and lift the CP2 capsules."""
    data = open(path, "rb").read()
    _m, _v, psize, _ck, _s1, _s2, _c1, _c2 = struct.unpack(">8I", data[:32])
    frames = (len(data) - 32) // (psize + 24)
    caps = []
    for i in range(frames):
        off = 32 + i * (psize + 24)
        pgno, _dbsize, _f1, _f2, _g1, _g2 = struct.unpack(">6I", data[off:off + 24])
        if pgno != 2:                      # 2 = b-tree root of `slots`
            continue
        page = data[off + 24:off + 24 + psize]
        for payload in parse_leaf(page):
            v = parse_record(payload)
            if (len(v) >= 7 and isinstance(v[6], bytes) and len(v[6]) == 68
                    and v[6][:4] == b"CP2\x00"):
                caps.append(dict(serial=v[1], boot=v[3], gen=v[4], cap=v[6]))
    return caps


def decrypt_wire(key, wire):
    """Delivery envelope: CBC only (trailer is not the Envelope MAC)."""
    dec = Cipher(algorithms.AES(H(key + b"\x00")), modes.CBC(wire[:16])).decryptor()
    pt = dec.update(wire[16:-32]) + dec.finalize()
    pad = pt[-1]
    if not (1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad):
        return None
    pt = pt[:-pad]
    return pt if len(pt) == 120 and pt[:4] == b"CCJ2" else None


def parse_entry(pt, wall):
    return dict(
        author=struct.unpack("<I", pt[4:8])[0],
        document=pt[8:24].hex(),
        identity=pt[24:40].hex(),
        lane=pt[40],
        kind=pt[41],
        clock=list(struct.unpack("<3H", pt[42:48])),
        basis=pt[48:64].hex(),
        target=pt[64:80].hex(),
        matrix=[list(struct.unpack("<4H", pt[80 + 8 * r:88 + 8 * r])) for r in range(4)],
        vector=list(struct.unpack("<4H", pt[112:120])),
        wall=wall,
    )


# ---------------------------------------------------------- Sequence v23
ZERO = "0" * 32


class Reader:
    def __init__(self, b):
        self.b = b
        self.o = 0

    def take(self, n):
        v = self.b[self.o:self.o + n]
        if len(v) != n:
            raise ValueError("short")
        self.o += n
        return v

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def text(self):
        return self.take(self.i32()).decode("utf-8")


def seq_roots(key, s):
    out, parent, idx = [], ZERO, 0
    for ch in s:
        nid = H(b"carbon/root/" + key + struct.pack("<I", idx))[:16].hex()
        out.append(dict(id=nid, parent=parent, glyph=ch, height=0))
        parent, idx = nid, idx + 1
    return out


def seq_boundary(nodes, target):
    length = 0
    for i in range(len(nodes) + 1):
        if length == target:
            return i
        if i < len(nodes):
            length += len(nodes[i]["glyph"].encode("utf-16-le")) // 2
    raise ValueError("cursor")


def seq_digest(nodes):
    b = bytearray(b"carbon/view23\x00")
    for n in nodes:
        b += n["glyph"].encode("utf-8")
    for n in nodes:
        b += bytes.fromhex(n["id"])
    return H(bytes(b))


def seq_view(roots, elist):
    arr = [dict(n) for n in roots]
    hide = set()
    for e in elist:
        if e["kind"] != 0:
            hide.update(e["targets"])
        else:
            parent = e["anchor"]
            for idx, ch in enumerate(e["text"]):
                nid = H(e["id"] + struct.pack("<H", idx))[:16].hex()
                arr.append(dict(id=nid, parent=parent, glyph=ch, height=e["height"]))
                parent = nid
    mp = {}
    for n in arr:
        mp.setdefault(n["parent"], []).append(n)
    for k in mp:
        mp[k].sort(key=lambda n: (-n["height"], n["id"]))
    out = []

    def walk(pid):
        for n in mp.get(pid, []):
            if n["id"] not in hide:
                out.append(n)
            walk(n["id"])

    walk(ZERO)
    return out


def seq_visible(a, b):
    return all(a[i] <= b[i] for i in range(3))


def sequence_recover(key, program_key, payload):
    r = Reader(payload)
    if r.i32() != 1129525811:              # "CS23"
        raise ValueError("sequence magic")
    program = r.text()
    entries = []
    for _ in range(r.i32()):
        e = dict(id=r.take(16), anchor=ZERO)
        r.take(1)
        e["kind"] = r.take(1)[0]
        e["clock"] = [r.u16(), r.u16(), r.u16()]
        e["pos"] = r.u16()
        e["span"] = r.u16()
        e["text"] = r.text()
        entries.append(e)
    wits = []
    for _ in range(r.i32()):
        wits.append(([r.u16(), r.u16(), r.u16()], r.take(32)))
    if r.o != len(payload):
        raise ValueError("tail")
    entries.sort(key=lambda e: (sum(e["clock"]), e["id"].hex()))
    roots = seq_roots(program_key, program)
    done = []
    for e in entries:
        vis = [x for x in done if seq_visible(x["clock"], e["clock"])]
        v = seq_view(roots, vis)
        b1 = seq_boundary(v, e["pos"])
        b2 = seq_boundary(v, e["pos"] + e["span"])
        e["height"] = sum(e["clock"])
        e["targets"] = []
        if e["kind"] != 0:
            e["targets"] = [v[k]["id"] for k in range(b1, b2)]
        else:
            if e["span"] != 0:
                raise ValueError("span")
            e["anchor"] = ZERO if b1 == 0 else v[b1 - 1]["id"]
        done.append(e)
    for clk, dg in wits:                    # witness digests pin the history
        vis = [x for x in done if seq_visible(x["clock"], clk)]
        if seq_digest(seq_view(roots, vis)) != dg:
            raise ValueError("witness")
    final = seq_view(roots, done)
    b3 = bytearray(b"carbon/sequence23\x00")
    b3 += key
    b3 += program_key
    ids = bytearray()
    for n in final:
        b3 += n["glyph"].encode("utf-8")
        ids += bytes.fromhex(n["id"])
    be = bytearray()
    for e in done:
        be += e["id"]
        be.append(e["kind"])
        be += bytes.fromhex(e["anchor"])
        be += struct.pack("<H", len(e["targets"]))
        for t in e["targets"]:
            be += bytes.fromhex(t)
        tb = e["text"].encode("utf-8")
        be += struct.pack("<H", len(tb))
        be += tb
    b3 += H(bytes(ids))
    b3 += H(bytes(be))
    return H(bytes(b3))


# ---------------------------------------------------------- Dispatch v31
def rol(x, n):
    n &= 31
    return x & M32 if n == 0 else ((x << n) | (x >> (32 - n))) & M32


def ror(x, n):
    n &= 31
    return x & M32 if n == 0 else ((x >> n) | (x << (32 - n))) & M32


def disp_step(st, lane, eid, val, pre):
    val &= M32
    if (((((st[(lane + 1) & 3] & M32) >> ((val >> 24) & 15)) ^ eid ^ lane) & 1) != pre):
        return None
    s3 = st[3] & M32
    i6 = ((s3 >> 27) ^ val) & 3
    i7 = ((val >> 2) + lane) & 3
    rot = (rol((st[i6] ^ val) & M32, (((s3 >> 27) ^ (val >> 8)) & 31) + 1) + st[i7]) & M32
    ns = st[:]
    ns[i6] = rot
    i8 = (i6 + 1) & 3
    ns[i8] = (ror((st[(i7 + 2) & 3] ^ rot) & M32, ((val >> 16) & 31) + 1) ^ ns[i8]) & M32
    ns[3] = (ns[3] + (((eid * -1640531527) & M32) ^ val) + lane) & M32
    return [x & M32 for x in ns]


def disp_observation(st, bits):
    return (((st[3] & M32) >> 7) ^ (st[0] ^ rol(st[2], 9))) & ((1 << bits) - 1)


def disp_initial(key):
    return list(struct.unpack("<4I", H(b"carbon/dispatch31\x00" + key)[:16]))


def parse_dispatch(prog):
    o = 0

    def take(n):
        nonlocal o
        v = prog[o:o + n]
        o += n
        return v

    if struct.unpack(">i", take(4))[0] != 1128543025:      # "CD31"
        raise ValueError("dispatch magic")
    cks = []
    for _ in range(struct.unpack(">i", take(4))[0]):
        bits = take(1)[0]
        obs = struct.unpack(">i", take(4))[0]
        lanes = []
        for _ in range(3):
            n = struct.unpack(">H", take(2))[0]
            lanes.append([(struct.unpack(">H", take(2))[0],
                           struct.unpack(">i", take(4))[0],
                           take(1)[0]) for _ in range(n)])
        cks.append((bits, obs, lanes))
    tail = take(32)
    if o != len(prog):
        raise ValueError("dispatch tail")
    return cks, tail


def dispatch_solve(key, cks, tail):
    """DFS over in-checkpoint interleavings; preconditions + masks prune."""
    total = sum(len(l) for c in cks for l in c[2])
    trace = bytearray(total * 7)
    found = []

    def commit(st):
        msg = b"engine-final" + struct.pack("<4I", *[x & M32 for x in st]) + H(bytes(trace))
        return hmac.new(key, msg, hashlib.sha256).digest()

    def rec(ci, st, depth):
        if found:
            return
        if ci == len(cks):
            if commit(st) == tail:
                found.append((bytes(trace), st))
            return
        bits, obs, lanes = cks[ci]
        end = depth + sum(len(x) for x in lanes)
        idx = [0, 0, 0]

        def rec2(d, st2):
            if found:
                return
            if d == end:
                if disp_observation(st2, bits) == obs:
                    rec(ci + 1, st2, d)
                return
            for lane in range(3):
                if idx[lane] >= len(lanes[lane]):
                    continue
                eid, val, pre = lanes[lane][idx[lane]]
                ns = disp_step(st2, lane, eid, val, pre)
                if ns is None:
                    continue
                idx[lane] += 1
                off = d * 7
                v = val & M32
                trace[off] = lane
                trace[off + 1] = eid & 255
                trace[off + 2] = (eid >> 8) & 255
                trace[off + 3:off + 7] = struct.pack("<I", v)
                rec2(d + 1, ns)
                idx[lane] -= 1
                if found:
                    return

        rec2(depth, st)

    rec(0, disp_initial(key), 0)
    if not found:
        raise ValueError("no dispatch trace")
    trace, st = found[0]
    return H(b"carbon/archive/v3\x00" + key +
             struct.pack("<4I", *[x & M32 for x in st]) + H(trace))


# ---------------------------------------------------------------- driver
def unpack(zip_path, tmp):
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(tmp)
    base = os.path.join(tmp, "carbon-without-an-original")
    with tarfile.open(os.path.join(base, "export.tar")) as t:
        t.extractall(os.path.join(tmp, "export"))
    return os.path.join(base, "Carbon.apk"), os.path.join(tmp, "export", "dev.sr.carbon")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    default_zip = os.path.abspath(os.path.join(
        here, "..", "..", "challenges", "carbon-without-an-original",
        "input", "carbon-without-an-original.zip"))
    zip_path = sys.argv[1] if len(sys.argv) > 1 else default_zip
    tmp = tempfile.mkdtemp(prefix="carbon_")
    apk_path, app = unpack(zip_path, tmp)
    dbs = os.path.join(app, "databases")

    with zipfile.ZipFile(apk_path) as z:
        archive = z.read("assets/archive.bin")
    obj_v23 = open(os.path.join(app, "files", "objects", OBJ_V23), "rb").read()
    obj_v31 = open(os.path.join(app, "files", "objects", OBJ_V31), "rb").read()

    # 1. capsule history from the WAL (live DB capsules were zeroed)
    caps = wal_capsules(os.path.join(dbs, "cache.db-wal"))
    hdr_by_serial, keys_by_boot = {}, {}
    for c in caps:
        hdr_by_serial.setdefault(c["serial"], c["cap"][4:36])
        keys_by_boot.setdefault(c["boot"], set()).add(c["cap"][36:68])
    print("[*] WAL capsules: %d rows, serials %s, boots %d"
          % (len(caps), sorted(hdr_by_serial), len(keys_by_boot)))

    # installation basis matrices: capsule header as 16 LE u16
    bases = {}
    for serial, h in hdr_by_serial.items():
        vals = struct.unpack("<16H", h)
        m = [list(vals[i * 4:(i + 1) * 4]) for i in range(4)]
        matinv(m)                                   # headers are in SL(4,P)
        bases[serial] = m

    # 2. journal deliveries -> Journal v2 entries
    con = sqlite3.connect(os.path.join(dbs, "journal.db"))
    rows = con.execute("select user_id, slot, boot, wall_ms, ticket, wire "
                       "from deliveries order by wall_ms").fetchall()
    entries, skipped = [], 0
    for _uid, _slot, boot, wall, _ticket, wire in rows:
        pt = None
        for key in keys_by_boot.get(boot, ()):
            pt = decrypt_wire(key, wire)
            if pt:
                break
        if pt is None:
            skipped += 1
            continue
        entries.append(parse_entry(pt, wall))
    raw_count = len(entries)
    seen, uniq = set(), []
    for e in entries:
        if e["identity"] not in seen:
            seen.add(e["identity"])
            uniq.append(e)
    entries = uniq
    print("[*] journal entries: %d decrypted (%d undecryptable), %d unique"
          % (raw_count, skipped, len(entries)))

    # 3. historical v2 archive key: the state at the 12->23 migration.
    #    Only the two installations that shared the note before the upgrade
    #    (29 = original work profile, 64 = its restored clone) and heights
    #    up to 114 reproduce the migration object's receipt.
    doc_entries = [e for e in entries if e["document"] == NOTE_DOC]
    authors = sorted({e["author"] for e in doc_entries})
    heights = sorted({jheight(e) for e in doc_entries})
    walls = sorted({e["wall"] for e in doc_entries})
    v2 = None
    tried = 0
    for r in range(1, len(authors) + 1):
        for comb in itertools.combinations(authors, r):
            pool = [e for e in doc_entries if e["author"] in comb]
            for cutoff in heights + walls:
                sel = [e for e in pool
                       if (jheight(e) if cutoff in heights else e["wall"]) <= cutoff]
                if not sel:
                    continue
                try:
                    k = archive_key(sel, NOTE_DOC, bases)
                except Exception:
                    continue
                tried += 1
                try:
                    envelope_open(k, obj_v23, b"carbon/migrate/23")
                except ValueError:
                    continue
                v2 = k
                print("[*] v2 archive key (authors %s, cutoff %d, %d candidates): %s"
                      % (comb, cutoff, tried, k.hex()))
                break
            if v2:
                break
        if v2:
            break
    if v2 is None:
        raise SystemExit("v2 archive key not found")

    # 4. 12->23: Sequence payload, document id is the Merkle-root seed
    seq = envelope_open(v2, obj_v23, b"carbon/migrate/23")
    text = Reader(seq)
    text.i32()
    program_text = text.text()
    v23 = sequence_recover(v2, bytes.fromhex(NOTE_DOC), seq)
    print("[*] v23 sequence note: %r" % program_text)
    print("[*] v23 archive key: %s" % v23.hex())

    # 5. 23->31: Dispatch program, unique replay trace -> recovery code
    cks, tail = parse_dispatch(envelope_open(v23, obj_v31, b"carbon/migrate/31"))
    print("[*] dispatch: %d checkpoints, %d events"
          % (len(cks), sum(len(l) for c in cks for l in c[2])))
    recovery = dispatch_solve(v23, cks, tail)
    print("[*] v31 recovery code: %s" % recovery.hex())

    # 6. open the archived note
    note = envelope_open(recovery, archive, b"carbon/note/v31").decode()
    print("[+] note: %s" % note)
    if note.startswith("isfcr{") and note.endswith("}"):
        print("[+] FLAG: %s" % note)


if __name__ == "__main__":
    main()
