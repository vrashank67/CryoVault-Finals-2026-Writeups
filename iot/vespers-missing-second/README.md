---
title: "Vesper's Missing Second"
ctf: "CryoVault Finals"
date: 2026-10-24
category: iot
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# Vesper's Missing Second

## Summary

The recovery bundle is a deterministic digital twin of an RV32IM fixture. The handover
record is sealed with HKDF-SHA256 over a canonical serialization of every RF frame the
gateway accepted, plus the original sensor vector that produced it. Reversing
`vesper.elf`, rebuilding the sensor/RF/NVM fixture, and solving the unknown powered-slot
count `Q` for all 144 boots from the journal, the receipts and the six VCD windows
recovers those vectors, which decrypts `record.sealed`.

## Solution

### Step 1: Understand the fixture and the sealed format

`BOARD.md` defines the contracts that matter:

- The MCU is reset every boot; NVM, sensor FIFO, RF bridge and gateway stay powered.
- A boot has `Q` powered slots (one metered MMIO command each) followed by `G` unpowered
  slots. RF lanes tick at the start of **every** slot, powered or not, and once the
  firmware sleeps the remaining powered slots still elapse.
- The sensor hub streams 16-bit entries (low byte first); deselecting or resetting after
  an odd number of data bytes discards the pending high byte and advances the cursor.
- Each submission gets a lane; `D = 60 + 12*((frame[2]^frame[3]) & 15)` slots later it is
  delivered to the gateway. Both lanes full means the submission is dropped.
- The journal is sampled every 6 boots (its RX/DUPLICATES/DROPPED are per-interval
  deltas), and `receipts.bin` lists the accepted frames in gateway acceptance order.

`FORMAT.md` fixes the handover serialization (`VESPER-HANDOVER\0\x01`, count, then
`u16 id`, `u8 N`, `N` original `u16` entries) and the seal: HKDF-SHA256 with the
serialization as IKM, salt = bytes 4..19 of `record.sealed`, info
`vesper/handover/v1`, then ChaCha20-Poly1305 with nonce at bytes 20..31 and the first
32 bytes as AAD.

### Step 2: Reverse the sealing routine

`vesper.elf` is a small stripped RV32IM image. Its logic (addresses from `0x10010`):

1. Read four 16-byte NVM records. A record is valid when it starts with `VP`, ends with
   `0xA5`, has `id ^ id_complement == 0xFFFF`, `byte14 == 0`, and
   `CRC-16/CCITT-FALSE(bytes 0..9) == bytes 10..11`. The valid record with the highest
   id supplies the frame identifier and the 32-bit rolling hash state `(a2, a3)` plus
   the 5-bit tag `a5`.
2. Read the first two FIFO entries. The vector length is
   `N = 5 + ((id ^ a3 ^ (entry0 & 0xff) ^ (entry1 >> 3)) & 3)`; `3..6` more entries are
   read and mixed into `(a2, a3, a5)` with the 32-bit mixer at `0x102a0`.
3. Build `frame = id | (hash_bits) | crc16`, stage it with six `op3` commands, submit
   with `op4`, then write the next record (`id+1`) into NVM slot `(id+1) & 3`, updating
   the hash state and `N`. A boot therefore executes `40 + 2*sel` metered commands
   (16+2*sel sensor, 7 stage/submit, 17 NVM writes). Truncation leaves half-read entries
   and partially written records, which the journal's memory/radio checks expose.

### Step 3: Solve Q for every boot and rebuild the acceptances

The six VCD windows give exact `Q` values (`(fall - rise - 10_000) / 20_000`): 25, 50,
38, 41, 13 and 3 for boots 11, 35, 59, 83, 107 and 131. Note boot 35 has `Q = 50` but
only 46 commands: the four extra powered slots still elapse and shift the RF lane
timing — counting service pulses instead of slots makes a boot look "one command short".

A step-by-step search over the `power.csv` ranges, pruned by the journal's cursor,
NVM CRC, radio-lane CRC and per-interval counters, by the receipt prefix
(interval + frame) and finally by `fram.bin`, leaves exactly one fixture history. The
27 acceptances and their exact sensor vectors are then serialized and decrypted.

The script below is the complete solve (the search takes several minutes):

```python
#!/usr/bin/env python3
"""Vesper's Missing Second - CryoVault Finals (IoT, 500 pts)

Complete solve: reconstruct the handover serialization from the acquisition
bundle, then decrypt record.sealed.

The bundle contains an RV32IM firmware image, a sensor replay FIFO, a power
schedule, a diagnostic journal, gateway receipts, six VCD capture windows and
the sealed handover record.  We re-implement the fixture (MCU firmware logic +
sensor hub + RF bridge + NVM) and search over the unknown number of powered
service slots Q for every boot, pruning with the journal, the receipts and the
final NVM image.  The resulting acceptances give the exact sensor vectors that
were sealed, which yields the HKDF input key material.

Usage: python solve.py [path/to/vespers-missing-second.zip]
"""
import sys, os, struct, zipfile, hashlib, hmac, tempfile
import re

# ---------------------------------------------------------------- utilities

def crc16(data, crc=0xFFFF):
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def chacha20poly1305_decrypt(key, nonce, data, aad):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(key).decrypt(nonce, data, aad)
    except ImportError:
        from Crypto.Cipher import ChaCha20_Poly1305
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(aad)
        return c.decrypt_and_verify(data[:-16], data[-16:])


# ---------------------------------------------------------------- input

def load_input(path):
    if os.path.isdir(path):
        d = path
        cleanup = None
    else:
        cleanup = None
        tmp = tempfile.mkdtemp(prefix="vesper_")
        with zipfile.ZipFile(path) as z:
            z.extractall(tmp)
        # the zip may contain a single top-level directory
        entries = os.listdir(tmp)
        d = os.path.join(tmp, entries[0]) if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])) else tmp
    files = {}
    for name in ["BOARD.md", "FORMAT.md", "vesper.elf", "record.sealed", "fram.bin",
                 "acquisition.bin", "power.csv", "journal.csv", "receipts.bin",
                 "capture.vcd", "capture-index.csv"]:
        p = os.path.join(d, name)
        if os.path.exists(p):
            files[name] = open(p, "rb").read()
    return files


# ---------------------------------------------------------------- VCD anchors

def capture_anchors(files):
    vcd = files["capture.vcd"].decode()
    idx = files["capture-index.csv"].decode()

    ids = {}
    for ln in vcd.splitlines():
        if ln.startswith("$var"):
            p = ln.split()
            ids[p[4]] = p[3]
    sid, pgid = ids["service"], ids["power_good"]
    cmdid, respid = ids["command"], ids["response"]

    vals = {}
    cur = 0
    last_service = 0
    pulses = []
    rises = []
    pfalls = []
    for ln in vcd.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if ln[0] == "#":
            cur = int(ln[1:])
        elif ln[0] in "01" and len(ln) >= 2:
            vid, v = ln[1:], int(ln[0])
            if vid == sid:
                if v == 1 and last_service == 0:
                    pulses.append((cur, vals.get(cmdid, 0), vals.get(respid, 0)))
                last_service = v
            vals[vid] = v
            if vid == pgid:
                if v == 1:
                    rises.append(cur)
                else:
                    pfalls.append(cur)
        elif ln[0] in "bB":
            m = re.match(r"b([01xXzZ]+)\s+(\S+)", ln)
            if m:
                vals[m.group(2)] = int(m.group(1), 2)

    index = []
    for ln in idx.splitlines()[1:]:
        if ln.strip():
            b, st = ln.split(",")
            index.append((int(b), int(st)))

    windows = []
    for i, r in enumerate(rises):
        end = rises[i + 1] if i + 1 < len(rises) else 10 ** 18
        windows.append((r, [p for p in pulses if r <= p[0] < end]))

    anchors = {}
    for (boot, start), (rise, ws) in zip(index, windows):
        fall = min(f for f in pfalls if f > rise)
        q = (fall - rise - 10000) // 20000
        datas = []
        frame = []
        for t, cmd, resp in ws:
            op = cmd >> 24
            if op == 2 and (cmd & 0xFFFFFF) == 0:
                datas.append(resp & 0xFF)
            elif op == 3:
                frame.append(cmd & 0xFF)
        fr = bytes(frame) if len(frame) == 6 else None
        anchors[boot] = {"Q": q, "data_bytes": len(datas), "frame": fr}
    return anchors


# ---------------------------------------------------------------- firmware model

def decode_nvm(nvm):
    """Read the four VP records; return (id, a2, a3, a5) of the highest valid one."""
    best = -1
    a1, a2, a3, a5 = 0, 0x9137, 0x6D2B, 0
    for slot in range(4):
        r = nvm[16 * slot:16 * slot + 16]
        if r[0] != 0x56 or r[1] != 0x50 or r[15] != 0xA5 or r[14] != 0:
            continue
        rid = r[2] | (r[3] << 8)
        if ((r[12] | (r[13] << 8)) ^ rid) != 0xFFFF:
            continue
        if crc16(r[:10]) != (r[10] | (r[11] << 8)):
            continue
        if rid > best:
            best = rid
            a1, a3 = rid, r[4] | (r[5] << 8)
            a2, a5 = r[6] | (r[7] << 8), r[8]
    return a1, a2, a3, a5


def hash_vector(vec, a2, a3, a5):
    """Reversed rolling mixer (32-bit) from 0x102a0..0x102f4."""
    seed = 0xFFFFA73D
    for i, e in enumerate(vec):
        t3 = (i * 49 + (e & 0x3FFF) + 49) & 0xFFFFFFFF
        t2 = ((e ^ seed) + a2) & 0xFFFFFFFF
        t2 = ((t2 << 3) | ((t2 >> 13) & 7)) & 0xFFFFFFFF
        a3 = (a3 ^ t3) & 0xFFFFFFFF
        a3 = (((a3 << 5) | ((a3 >> 11) & 0x1F)) + a2) & 0xFFFFFFFF
        a2 = (a3 ^ t2) & 0xFFFFFFFF
    a5 = (a5 ^ (a3 >> 2) ^ (a2 >> 5)) & 0x1F
    return a2, a3, a5


def make_frame(a1, a2, a3, a5):
    f = bytes([a1 & 0xFF, (a1 >> 8) & 0xFF, a5 & 0x1F,
               ((a2 >> 8) + (a3 >> 11)) & 7, 0, 0])
    c = crc16(f[:4])
    return f[:4] + bytes([c & 0xFF, c >> 8])


def make_record(a1, a2, a3, a5, n):
    r = bytearray(16)
    r[0:2] = b"VP"
    nid = (a1 + 1) & 0xFFFF
    r[2], r[3] = nid & 0xFF, nid >> 8
    r[4], r[5] = a3 & 0xFF, (a3 >> 8) & 0xFF
    r[6], r[7] = a2 & 0xFF, (a2 >> 8) & 0xFF
    r[8], r[9] = a5 & 0xFF, n
    c = crc16(r[:10])
    r[10], r[11] = c & 0xFF, c >> 8
    inv = (~nid) & 0xFFFF
    r[12], r[13] = inv & 0xFF, inv >> 8
    r[14], r[15] = 0, 0xA5
    return bytes(r)


def sensor_cursor_after(cursor, Q, sel):
    """FIFO cursor after Q metered commands of the boot's sensor phase."""
    sensor_cmds = 16 + 2 * sel
    idx, half = cursor, 0
    for c in range(1, min(Q, sensor_cmds) + 1):
        if c in (1, 2, 8, 9):
            continue
        if c == 7 or c == sensor_cmds:
            if half:
                idx += 1
                half = 0
            continue
        if half:
            half, idx = 0, idx + 1
        else:
            half = 1
    if half:
        idx += 1
    return idx


def boot_step(nvm, cursor, entries, Q):
    """One boot: returns (nvm, cursor, n, sel, frame, vector, record)."""
    a1, a2, a3, a5 = decode_nvm(nvm)
    e1 = entries[cursor]
    e2 = entries[cursor + 1]
    sel = (a1 ^ a3 ^ (e1 & 0xFF) ^ (e2 >> 3)) & 3
    n = 5 + sel
    vec = entries[cursor:cursor + n]
    cursor2 = sensor_cursor_after(cursor, Q, sel)
    frame = record = None
    nvm2 = bytearray(nvm)
    sub_idx = 23 + 2 * sel
    if Q >= sub_idx and len(vec) == n:
        ha2, ha3, ha5 = hash_vector(vec, a2, a3, a5)
        frame = make_frame(a1, ha2, ha3, ha5)
        record = make_record(a1, ha2, ha3, ha5, n)
        nw = min(17, max(0, Q - sub_idx))
        slot = (a1 + 1) & 3
        base = 16 * slot
        if nw > 0:
            nvm2[base + 15] = 0
            for j in range(min(nw - 1, 15)):
                nvm2[base + j] = record[j]
            if nw >= 17:
                nvm2[base + 15] = 0xA5
    return bytes(nvm2), cursor2, n, sel, frame, tuple(vec), record


# ---------------------------------------------------------------- search

def solve(files):
    entries = list(struct.unpack("<4096H", files["acquisition.bin"]))

    power = []
    for ln in files["power.csv"].decode().splitlines()[1:]:
        b, mn, mx, off = [int(x) for x in ln.split(",")]
        power.append((mn, mx, off))

    rows = []
    for ln in files["journal.csv"].decode().splitlines()[1:]:
        p = ln.split(",")
        rows.append(dict(last_boot=int(p[0]), cursor=int(p[1]), memory_check=int(p[2]),
                         rx=int(p[3]), duplicates=int(p[4]), radio_check=int(p[5]),
                         dropped=int(p[6])))
    row_for_boot = {r["last_boot"]: r for r in rows}

    raw = files["receipts.bin"]
    n_receipts = struct.unpack_from("<I", raw, 4)[0]
    receipts = []
    for i in range(n_receipts):
        interval, = struct.unpack_from("<H", raw, 8 + 8 * i)
        receipts.append((interval, raw[10 + 8 * i:16 + 8 * i]))

    fram_final = files["fram.bin"]

    # VCD anchors: exact Q, exact start cursor (row cursor - entries consumed),
    # and the exact frame the captured boot produced.
    anchors = capture_anchors(files)
    for boot, a in anchors.items():
        row = row_for_boot[boot]
        consumed = (a["data_bytes"] + 1) // 2
        a["cursor"] = row["cursor"] - consumed
        a["Q"] = int(a["Q"])

    def radio_check(lanes):
        blob = bytearray()
        for lane in lanes:
            if lane is None:
                blob += b"\x00" * 9
            else:
                blob += bytes([1]) + struct.pack("<H", lane[1]) + lane[0]
        return crc16(blob)

    def advance(lane):
        rem = lane[1] - 1
        return None if rem == 0 else (lane[0], rem, lane[2], lane[3]), rem

    def run_boot(state, b, Q):
        (nvm, cursor, l0, l1, seen, irx, idup, idrop, k, acc) = state
        G = power[b][2]
        nvm2, cursor2, n, sel, frame, vec, rec = boot_step(nvm, cursor, entries, Q)
        sub_idx = 23 + 2 * sel
        lanes = [l0, l1]
        deliveries = []
        for s in range(1, Q + G + 1):
            for i in range(2):
                lane = lanes[i]
                if lane is None:
                    continue
                nl, rem = advance(lane)
                if nl is None:
                    deliveries.append(lane)
                lanes[i] = nl
            if s <= Q and s == sub_idx and frame is not None:
                if lanes[0] is not None and lanes[1] is not None:
                    idrop += 1
                else:
                    d = 60 + 12 * ((frame[2] ^ frame[3]) & 15)
                    lanes[0 if lanes[0] is None else 1] = (frame, d, vec, b)
        if b == 143:  # final drain: 512 unpowered slots
            for _ in range(512):
                for i in range(2):
                    lane = lanes[i]
                    if lane is None:
                        continue
                    nl, rem = advance(lane)
                    if nl is None:
                        deliveries.append(lane)
                    lanes[i] = nl
        seen = set(seen)
        acc = list(acc)
        for lane in deliveries:
            f = lane[0]
            irx += 1
            ident = f[0] | (f[1] << 8)
            if ident in seen:
                idup += 1
            else:
                iv = b // 6
                if k >= len(receipts):
                    return None
                if receipts[k][0] != iv or receipts[k][1] != f:
                    return None
                seen.add(ident)
                acc.append((iv, f, lane[2]))
                k += 1
        return (nvm2, cursor2, lanes[0], lanes[1], frozenset(seen), irx, idup, idrop, k, tuple(acc))

    def row_ok(state, b):
        nvm, cursor, l0, l1, seen, irx, idup, idrop, k, acc = state
        row = row_for_boot[b]
        return (cursor == row["cursor"] and crc16(nvm) == row["memory_check"]
                and radio_check([l0, l1]) == row["radio_check"]
                and irx == row["rx"] and idup == row["duplicates"]
                and idrop == row["dropped"])

    init = (b"\xff" * 64, 0, None, None, frozenset(), 0, 0, 0, 0, tuple())
    states = {init: init}

    for b in range(144):
        mn, mx, G = power[b]
        qs = [anchors[b]["Q"]] if b in anchors else list(range(mn, mx + 1))
        row = row_for_boot.get(b)
        row_b = b - (b % 6) + 5
        tgt_row = row_for_boot[row_b]
        tgt = tgt_row["cursor"]
        newstates = {}
        for state in states.values():
            if b in anchors and state[1] != anchors[b]["cursor"]:
                continue
            if state[1] > tgt or state[1] + 8 * (row_b - b + 1) < tgt:
                continue
            for Q in qs:
                ns = run_boot(state, b, Q)
                if ns is None:
                    continue
                if ns[5] > tgt_row["rx"] or ns[6] > tgt_row["duplicates"] or ns[7] > tgt_row["dropped"]:
                    continue
                if b in anchors and anchors[b]["frame"] is not None:
                    # captured boot must actually produce the captured frame
                    nvm2, cursor2, n, sel, frame, vec, rec = boot_step(state[0], state[1], entries, Q)
                    if frame != anchors[b]["frame"]:
                        continue
                if row is not None:
                    if not row_ok(ns, b):
                        continue
                    ns = ns[:5] + (0, 0, 0) + ns[8:]
                newstates[ns] = ns
        states = newstates
        if not states:
            raise RuntimeError("no consistent fixture state at boot %d" % b)

    good = [s for s in states.values()
            if s[8] == len(receipts) and s[0] == fram_final]
    if len(good) != 1:
        raise RuntimeError("expected one fixture history, found %d" % len(good))
    return good[0][9]


# ---------------------------------------------------------------- seal

def build_serialization(accepted):
    ser = bytearray(b"VESPER-HANDOVER\x00\x01")
    ser += struct.pack("<I", len(accepted))
    for iv, frame, vec in accepted:
        ident = frame[0] | (frame[1] << 8)
        ser += struct.pack("<H", ident)
        ser += bytes([len(vec)])
        for v in vec:
            ser += struct.pack("<H", v)
    return bytes(ser)


def main():
    zpath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "..", "challenges", "vespers-missing-second",
        "input", "vespers-missing-second.zip")
    files = load_input(zpath)

    accepted = solve(files)
    ikm = build_serialization(accepted)

    sealed = files["record.sealed"]
    assert sealed[:4] == b"VSR1"
    salt = sealed[4:20]
    nonce = sealed[20:32]
    aad = sealed[:32]
    key = hkdf_sha256(ikm, salt, b"vesper/handover/v1", 32)
    plaintext = chacha20poly1305_decrypt(key, nonce, sealed[32:], aad)
    print(plaintext.decode())


if __name__ == "__main__":
    main()

```

Output:

```
isfcr{fd0a085830b0802f234486bd05c201818fb469ae02c597cd}
```

## Flag

```
isfcr{fd0a085830b0802f234486bd05c201818fb469ae02c597cd}
```
