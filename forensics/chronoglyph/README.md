---
title: "Chronoglyph"
ctf: "CryoVault Finals"
date: 2026-10-24
category: forensics
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# Chronoglyph

## Summary

A single ext4 partition hides a 200-byte payload in the sub-second
`i_crtime_extra` fields of 160 inodes (a custom scheme documented in
`paper/draft-v1.md`). Decoding it yields the offset/length of a LUKS2 volume
plus its passphrase. Inside that volume the visible files are all decoys; the
real note is a deleted, zlib-compressed git blob that is still sitting in the
filesystem's unallocated blocks.

## Solution

### Step 1: Rebuild the timestamp decoder

The image is a raw ext4 filesystem (no partition table) whose home directory
contains a research tree for a tool called *chronoglyph*. `encode.py` has its
constants stripped, but `paper/draft-v1.md` is normative:

* `uuid_bytes` = the raw 16-byte ext4 superblock UUID.
* Candidates are regular-file inodes `>= 12`, sorted ascending.
* `permute()` is a Fisher–Yates shuffle driven by an HMAC-SHA256 byte stream
  (`HmacStream`), keyed by `uuid_bytes` with domain `b"chronoglyph/v1/perm"`.
* The first 160 permuted inodes are *marked*. For each marked inode
  `tag16 = HMAC_SHA256(uuid, b"chronoglyph/v1/tag:" + inode_le32)[:2]` must
  equal the low 16 bits of `i_crtime_extra >> 2`.
* The 10 payload bits per marked inode are bits 16..25 of that nanosecond
  value, MSB-first, giving exactly 200 bytes.

The 200-byte blob is `"CGLYPHv1"`, `le64 inner_offset`, `le64 inner_length`,
a NUL-padded passphrase, zero padding and an HMAC-SHA256 over the first 168
bytes. Here it points at bytes `0x6400000..0x9400000` (exactly where the
ext4 filesystem ends) and yields the passphrase
`Z5JCHzgEXGvFPi53KeBhZrJH9TULvpN5dv39GRpfWcfZ3pMM`.

### Step 2: Unlock the LUKS2 volume and carve deleted git objects

The target region is a LUKS2 header (`cryptsetup luksOpen` with the recovered
passphrase opens immediately). The decrypted ext4 volume (`notes`) contains a
couple of dozen decoy files: 14 mails and a 2000-line `staging.log`, all full
of fake `isfcr{hex}` values, plus a small decoy git repo.

The tell is in `chat/.git/objects`: 11 empty fan-out directories (`16`, `23`,
`24`, `25`, `2f`, `47`, `4f`, `57`, `5c`, `df`, `e0`). They are the remains of
deleted git objects. Those objects are zlib-compressed, so they do not show up
in `strings`/`grep`, but their data blocks were never overwritten. Carving
zlib streams out of the ext4 unallocated blocks recovers five `blob` objects;
one of them contains the real note.

```python
#!/usr/bin/env python3
"""
Chronoglyph (CryoVault Finals 2026) -- full solve.

Pipeline
  1. Unpack evidence.zip -> evidence.img (a single raw ext4 partition).
  2. Rebuild the Chronoglyph v1 decoder from paper/draft-v1.md:
       - key = raw 16-byte ext4 superblock UUID
       - candidates = regular-file inodes >= 12, ascending
       - marked set = first 160 entries of the HMAC-SHA256 Fisher-Yates
         permutation
       - per marked inode: tag16 = HMAC(uuid, "chronoglyph/v1/tag:"+ino_le)[:2]
         must equal the low 16 bits of i_crtime_extra>>2
       - 10 payload bits per marked inode from bits 16..25 of that nsec value
     The recovered 200-byte blob is a header containing
       [8..16]  le64 inner_offset
       [16..24] le64 inner_length
       [24..88] LUKS passphrase
       [168..200] HMAC-SHA256(uuid, blob[0..168])
  3. Slice the inner region and unlock the LUKS2 volume with that passphrase.
  4. The decrypted ext4 ("notes") is mostly decoys.  Its git object store
     still contains empty fan-out directories (16, 23, 24, 25, 2f, ...):
     deleted, zlib-compressed git blobs.  Carve zlib streams out of the
     unallocated blocks and decompress them; the real note says
     "the real token for this quarter is: isfcr{...}".

Requires: cryptsetup (run as root).  No other third-party modules.
"""

import hashlib
import hmac
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ZIP = os.path.join(ROOT, "challenges", "chronoglyph", "input", "chronoglyph.zip")

TAG_DOMAIN = b"chronoglyph/v1/tag:"
PERM_DOMAIN = b"chronoglyph/v1/perm"
BITS_PER_FILE = 10
MARKED_FILES = 160
PAYLOAD_LEN = 200


# ---------------------------------------------------------------- ext4 basics
class Ext4:
    def __init__(self, data):
        self.data = data
        self.sb = data[1024:2048]
        sb = self.sb
        if struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
            raise ValueError("not an ext4 image")
        self.uuid = sb[0x68:0x78]
        self.inodes_count = struct.unpack_from("<I", sb, 0x00)[0]
        self.blocks_count = struct.unpack_from("<I", sb, 0x04)[0]
        self.first_data_block = struct.unpack_from("<I", sb, 0x14)[0]
        self.log_block_size = struct.unpack_from("<I", sb, 0x18)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, 0x20)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
        self.inode_size = struct.unpack_from("<H", sb, 0x58)[0]
        self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] or 32
        self.bs = 1024 << self.log_block_size
        self.gdt = (self.first_data_block + 1) * self.bs
        self.ngroups = (self.blocks_count - self.first_data_block
                        + self.blocks_per_group - 1) // self.blocks_per_group

    def gd(self, group):
        return self.gdt + group * self.desc_size

    def inode_offset(self, ino):
        g, idx = divmod(ino - 1, self.inodes_per_group)
        table = struct.unpack_from("<I", self.data, self.gd(g) + 8)[0]
        return table * self.bs + idx * self.inode_size

    def mode(self, ino):
        return struct.unpack_from("<H", self.data, self.inode_offset(ino))[0]

    def regular_inodes(self, min_ino=12):
        out = []
        for ino in range(min_ino, self.inodes_count + 1):
            if self.mode(ino) & 0xF000 == 0x8000:
                out.append(ino)
        return out

    def crtime_extra(self, ino):
        return struct.unpack_from("<I", self.data, self.inode_offset(ino) + 0x94)[0]

    def extents(self, ino):
        off = self.inode_offset(ino)
        flags = struct.unpack_from("<I", self.data, off + 0x20)[0]
        i_block = self.data[off + 0x28:off + 0x28 + 60]
        blocks = []
        if not flags & 0x80000:  # not extent-mapped: old block map
            for blk in struct.unpack("<15I", i_block):
                if blk:
                    blocks.append((blk, 1))
            return blocks
        magic, entries, _max, depth, _gen = struct.unpack_from("<HHHHI", i_block, 0)
        if magic != 0xF30A:
            return blocks
        if depth != 0:
            raise NotImplementedError("extent tree depth > 0 not needed here")
        for k in range(entries):
            _lblk, ln, hi, lo = struct.unpack_from("<IHHI", i_block, 12 + 12 * k)
            blocks.append(((hi << 32) | lo, ln))
        return blocks

    def allocated_blocks(self):
        alloc = set()
        for g in range(self.ngroups):
            bitmap = struct.unpack_from("<I", self.data, self.gd(g))[0]
            bm = self.data[bitmap * self.bs:(bitmap + 1) * self.bs]
            for i in range(self.blocks_per_group):
                if bm[i >> 3] >> (i & 7) & 1:
                    alloc.add(g * self.blocks_per_group + i
                              + (self.first_data_block if g == 0 else 0))
        return alloc

    def used_blocks(self):
        used = {0, 1}  # superblock + GDT (block numbers; superblock lives at 1024)
        for g in range(self.ngroups):
            d = self.gd(g)
            bbitmap, ibitmap, itable = struct.unpack_from("<III", self.data, d)
            used.add(bbitmap)
            used.add(ibitmap)
            n = (self.inodes_per_group * self.inode_size + self.bs - 1) // self.bs
            used.update(range(itable, itable + n))
        for ino in range(1, self.inodes_count + 1):
            if self.mode(ino) == 0:
                continue
            for start, length in self.extents(ino):
                used.update(range(start, start + length))
        return used

    def free_space(self):
        alloc = self.allocated_blocks()
        free = sorted(set(range(self.blocks_count)) - alloc)
        return b"".join(self.data[b * self.bs:(b + 1) * self.bs] for b in free)


# ------------------------------------------------------- Chronoglyph v1 codec
class HmacStream:
    """Deterministic byte stream from the paper's draft-v1.md."""

    def __init__(self, uuid_bytes):
        info = PERM_DOMAIN
        self.k = hmac.new(uuid_bytes, b"\x00" + info, hashlib.sha256).digest()
        self.v = hmac.new(self.k, b"\x01" + info, hashlib.sha256).digest()
        self.buf = b""

    def _refill(self):
        self.v = hmac.new(self.k, self.v, hashlib.sha256).digest()
        self.buf += self.v

    def take(self, n):
        while len(self.buf) < n:
            self._refill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def rand_below(stream, n):
    mask = (1 << n.bit_length()) - 1
    while True:
        x = int.from_bytes(stream.take(8), "big") & mask
        if x < n:
            return x


def permute(candidates, uuid_bytes):
    a = list(candidates)
    s = HmacStream(uuid_bytes)
    for i in range(len(a) - 1, 0, -1):
        j = rand_below(s, i + 1)
        a[i], a[j] = a[j], a[i]
    return a


def tag16(uuid_bytes, ino):
    return hmac.new(uuid_bytes, TAG_DOMAIN + struct.pack("<I", ino),
                    hashlib.sha256).digest()[:2]


def decode_chronoglyph(fs):
    marked = permute(fs.regular_inodes(12), fs.uuid)[:MARKED_FILES]
    bits, verified = [], 0
    for ino in marked:
        nsec = fs.crtime_extra(ino) >> 2
        if struct.pack("<H", nsec & 0xFFFF) == tag16(fs.uuid, ino):
            verified += 1
        bits.append(format((nsec >> 16) & 0x3FF, "010b"))
    if verified != MARKED_FILES:
        raise ValueError("tag check failed (%d/%d) -- wrong decoder"
                         % (verified, MARKED_FILES))

    bitstr = "".join(bits)
    payload = bytes(int(bitstr[i:i + 8], 2) for i in range(0, PAYLOAD_LEN * 8, 8))

    body = payload[:168]
    mac = payload[168:200]
    if not hmac.compare_digest(
            mac, hmac.new(fs.uuid, body, hashlib.sha256).digest()):
        raise ValueError("payload HMAC mismatch")

    inner_offset = struct.unpack("<Q", payload[8:16])[0]
    inner_length = struct.unpack("<Q", payload[16:24])[0]
    passphrase = payload[24:88].split(b"\x00", 1)[0]
    return inner_offset, inner_length, passphrase


# ------------------------------------------------------------------- LUKS2
def luks_open(region_bytes, passphrase):
    if os.geteuid() != 0:
        sys.exit("run as root (cryptsetup needs privileges)")

    tmpdir = tempfile.mkdtemp(prefix="cg_luks_")
    image = os.path.join(tmpdir, "inner.img")
    keyfile = os.path.join(tmpdir, "pass.txt")
    name = "cg_%d" % os.getpid()
    with open(image, "wb") as f:
        f.write(region_bytes)
    with open(keyfile, "wb") as f:
        f.write(passphrase)          # no trailing newline

    subprocess.run(["cryptsetup", "luksOpen", "--key-file", keyfile,
                    "--batch-mode", image, name], check=True)
    try:
        with open("/dev/mapper/" + name, "rb") as f:
            decrypted = f.read()
    finally:
        subprocess.run(["cryptsetup", "luksClose", name], check=True)
        shutil.rmtree(tmpdir, ignore_errors=True)
    return decrypted


# --------------------------------------------------- deleted git object carve
def carve_git_blobs(free_bytes):
    blobs = []
    seen = set()
    for sig in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
        start = 0
        while True:
            i = free_bytes.find(sig, start)
            if i < 0:
                break
            start = i + 1
            try:
                out = zlib.decompressobj().decompress(
                    free_bytes[i:i + (1 << 20)])
            except zlib.error:
                continue
            if len(out) < 10 or out in seen:
                continue
            seen.add(out)
            if re.match(rb"^(blob|tree|commit|tag) \d+\x00", out):
                blobs.append(out.split(b"\x00", 1)[1])
    return blobs


def main():
    work = tempfile.mkdtemp(prefix="cg_")
    try:
        with zipfile.ZipFile(ZIP) as z:
            z.extractall(work)
        img_path = os.path.join(work, "chronoglyph", "evidence.img")
        data = open(img_path, "rb").read()
        fs = Ext4(data)
        print("[*] outer ext4 uuid:", fs.uuid.hex())

        off, length, passphrase = decode_chronoglyph(fs)
        print("[*] payload ok: inner region %d..%d, passphrase %r"
              % (off, off + length, passphrase.decode()))

        inner = data[off:off + length]
        if inner[:6] != b"LUKS\xba\xbe":
            raise ValueError("inner region is not LUKS2")
        decrypted = luks_open(inner, passphrase)
        print("[*] LUKS opened, decrypted ext4: %d bytes" % len(decrypted))

        inner_fs = Ext4(decrypted)
        print("[*] inner uuid:", inner_fs.uuid.hex(),
              "| deleted git objects still in unallocated blocks")

        free = inner_fs.free_space()
        blobs = carve_git_blobs(free)
        print("[*] carved %d git blobs from unallocated space" % len(blobs))
        for body in blobs:
            text = body.decode("utf-8", "replace")
            if "real token" in text.lower():
                print("\n--- recovered note -----------------------------------")
                print(text.strip())
                print("-----------------------------------------------------")
                m = re.search(r"isfcr\{[^}\n]+\}", text)
                if m:
                    print("\nFLAG:", m.group(0))
                    return 0
        raise SystemExit("real-token blob not found")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
```

Output:

```
[*] outer ext4 uuid: 7ac3e5f19d414a68b2c75e0f12d3b4a9
[*] payload ok: inner region 104857600..155189248, passphrase 'Z5JCHzgEXGvFPi53KeBhZrJH9TULvpN5dv39GRpfWcfZ3pMM'
[*] LUKS opened, decrypted ext4: 33554432 bytes
[*] inner uuid: 41b0d8f26c934f1a9e22c0317a5f8d64 | deleted git objects still in unallocated blocks
[*] carved 5 git blobs from unallocated space

--- recovered note -----------------------------------
ignore the previous notes.

the real token for this quarter is:
isfcr{n4no_t1me_h0ld5_what_th3_j0urnal_f0rg0t_a71c3}

rotate at the next window.
-----------------------------------------------------

FLAG: isfcr{n4no_t1me_h0ld5_what_th3_j0urnal_f0rg0t_a71c3}
```

## Flag

```
isfcr{n4no_t1me_h0ld5_what_th3_j0urnal_f0rg0t_a71c3}
```
