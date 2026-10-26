#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read Receipt (RR3-063) -- QUIC v1 / HTTP-3 / QPACK transit-capsule decoder.

Reads the two-interface pcapng (`uplink.pcapng`), merges the acquisition
interfaces using each interface's if_tsresol / if_tsoffset, reassembles the
IPv4 fragments that are deliberately split across the two interfaces,
removes QUIC header protection, reconstructs packet numbers, verifies the
AES-GCM (or ChaCha20-Poly1305) tags with keys derived from the capsule's
direction-specific traffic secrets, decodes HTTP/3 streams and QPACK field
sections (static table + literals + Huffman, dynamic table tolerated), and
then validates the rr-ledger/1 hash chain against the capsule's
ticket / length / root.

Usage
-----
    python solve.py ../capsule.json                 # full decode -> ledger.json
    python solve.py ../capsule.json --pcap ../uplink.pcapng --out ledger.json
    python solve.py --parse-only                    # no secrets needed
    python solve.py --parse-only --pcap ../uplink.pcapng --dump-packets 20

The capsule may be a JSON document, or the raw receipt plaintext that starts
with b"RRTC5\\x00" followed by the JSON document.  Field naming is resolved
tolerantly (see NOTES.md); anything unresolved can be supplied explicitly:

    --client-secret HEX  --server-secret HEX  --cipher NAME  --cid-len N
    --next-pn-client N   --next-pn-server N   --ticket HEX  --root HEX
    --length N

Dependencies: Python 3.8+ standard library, plus either `cryptography` or
`pycryptodome` for AES-GCM / AES-ECB / ChaCha20.  Both are present in the
challenge environment.  scapy is NOT used.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import sys
from collections import defaultdict
from fractions import Fraction

# ---------------------------------------------------------------------------
# Crypto backends (cryptography preferred, pycryptodome fallback)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag as _InvalidTag

    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False
    _InvalidTag = Exception

try:
    from Crypto.Cipher import AES as _PCAES
    from Crypto.Cipher import ChaCha20_Poly1305 as _PCCHACHA

    HAVE_PYCRYPTODOME = True
except Exception:  # pragma: no cover
    HAVE_PYCRYPTODOME = False

CRYPTO_AVAILABLE = HAVE_CRYPTOGRAPHY or HAVE_PYCRYPTODOME


# ---------------------------------------------------------------------------
# Embedded QPACK static table (RFC 9204 Appendix A, 99 entries, 0-based)
# and HPACK/QPACK Huffman code (RFC 7541 Appendix B, same table)
# ---------------------------------------------------------------------------
HUFFMAN_CODES = {
    0: (0x1ff8, 13),
    1: (0x7fffd8, 23),
    2: (0xfffffe2, 28),
    3: (0xfffffe3, 28),
    4: (0xfffffe4, 28),
    5: (0xfffffe5, 28),
    6: (0xfffffe6, 28),
    7: (0xfffffe7, 28),
    8: (0xfffffe8, 28),
    9: (0xffffea, 24),
    10: (0x3ffffffc, 30),
    11: (0xfffffe9, 28),
    12: (0xfffffea, 28),
    13: (0x3ffffffd, 30),
    14: (0xfffffeb, 28),
    15: (0xfffffec, 28),
    16: (0xfffffed, 28),
    17: (0xfffffee, 28),
    18: (0xfffffef, 28),
    19: (0xffffff0, 28),
    20: (0xffffff1, 28),
    21: (0xffffff2, 28),
    22: (0x3ffffffe, 30),
    23: (0xffffff3, 28),
    24: (0xffffff4, 28),
    25: (0xffffff5, 28),
    26: (0xffffff6, 28),
    27: (0xffffff7, 28),
    28: (0xffffff8, 28),
    29: (0xffffff9, 28),
    30: (0xffffffa, 28),
    31: (0xffffffb, 28),
    32: (0x14, 6),
    33: (0x3f8, 10),
    34: (0x3f9, 10),
    35: (0xffa, 12),
    36: (0x1ff9, 13),
    37: (0x15, 6),
    38: (0xf8, 8),
    39: (0x7fa, 11),
    40: (0x3fa, 10),
    41: (0x3fb, 10),
    42: (0xf9, 8),
    43: (0x7fb, 11),
    44: (0xfa, 8),
    45: (0x16, 6),
    46: (0x17, 6),
    47: (0x18, 6),
    48: (0x0, 5),
    49: (0x1, 5),
    50: (0x2, 5),
    51: (0x19, 6),
    52: (0x1a, 6),
    53: (0x1b, 6),
    54: (0x1c, 6),
    55: (0x1d, 6),
    56: (0x1e, 6),
    57: (0x1f, 6),
    58: (0x5c, 7),
    59: (0xfb, 8),
    60: (0x7ffc, 15),
    61: (0x20, 6),
    62: (0xffb, 12),
    63: (0x3fc, 10),
    64: (0x1ffa, 13),
    65: (0x21, 6),
    66: (0x5d, 7),
    67: (0x5e, 7),
    68: (0x5f, 7),
    69: (0x60, 7),
    70: (0x61, 7),
    71: (0x62, 7),
    72: (0x63, 7),
    73: (0x64, 7),
    74: (0x65, 7),
    75: (0x66, 7),
    76: (0x67, 7),
    77: (0x68, 7),
    78: (0x69, 7),
    79: (0x6a, 7),
    80: (0x6b, 7),
    81: (0x6c, 7),
    82: (0x6d, 7),
    83: (0x6e, 7),
    84: (0x6f, 7),
    85: (0x70, 7),
    86: (0x71, 7),
    87: (0x72, 7),
    88: (0xfc, 8),
    89: (0x73, 7),
    90: (0xfd, 8),
    91: (0x1ffb, 13),
    92: (0x7fff0, 19),
    93: (0x1ffc, 13),
    94: (0x3ffc, 14),
    95: (0x22, 6),
    96: (0x7ffd, 15),
    97: (0x3, 5),
    98: (0x23, 6),
    99: (0x4, 5),
    100: (0x24, 6),
    101: (0x5, 5),
    102: (0x25, 6),
    103: (0x26, 6),
    104: (0x27, 6),
    105: (0x6, 5),
    106: (0x74, 7),
    107: (0x75, 7),
    108: (0x28, 6),
    109: (0x29, 6),
    110: (0x2a, 6),
    111: (0x7, 5),
    112: (0x2b, 6),
    113: (0x76, 7),
    114: (0x2c, 6),
    115: (0x8, 5),
    116: (0x9, 5),
    117: (0x2d, 6),
    118: (0x77, 7),
    119: (0x78, 7),
    120: (0x79, 7),
    121: (0x7a, 7),
    122: (0x7b, 7),
    123: (0x7ffe, 15),
    124: (0x7fc, 11),
    125: (0x3ffd, 14),
    126: (0x1ffd, 13),
    127: (0xffffffc, 28),
    128: (0xfffe6, 20),
    129: (0x3fffd2, 22),
    130: (0xfffe7, 20),
    131: (0xfffe8, 20),
    132: (0x3fffd3, 22),
    133: (0x3fffd4, 22),
    134: (0x3fffd5, 22),
    135: (0x7fffd9, 23),
    136: (0x3fffd6, 22),
    137: (0x7fffda, 23),
    138: (0x7fffdb, 23),
    139: (0x7fffdc, 23),
    140: (0x7fffdd, 23),
    141: (0x7fffde, 23),
    142: (0xffffeb, 24),
    143: (0x7fffdf, 23),
    144: (0xffffec, 24),
    145: (0xffffed, 24),
    146: (0x3fffd7, 22),
    147: (0x7fffe0, 23),
    148: (0xffffee, 24),
    149: (0x7fffe1, 23),
    150: (0x7fffe2, 23),
    151: (0x7fffe3, 23),
    152: (0x7fffe4, 23),
    153: (0x1fffdc, 21),
    154: (0x3fffd8, 22),
    155: (0x7fffe5, 23),
    156: (0x3fffd9, 22),
    157: (0x7fffe6, 23),
    158: (0x7fffe7, 23),
    159: (0xffffef, 24),
    160: (0x3fffda, 22),
    161: (0x1fffdd, 21),
    162: (0xfffe9, 20),
    163: (0x3fffdb, 22),
    164: (0x3fffdc, 22),
    165: (0x7fffe8, 23),
    166: (0x7fffe9, 23),
    167: (0x1fffde, 21),
    168: (0x7fffea, 23),
    169: (0x3fffdd, 22),
    170: (0x3fffde, 22),
    171: (0xfffff0, 24),
    172: (0x1fffdf, 21),
    173: (0x3fffdf, 22),
    174: (0x7fffeb, 23),
    175: (0x7fffec, 23),
    176: (0x1fffe0, 21),
    177: (0x1fffe1, 21),
    178: (0x3fffe0, 22),
    179: (0x1fffe2, 21),
    180: (0x7fffed, 23),
    181: (0x3fffe1, 22),
    182: (0x7fffee, 23),
    183: (0x7fffef, 23),
    184: (0xfffea, 20),
    185: (0x3fffe2, 22),
    186: (0x3fffe3, 22),
    187: (0x3fffe4, 22),
    188: (0x7ffff0, 23),
    189: (0x3fffe5, 22),
    190: (0x3fffe6, 22),
    191: (0x7ffff1, 23),
    192: (0x3ffffe0, 26),
    193: (0x3ffffe1, 26),
    194: (0xfffeb, 20),
    195: (0x7fff1, 19),
    196: (0x3fffe7, 22),
    197: (0x7ffff2, 23),
    198: (0x3fffe8, 22),
    199: (0x1ffffec, 25),
    200: (0x3ffffe2, 26),
    201: (0x3ffffe3, 26),
    202: (0x3ffffe4, 26),
    203: (0x7ffffde, 27),
    204: (0x7ffffdf, 27),
    205: (0x3ffffe5, 26),
    206: (0xfffff1, 24),
    207: (0x1ffffed, 25),
    208: (0x7fff2, 19),
    209: (0x1fffe3, 21),
    210: (0x3ffffe6, 26),
    211: (0x7ffffe0, 27),
    212: (0x7ffffe1, 27),
    213: (0x3ffffe7, 26),
    214: (0x7ffffe2, 27),
    215: (0xfffff2, 24),
    216: (0x1fffe4, 21),
    217: (0x1fffe5, 21),
    218: (0x3ffffe8, 26),
    219: (0x3ffffe9, 26),
    220: (0xffffffd, 28),
    221: (0x7ffffe3, 27),
    222: (0x7ffffe4, 27),
    223: (0x7ffffe5, 27),
    224: (0xfffec, 20),
    225: (0xfffff3, 24),
    226: (0xfffed, 20),
    227: (0x1fffe6, 21),
    228: (0x3fffe9, 22),
    229: (0x1fffe7, 21),
    230: (0x1fffe8, 21),
    231: (0x7ffff3, 23),
    232: (0x3fffea, 22),
    233: (0x3fffeb, 22),
    234: (0x1ffffee, 25),
    235: (0x1ffffef, 25),
    236: (0xfffff4, 24),
    237: (0xfffff5, 24),
    238: (0x3ffffea, 26),
    239: (0x7ffff4, 23),
    240: (0x3ffffeb, 26),
    241: (0x7ffffe6, 27),
    242: (0x3ffffec, 26),
    243: (0x3ffffed, 26),
    244: (0x7ffffe7, 27),
    245: (0x7ffffe8, 27),
    246: (0x7ffffe9, 27),
    247: (0x7ffffea, 27),
    248: (0x7ffffeb, 27),
    249: (0xffffffe, 28),
    250: (0x7ffffec, 27),
    251: (0x7ffffed, 27),
    252: (0x7ffffee, 27),
    253: (0x7ffffef, 27),
    254: (0x7fffff0, 27),
    255: (0x3ffffee, 26),
    256: (0x3fffffff, 30),
}

QPACK_STATIC = [
    (':authority', ''),
    (':path', '/'),
    ('age', '0'),
    ('content-disposition', ''),
    ('content-length', '0'),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('referer', ''),
    ('set-cookie', ''),
    (':method', 'CONNECT'),
    (':method', 'DELETE'),
    (':method', 'GET'),
    (':method', 'HEAD'),
    (':method', 'OPTIONS'),
    (':method', 'POST'),
    (':method', 'PUT'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '103'),
    (':status', '200'),
    (':status', '304'),
    (':status', '404'),
    (':status', '503'),
    ('accept', '*/*'),
    ('accept', 'application/dns-'),
    ('accept-encoding', 'gzip, deflate, br'),
    ('accept-ranges', 'bytes'),
    ('access-control-allow-headers', 'cache-control'),
    ('access-control-allow-headers', 'content-type'),
    ('access-control-allow-origin', '*'),
    ('cache-control', 'max-age=0'),
    ('cache-control', 'max-age=2592000'),
    ('cache-control', 'max-age=604800'),
    ('cache-control', 'no-cache'),
    ('cache-control', 'no-store'),
    ('cache-control', 'public, max-'),
    ('content-encoding', 'br'),
    ('content-encoding', 'gzip'),
    ('content-type', 'application/dns-'),
    ('content-type', 'application/'),
    ('content-type', 'application/json'),
    ('content-type', 'application/x-www-'),
    ('content-type', 'image/gif'),
    ('content-type', 'image/jpeg'),
    ('content-type', 'image/png'),
    ('content-type', 'text/css'),
    ('content-type', 'text/html;'),
    ('content-type', 'text/plain'),
    ('content-type', 'text/'),
    ('range', 'bytes=0-'),
    ('strict-transport-security', 'max-age=31536000'),
    ('strict-transport-security', 'max-age=31536000;'),
    ('strict-transport-security', 'max-age=31536000;'),
    ('vary', 'accept-encoding'),
    ('vary', 'origin'),
    ('x-content-type-options', 'nosniff'),
    ('x-xss-protection', '1; mode=block'),
    (':status', '100'),
    (':status', '204'),
    (':status', '206'),
    (':status', '302'),
    (':status', '400'),
    (':status', '403'),
    (':status', '421'),
    (':status', '425'),
    (':status', '500'),
    ('accept-language', ''),
    ('access-control-allow-credentials', 'FALSE'),
    ('access-control-allow-credentials', 'TRUE'),
    ('access-control-allow-headers', '*'),
    ('access-control-allow-methods', 'get'),
    ('access-control-allow-methods', 'get, post, options'),
    ('access-control-allow-methods', 'options'),
    ('access-control-expose-headers', 'content-length'),
    ('access-control-request-headers', 'content-type'),
    ('access-control-request-method', 'get'),
    ('access-control-request-method', 'post'),
    ('alt-svc', 'clear'),
    ('authorization', ''),
    ('content-security-policy', "script-src 'none';"),
    ('early-data', '1'),
    ('expect-ct', ''),
    ('forwarded', ''),
    ('if-range', ''),
    ('origin', ''),
    ('purpose', 'prefetch'),
    ('server', ''),
    ('timing-allow-origin', '*'),
    ('upgrade-insecure-requests', '1'),
    ('user-agent', ''),
    ('x-forwarded-for', ''),
    ('x-frame-options', 'deny'),
    ('x-frame-options', 'sameorigin'),
]



# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
class NeedMore(Exception):
    """Not enough bytes to decode a complete item yet (incremental parsers)."""


class QpackError(Exception):
    pass


class Blocked(QpackError):
    """Field section references a dynamic-table entry that has not arrived yet."""


class QuicError(Exception):
    pass


def be16(buf, off=0):
    return struct.unpack_from(">H", buf, off)[0]


def be32(buf, off=0):
    return struct.unpack_from(">I", buf, off)[0]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hkdf_expand(prk, info, length, hash_name):
    """RFC 5869 HKDF-Expand."""
    h = getattr(hashlib, hash_name)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), h).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf_expand_label(secret, label, context, length, hash_name):
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 7.1); QUIC prefixes 'tls13 '."""
    label_full = b"tls13 " + (label.encode() if isinstance(label, str) else label)
    if len(label_full) > 255 or len(context) > 255:
        raise QuicError("HKDF label/context too long")
    info = (
        struct.pack(">H", length)
        + bytes([len(label_full)])
        + label_full
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(secret, info, length, hash_name)


# QUIC varint (RFC 9000 16)
def varint_size(first_byte):
    return 1 << (first_byte >> 6)


def read_varint(data, pos=0):
    """Decode a QUIC varint at data[pos]; raises NeedMore if incomplete."""
    if pos >= len(data):
        raise NeedMore
    b = data[pos]
    size = 1 << (b >> 6)
    if pos + size > len(data):
        raise NeedMore
    if size == 1:
        return b & 0x3F, pos + 1
    val = b & 0x3F
    for i in range(1, size):
        val = (val << 8) | data[pos + i]
    return val, pos + size


def read_varint_loose(data, pos=0):
    """Decode a varint, returning (None, pos) if incomplete (no exception)."""
    try:
        return read_varint(data, pos)
    except NeedMore:
        return None, pos


def encode_varint(value):
    if value < 0:
        raise ValueError
    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return struct.pack(">H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack(">I", value | 0x80000000)
    if value < 1 << 62:
        return struct.pack(">Q", value | 0xC000000000000000)
    raise ValueError("varint too large")


def read_prefixed_int(data, pos, prefix_bits):
    """RFC 9204 4.1.1 prefixed integer; raises NeedMore on truncation."""
    if pos >= len(data):
        raise NeedMore
    mask = (1 << prefix_bits) - 1
    b = data[pos]
    pos += 1
    val = b & mask
    if val < mask:
        return val, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise NeedMore
        b = data[pos]
        pos += 1
        val += (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return val, pos
        if shift > 63:
            raise QpackError("prefixed integer overflow")


# ---------------------------------------------------------------------------
# Huffman (RFC 7541 Appendix B)
# ---------------------------------------------------------------------------
_HUFF_TREE = []


def _build_huffman_tree():
    tree = [[None, None]]
    for sym, (code, nbits) in HUFFMAN_CODES.items():
        node = 0
        for i in range(nbits - 1, -1, -1):
            bit = (code >> i) & 1
            nxt = tree[node][bit]
            if nxt is None:
                tree.append([None, None])
                nxt = len(tree) - 1
                tree[node][bit] = nxt
            node = nxt
        if tree[node] != [None, None]:
            raise RuntimeError("Huffman table is not prefix-free")
        tree[node] = sym
    return tree


_HUFF_TREE = _build_huffman_tree()


def huffman_decode(data):
    """Decode an HPACK/QPACK Huffman string (bytes) to bytes."""
    out = bytearray()
    node = 0
    trail_len = 0
    trail_all_ones = True
    for byte in data:
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            if isinstance(_HUFF_TREE[node], int):
                raise QpackError("Huffman decoder in leaf state")
            nxt = _HUFF_TREE[node][bit]
            if nxt is None:
                raise QpackError("invalid Huffman code")
            node = nxt
            trail_len += 1
            trail_all_ones = trail_all_ones and (bit == 1)
            if isinstance(_HUFF_TREE[node], int):
                sym = _HUFF_TREE[node]
                if sym == 256:
                    raise QpackError("EOS symbol in Huffman string")
                out.append(sym)
                node = 0
                trail_len = 0
                trail_all_ones = True
    if node != 0:
        # RFC 7541 5.2: at most 7 bits of all-ones padding are permitted.
        if not (trail_all_ones and trail_len < 8):
            raise QpackError("bad Huffman padding")
    return bytes(out)


def huffman_encode(data):
    """Encode bytes with the RFC 7541 table (used by the self-test/verifier)."""
    bits = []
    for byte in data:
        code, nbits = HUFFMAN_CODES[byte]
        for i in range(nbits - 1, -1, -1):
            bits.append((code >> i) & 1)
    while len(bits) % 8:
        bits.append(1)
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i : i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


# ---------------------------------------------------------------------------
# QPACK decoder (RFC 9204), with tolerant dynamic-table support
# ---------------------------------------------------------------------------
class QpackContext:
    """Dynamic table + static table view for one sender's encoder stream."""

    def __init__(self, max_capacity=0):
        self.max_capacity = int(max_capacity)
        self.capacity = 0
        self.size = 0
        self.entries = []  # list of (name_bytes, value_bytes) oldest..newest
        self.insert_count = 0  # total number of inserts ever
        self.enc_buf = bytearray()  # partial encoder-stream instruction buffer
        self.instructions = []  # log of applied instructions
        self.blocked = []  # pending field sections waiting for inserts
        self.error = None

    # -- table management -------------------------------------------------
    def entry_size(self, name, value):
        return len(name) + len(value) + 32

    def evict(self):
        name, value = self.entries.pop(0)
        self.size -= self.entry_size(name, value)

    def set_capacity(self, cap):
        if cap > self.max_capacity:
            # A conformant encoder cannot exceed the decoder's limit; if we
            # never saw SETTINGS (capture starts mid-connection) accept it and
            # raise our notion of the maximum so RIC reconstruction works.
            self.max_capacity = cap
        self.capacity = cap
        while self.size > self.capacity and self.entries:
            self.evict()

    def insert(self, name, value):
        if self.capacity <= 0:
            raise QpackError("dynamic insert with zero capacity")
        size = self.entry_size(name, value)
        if size > self.capacity:
            raise QpackError("dynamic entry larger than capacity")
        while self.size + size > self.capacity and self.entries:
            self.evict()
        self.entries.append((name, value))
        self.size += size
        self.insert_count += 1

    def lookup_abs(self, abs_index):
        """Absolute index -> (name, value). Raises QpackError/Blocked."""
        if abs_index < 0:
            raise QpackError("negative dynamic table index")
        if abs_index >= self.insert_count:
            raise Blocked("dynamic entry %d not inserted yet" % abs_index)
        oldest = self.insert_count - len(self.entries)
        if abs_index < oldest:
            raise QpackError("dynamic entry evicted")
        return self.entries[abs_index - oldest]

    def lookup_relative(self, base, rel):
        """Field-line relative index: 0 = entry with abs index Base-1."""
        return self.lookup_abs(base - 1 - rel)

    def lookup_postbase(self, base, idx):
        return self.lookup_abs(base + idx)

    # -- encoder stream ---------------------------------------------------
    def feed_encoder(self, data, on_change=None):
        self.enc_buf.extend(data)
        pos = 0
        try:
            while pos < len(self.enc_buf):
                pos = self._one_instruction(bytes(self.enc_buf), pos)
                if on_change is not None:
                    on_change()
        except NeedMore:
            pass
        except QpackError as exc:
            self.error = "encoder stream: %s" % exc
            pos = len(self.enc_buf)
        del self.enc_buf[:pos]

    def _one_instruction(self, buf, pos):
        if pos >= len(buf):
            raise NeedMore
        b = buf[pos]
        if b & 0x80:
            # Insert With Name Reference: 1 T index(6+), value string
            is_static = bool(b & 0x40)
            idx, pos = read_prefixed_int(buf, pos, 6)
            if is_static:
                if idx >= len(QPACK_STATIC):
                    raise QpackError("static name index out of range")
                name = QPACK_STATIC[idx][0].encode("latin-1")
            else:
                name = self.lookup_relative(self.insert_count, idx)[0]
            value, pos = qpack_string(buf, pos)
            self.insert(name, value)
            self.instructions.append(("insert_ref", "static" if is_static else "dyn", idx))
            return pos
        if b & 0x40:
            # Insert With Literal Name: 01 H name-len(5+), name, value
            huff = bool(b & 0x20)
            namelen, pos = read_prefixed_int(buf, pos, 5)
            if pos + namelen > len(buf):
                raise NeedMore
            raw = buf[pos : pos + namelen]
            pos += namelen
            name = huffman_decode(raw) if huff else raw
            value, pos = qpack_string(buf, pos)
            self.insert(name, value)
            self.instructions.append(("insert_literal", name.decode("latin-1"), huff))
            return pos
        if b & 0x20:
            # Set Dynamic Table Capacity: 001 capacity(5+)
            cap, pos = read_prefixed_int(buf, pos, 5)
            self.set_capacity(cap)
            self.instructions.append(("set_capacity", cap))
            return pos
        # Duplicate: 000 index(5+)
        idx, pos = read_prefixed_int(buf, pos, 5)
        name, value = self.lookup_relative(self.insert_count, idx)
        self.insert(name, value)
        self.instructions.append(("duplicate", idx))
        return pos

    # -- decoder stream (informational only) ------------------------------
    def feed_decoder(self, data):
        pos = 0
        buf = bytes(data)
        try:
            while pos < len(buf):
                b = buf[pos]
                if b & 0x80:
                    _, pos = read_prefixed_int(buf, pos, 7)
                elif b & 0x40:
                    _, pos = read_prefixed_int(buf, pos, 6)
                else:
                    _, pos = read_prefixed_int(buf, pos, 5)
        except NeedMore:
            pass


def qpack_string(data, pos):
    """Decode an HPACK/QPACK string literal; raises NeedMore."""
    if pos >= len(data):
        raise NeedMore
    huff = bool(data[pos] & 0x80)
    length, pos = read_prefixed_int(data, pos, 7)
    if pos + length > len(data):
        raise NeedMore
    raw = data[pos : pos + length]
    pos += length
    return (huffman_decode(raw) if huff else raw), pos


def decode_field_section(data, ctx):
    """Decode a QPACK field section; returns list of (name str, value str)."""
    data = bytes(data)
    pos = 0
    enc_ric, pos = read_prefixed_int(data, pos, 8)
    if pos >= len(data):
        raise NeedMore
    sign = bool(data[pos] & 0x80)
    delta_base, pos = read_prefixed_int(data, pos, 7)

    if enc_ric == 0:
        ric = 0
        if delta_base != 0:
            raise QpackError("delta base nonzero with RIC 0")
        base = 0
    else:
        max_entries = ctx.max_capacity // 32
        if max_entries == 0:
            # Fall back to the currently advertised capacity; some captures
            # omit the SETTINGS frame that carried the decoder's limit.
            max_entries = max(1, ctx.capacity // 32)
        full_range = 2 * max_entries
        if enc_ric > full_range:
            raise QpackError("encoded insert count exceeds FullRange")
        max_value = ctx.insert_count + max_entries
        max_wrapped = (max_value // full_range) * full_range
        ric = max_wrapped + enc_ric - 1
        if ric > max_value:
            if ric <= full_range:
                raise QpackError("bad required insert count")
            ric -= full_range
        if ric == 0:
            raise QpackError("required insert count is zero")
        base = ric + delta_base if not sign else ric - delta_base - 1
        if base < 0:
            raise QpackError("negative base")

    headers = []
    while pos < len(data):
        b = data[pos]
        if b & 0x80:
            # Indexed Field Line: 1 T index(6+)
            is_static = bool(b & 0x40)
            idx, pos = read_prefixed_int(data, pos, 6)
            if is_static:
                if idx >= len(QPACK_STATIC):
                    raise QpackError("static index %d out of range" % idx)
                name, value = QPACK_STATIC[idx]
                headers.append((name, value))
            else:
                n, v = ctx.lookup_relative(base, idx)
                headers.append((n.decode("latin-1"), v.decode("latin-1")))
        elif b & 0x40:
            # Literal Field Line With Name Reference: 01 N T index(4+)
            is_static = bool(b & 0x10)
            idx, pos = read_prefixed_int(data, pos, 4)
            if is_static:
                if idx >= len(QPACK_STATIC):
                    raise QpackError("static name index %d out of range" % idx)
                name = QPACK_STATIC[idx][0].encode("latin-1")
            else:
                name = ctx.lookup_relative(base, idx)[0]
            value, pos = qpack_string(data, pos)
            headers.append((name.decode("latin-1"), value.decode("latin-1")))
        elif b & 0x20:
            # Literal Field Line With Literal Name: 001 N H namelen(3+)
            huff = bool(b & 0x08)
            namelen, pos = read_prefixed_int(data, pos, 3)
            if pos + namelen > len(data):
                raise NeedMore
            raw = data[pos : pos + namelen]
            pos += namelen
            name = huffman_decode(raw) if huff else raw
            value, pos = qpack_string(data, pos)
            headers.append((name.decode("latin-1"), value.decode("latin-1")))
        elif b & 0x10:
            # Indexed Field Line With Post-Base Index: 0001 index(4+)
            idx, pos = read_prefixed_int(data, pos, 4)
            n, v = ctx.lookup_postbase(base, idx)
            headers.append((n.decode("latin-1"), v.decode("latin-1")))
        else:
            # Literal Field Line With Post-Base Name Reference:
            # 0000 N index(3+)
            idx, pos = read_prefixed_int(data, pos, 3)
            name = ctx.lookup_postbase(base, idx)[0]
            value, pos = qpack_string(data, pos)
            headers.append((name.decode("latin-1"), value.decode("latin-1")))
    return headers, {"ric": ric, "base": base, "encoded_ric": enc_ric}


# ---------------------------------------------------------------------------
# pcapng reader (two-interface merge with exact rational timestamps)
# ---------------------------------------------------------------------------
SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
SPB_TYPE = 0x00000003
BYTE_ORDER_MAGIC = 0x1A2B3C4D


class Interface:
    __slots__ = ("index", "name", "linktype", "tsresol", "tsoffset", "base")

    def __init__(self, index=0, name=None, linktype=1):
        self.index = index
        self.name = name
        self.linktype = linktype
        self.tsresol = 6  # default: microseconds
        self.tsoffset = 0  # seconds
        self.base = 10  # 10 or 2

    def time(self, ts):
        """Absolute capture time as an exact Fraction of seconds."""
        denom = (10 ** self.tsresol) if self.base == 10 else (1 << self.tsresol)
        return Fraction(ts, denom) + self.tsoffset

    def describe(self):
        if self.base == 10:
            res = "1e-%d s" % self.tsresol
        else:
            res = "2^-%d s" % self.tsresol
        return "%s(tsresol=%s, tsoffset=%+d s)" % (
            self.name or ("if%d" % self.index),
            res,
            self.tsoffset,
        )


class PcapNgPacket:
    __slots__ = ("index", "iface", "ts", "t", "data", "caplen", "origlen")

    def __init__(self, index, iface, ts, data, caplen, origlen):
        self.index = index
        self.iface = iface
        self.ts = ts
        self.t = iface.time(ts)
        self.data = data
        self.caplen = caplen
        self.origlen = origlen


def read_pcapng(path):
    raw = open(path, "rb").read()
    if len(raw) < 12:
        raise ValueError("file too short for pcapng")
    off = 0
    endian = "<"
    interfaces = []
    packets = []
    section_interfaces = []
    pkt_index = 0
    block_counts = defaultdict(int)
    while off + 12 <= len(raw):
        # SHB is readable independent of endianness (palindromic type)
        if raw[off : off + 4] == b"\x0a\x0d\x0d\x0a":
            bom = raw[off + 8 : off + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("bad byte-order magic at %d" % off)
        bt, bl = struct.unpack_from(endian + "II", raw, off)
        block_counts[bt] += 1
        if bl < 12 or bl % 4 != 0 or off + bl > len(raw):
            raise ValueError("bad block at %d (type %#x len %d)" % (off, bt, bl))
        body = raw[off + 8 : off + bl - 4]
        if bt == SHB_TYPE:
            section_interfaces = []
            interfaces = section_interfaces  # noqa: F841 (documentation)
        elif bt == IDB_TYPE:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            ifc = Interface(len(section_interfaces), linktype=linktype)
            pos = 8
            while pos + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, pos)
                pos += 4
                if code == 0:
                    break
                val = body[pos : pos + olen]
                pos += (olen + 3) & ~3
                if code == 2:
                    ifc.name = val.rstrip(b"\x00").decode("latin-1", "replace")
                elif code == 9 and olen >= 1:
                    v = val[0]
                    if v & 0x80:
                        ifc.base = 2
                        ifc.tsresol = v & 0x7F
                    else:
                        ifc.base = 10
                        ifc.tsresol = v
                elif code == 14 and olen >= 8:
                    ifc.tsoffset = struct.unpack(endian + "q", val[:8])[0]
            section_interfaces.append(ifc)
        elif bt == EPB_TYPE:
            if len(body) < 20:
                raise ValueError("short EPB at %d" % off)
            iid, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            if iid >= len(section_interfaces):
                raise ValueError("EPB references unknown interface %d" % iid)
            ifc = section_interfaces[iid]
            data = body[20 : 20 + caplen]
            if len(data) < caplen:
                # truncated capture: keep what is there
                caplen = len(data)
            ts = (tsh << 32) | tsl
            packets.append(PcapNgPacket(pkt_index, ifc, ts, bytes(data), caplen, origlen))
            pkt_index += 1
        elif bt == SPB_TYPE:
            # Simple Packet Block: no timestamp; not expected in this capture.
            pass
        off += bl
    packets.sort(key=lambda p: (p.t, p.index))
    return section_interfaces, packets


# ---------------------------------------------------------------------------
# Link layer / IP / UDP
# ---------------------------------------------------------------------------
def link_to_ip(linktype, data):
    """Return (version, offset) of the IP header inside a link-layer frame."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        etype = be16(data, 12)
        off = 14
        while etype in (0x8100, 0x88A8, 0x9100):  # VLAN / QinQ
            if len(data) < off + 4:
                return None
            etype = be16(data, off + 2)
            off += 4
        if etype == 0x0800:
            return (4, off)
        if etype == 0x86DD:
            return (6, off)
        return None
    if linktype in (101, 228):  # raw IPv4
        return (4, 0)
    if linktype == 229:  # raw IPv6
        return (6, 0)
    if linktype == 113:  # Linux cooked SLL v1
        if len(data) < 16:
            return None
        proto = be16(data, 14)
        if proto == 0x0800:
            return (4, 16)
        if proto == 0x86DD:
            return (6, 16)
        return None
    if linktype == 276:  # Linux cooked SLL v2
        if len(data) < 20:
            return None
        proto = be16(data, 0)
        if proto == 0x0800:
            return (4, 20)
        if proto == 0x86DD:
            return (6, 20)
        return None
    return None


def parse_ipv4(data, off):
    if len(data) < off + 20:
        return None
    vihl = data[off]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    total = be16(data, off + 2)
    ident = be16(data, off + 4)
    flags_frag = be16(data, off + 6)
    proto = data[off + 9]
    src = bytes(data[off + 12 : off + 16])
    dst = bytes(data[off + 16 : off + 20])
    declared = total - ihl if total >= ihl else 0
    avail = len(data) - (off + ihl)
    if declared <= 0 or declared > avail:
        declared = avail
    payload = bytes(data[off + ihl : off + ihl + declared])
    return {
        "src": src,
        "dst": dst,
        "id": ident,
        "proto": proto,
        "offset": (flags_frag & 0x1FFF) * 8,
        "mf": bool(flags_frag & 0x2000),
        "payload": payload,
        "truncated": (total - ihl) > avail if total >= ihl else False,
        "total": total,
        "ihl": ihl,
    }


def parse_ipv6(data, off):
    """Minimal IPv6 + extension-header walk; returns same shape as v4."""
    if len(data) < off + 40:
        return None
    if (data[off] >> 4) != 6:
        return None
    plen = be16(data, off + 4)
    nxt = data[off + 6]
    src = bytes(data[off + 8 : off + 24])
    dst = bytes(data[off + 24 : off + 40])
    pos = off + 40
    end = min(len(data), off + 40 + plen) if plen else len(data)
    frag_off = 0
    mf = False
    while nxt in (0, 43, 60) and pos + 2 <= end:
        nxt = data[pos]
        hdr_ext_len = (data[pos + 1] + 1) * 8
        pos += hdr_ext_len
    if nxt == 44 and pos + 8 <= end:  # Fragment header
        frag = be16(data, pos + 2)
        frag_off = (frag & 0xFFF8)
        mf = bool(frag & 0x1)
        nxt = data[pos]
        pos += 8
    if nxt != 17:
        return None
    payload = bytes(data[pos:end])
    return {
        "src": src,
        "dst": dst,
        "id": 0,  # IPv6 fragments not keyed by id in this capture
        "proto": 17,
        "offset": frag_off,
        "mf": mf,
        "payload": payload,
        "truncated": False,
        "total": plen,
        "ihl": pos - off,
    }


class IPReassembler:
    """RFC 791-ish IPv4 reassembly (the capture splits datagrams by design)."""

    def __init__(self):
        self.pending = {}
        self.completed = 0
        self.incomplete_keys = set()
        self.fragment_packets = 0
        self.duplicate_fragments = 0
        self.conflicts = 0

    def add(self, key, off, payload, mf, time):
        self.fragment_packets += 1
        rec = self.pending.get(key)
        if rec is None:
            rec = {"parts": {}, "total": None, "times": [], "meta": None}
            self.pending[key] = rec
        rec["times"].append(time)
        if off in rec["parts"]:
            if rec["parts"][off] != payload:
                self.conflicts += 1
            else:
                self.duplicate_fragments += 1
        else:
            rec["parts"][off] = payload
        if not mf:
            total = off + len(payload)
            if rec["total"] is not None and rec["total"] != total:
                self.conflicts += 1
            rec["total"] = total
        if rec["total"] is None:
            return None
        # Check contiguous coverage
        cur = 0
        for o in sorted(rec["parts"]):
            if o > cur:
                return None
            ln = len(rec["parts"][o])
            if o + ln > cur:
                cur = o + ln
            if cur >= rec["total"]:
                break
        if cur < rec["total"]:
            return None
        data = b"".join(rec["parts"][o] for o in sorted(rec["parts"]) if o < rec["total"])
        if len(data) != rec["total"]:
            return None
        del self.pending[key]
        self.completed += 1
        return data, min(rec["times"])

    def unfinished(self):
        return len(self.pending)


def parse_udp(datagram):
    if len(datagram) < 8:
        return None
    sport, dport, ulen, csum = struct.unpack_from(">HHHH", datagram, 0)
    if ulen == 0:  # jumbogram
        payload = datagram[8:]
    elif ulen < 8:
        payload = datagram[8:]
    else:
        payload = datagram[8:ulen]
        if len(payload) != ulen - 8:
            payload = datagram[8:]
    return {
        "sport": sport,
        "dport": dport,
        "length": ulen,
        "checksum": csum,
        "payload": bytes(payload),
    }


# ---------------------------------------------------------------------------
# QUIC crypto
# ---------------------------------------------------------------------------
CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256": {"hash": "sha256", "key_len": 16, "aead": "aesgcm"},
    "TLS_AES_256_GCM_SHA384": {"hash": "sha384", "key_len": 32, "aead": "aesgcm"},
    "TLS_CHACHA20_POLY1305_SHA256": {"hash": "sha256", "key_len": 32, "aead": "chacha"},
}

CIPHER_BY_CODE = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    4865: "TLS_AES_128_GCM_SHA256",
    4866: "TLS_AES_256_GCM_SHA384",
    4867: "TLS_CHACHA20_POLY1305_SHA256",
}


def parse_cipher(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, int):
        return CIPHER_BY_CODE.get(value, "TLS_AES_128_GCM_SHA256")
    if value is None:
        return "TLS_AES_128_GCM_SHA256"
    text = str(value).strip()
    if text.lower().startswith("0x"):
        try:
            return CIPHER_BY_CODE.get(int(text, 16), "TLS_AES_128_GCM_SHA256")
        except ValueError:
            pass
    u = re.sub(r"[^A-Z0-9]+", "_", text.upper())
    if u.startswith("0X"):
        u = u[2:]
    if u.isdigit():
        return CIPHER_BY_CODE.get(int(u), "TLS_AES_128_GCM_SHA256")
    if "CHACHA" in u:
        return "TLS_CHACHA20_POLY1305_SHA256"
    if "AES_256" in u or "256_GCM" in u or "SHA384" in u:
        return "TLS_AES_256_GCM_SHA384"
    if "AES_128" in u or "128_GCM" in u:
        return "TLS_AES_128_GCM_SHA256"
    return "TLS_AES_128_GCM_SHA256"


def aead_decrypt(aead, key, nonce, ct_and_tag, aad):
    """Return plaintext or raise QuicError."""
    if aead == "aesgcm":
        if HAVE_CRYPTOGRAPHY:
            try:
                return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
            except Exception:
                raise QuicError("AEAD tag mismatch")
        elif HAVE_PYCRYPTODOME:
            try:
                c = _PCAES.new(key, _PCAES.MODE_GCM, nonce=nonce, mac_len=16)
                c.update(aad)
                return c.decrypt_and_verify(ct_and_tag[:-16], ct_and_tag[-16:])
            except Exception:
                raise QuicError("AEAD tag mismatch")
        raise QuicError("no AES-GCM backend")
    if aead == "chacha":
        if HAVE_CRYPTOGRAPHY:
            try:
                return ChaCha20Poly1305(key).decrypt(nonce, ct_and_tag, aad)
            except Exception:
                raise QuicError("AEAD tag mismatch")
        elif HAVE_PYCRYPTODOME:
            try:
                c = _PCCHACHA.new(key=key, nonce=nonce, mac_len=16)
                c.update(aad)
                return c.decrypt_and_verify(ct_and_tag[:-16], ct_and_tag[-16:])
            except Exception:
                raise QuicError("AEAD tag mismatch")
        raise QuicError("no ChaCha20 backend")
    raise QuicError("unsupported AEAD")


def header_protection_mask(aead, hp_key, sample):
    if len(sample) < 16:
        raise QuicError("short header-protection sample")
    if aead == "chacha":
        if HAVE_CRYPTOGRAPHY:
            c = Cipher(algorithms.ChaCha20(hp_key, sample[:16]), mode=None).encryptor()
            return c.update(b"\x00\x00\x00\x00\x00")
        elif HAVE_PYCRYPTODOME:
            c = _PCCHACHA.new(key=hp_key, nonce=sample[4:16])
            c.update(sample[:4])
            return c.encrypt(b"\x00" * 5)
        raise QuicError("no ChaCha20 backend")
    if HAVE_CRYPTOGRAPHY:
        enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
        return (enc.update(sample) + enc.finalize())[:5]
    if HAVE_PYCRYPTODOME:
        return _PCAES.new(hp_key, _PCAES.MODE_ECB).encrypt(sample)[:5]
    raise QuicError("no AES backend")


class KeyGeneration:
    __slots__ = ("secret", "key", "iv", "hp", "phase", "index")

    def __init__(self, secret, suite, index):
        spec = CIPHER_SUITES[suite]
        h = spec["hash"]
        klen = spec["key_len"]
        self.secret = secret
        self.key = hkdf_expand_label(secret, "quic key", b"", klen, h)
        self.iv = hkdf_expand_label(secret, "quic iv", b"", 12, h)
        self.hp = hkdf_expand_label(secret, "quic hp", b"", klen, h)
        self.phase = index & 1
        self.index = index


class DirKeys:
    """Key generations for one direction of one connection (key set)."""

    def __init__(self, secret, suite):
        self.suite = suite
        self.secret = secret
        self.gens = [KeyGeneration(secret, suite, 0)]
        self.cur = 0
        self.largest = -1
        self.per_cid = {}
        self.capsule_next = None
        self.capsule_per_cid = {}
        self.decrypted = 0
        self.failures = 0

    def gen(self, index):
        while len(self.gens) <= index:
            if index >= 8:
                raise QuicError("too many key updates")
            prev = self.gens[-1]
            h = CIPHER_SUITES[self.suite]["hash"]
            new_secret = hkdf_expand_label(prev.secret, "quic ku", b"", len(prev.secret), h)
            self.gens.append(KeyGeneration(new_secret, self.suite, index))
        return self.gens[index]

    def pn_candidates(self, cid, truncated, pn_len):
        bits = pn_len * 8
        refs = []
        if cid in self.per_cid:
            refs.append(self.per_cid[cid])
        if self.largest >= 0:
            refs.append(self.largest)
        cid_hex = cid.hex() if isinstance(cid, (bytes, bytearray)) else str(cid)
        if cid_hex in self.capsule_per_cid:
            refs.append(int(self.capsule_per_cid[cid_hex]) - 1)
        if self.capsule_next is not None:
            refs.append(int(self.capsule_next) - 1)
        if not refs:
            refs.append(-1)
        out = []
        for largest in refs:
            pn = reconstruct_pn(truncated, bits, largest)
            if pn not in out:
                out.append(pn)
        # Always keep the bare truncated value: this makes the very first
        # packet recoverable even if a capsule "next packet number" hint is
        # missing or denotes the wrong packet-number space.
        if truncated not in out:
            out.append(truncated)
        return out

    def note_success(self, cid, pn, gen_index):
        self.cur = gen_index
        self.decrypted += 1
        if pn > self.largest:
            self.largest = pn
        if cid not in self.per_cid or pn > self.per_cid[cid]:
            self.per_cid[cid] = pn


def reconstruct_pn(truncated, bits, largest):
    """RFC 9000 Appendix A.3 packet-number reconstruction."""
    if largest is None or largest < 0:
        return truncated
    expected = largest + 1
    win = 1 << bits
    half = win >> 1
    mask = win - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - half and candidate < (1 << 62) - win:
        return candidate + win
    if candidate > expected + half and candidate >= win:
        return candidate - win
    return candidate


class KeySet:
    """A direction-pair of traffic secrets (one connection context)."""

    def __init__(self, index, suite, client_secret, server_secret, label=""):
        self.index = index
        self.suite = suite
        self.label = label
        self.keys = {
            "c2s": DirKeys(client_secret, suite),
            "s2c": DirKeys(server_secret, suite),
        }
        self.reverse_ok = {"c2s": 0, "s2c": 0}
        self.packets = 0


def parse_quic_packet(data, cid_len):
    """Parse QUIC packet framing (no decryption yet).

    Returns dict with kind, header fields, pn_offset, packet end, sample.
    """
    if not data:
        raise QuicError("empty QUIC datagram")
    b0 = data[0]
    info = {"first_byte": b0, "long": bool(b0 & 0x80)}
    if b0 & 0x80:
        if len(data) < 7:
            raise QuicError("short long header")
        version = be32(data, 1)
        info["version"] = version
        dcid_len = data[5]
        info["dcid_len"] = dcid_len
        info["dcid"] = bytes(data[6 : 6 + dcid_len])
        pos = 6 + dcid_len
        if pos >= len(data):
            raise QuicError("truncated long header")
        scid_len = data[pos]
        pos += 1
        if pos + scid_len > len(data):
            raise QuicError("truncated long header SCID")
        info["scid"] = bytes(data[pos : pos + scid_len])
        pos += scid_len
        if version == 0:
            info["kind"] = "version_negotiation"
            info["pn_offset"] = pos
            info["end"] = len(data)
            return info
        if version != 1:
            # QUIC v2 / grease: still parse the type bits differently.  The
            # challenge capture is v1; treat other versions as opaque.
            info["kind"] = "other_version"
            info["pn_offset"] = pos
            info["end"] = len(data)
            return info
        ptype = (b0 >> 4) & 0x03
        info["ptype"] = ptype
        if ptype == 3:  # Retry
            info["kind"] = "retry"
            info["pn_offset"] = pos
            info["end"] = len(data)
            return info
        if ptype == 0:  # Initial: token length + token
            token_len, pos = read_varint(data, pos)
            pos += token_len
        length, pos = read_varint(data, pos)
        info["kind"] = ["initial", "0rtt", "handshake", "retry"][ptype]
        info["length"] = length
        info["pn_offset"] = pos
        info["end"] = min(len(data), pos + length)
        if info["end"] < pos:
            raise QuicError("bad long-header length")
    else:
        info["kind"] = "short"
        if len(data) < 1 + cid_len + 1:
            raise QuicError("short header shorter than CID")
        info["dcid"] = bytes(data[1 : 1 + cid_len])
        info["dcid_len"] = cid_len
        info["pn_offset"] = 1 + cid_len
        info["end"] = len(data)
    if info["pn_offset"] + 4 + 16 > info["end"]:
        raise QuicError("packet too short for header protection sample")
    info["sample"] = bytes(data[info["pn_offset"] + 4 : info["pn_offset"] + 20])
    return info


def decrypt_quic_packet(data, info, dirkeys):
    """Try to decrypt a parsed QUIC packet with one direction's keys.

    Returns a dict (pn, plaintext, pn_len, gen_index, first, key_phase) or
    raises QuicError if no generation/tag combination authenticates.
    """
    suite = dirkeys.suite
    aead = CIPHER_SUITES[suite]["aead"]
    pn_offset = info["pn_offset"]
    end = info["end"]
    b0 = data[0]
    long_header = info["long"]
    first_mask = 0x0F if long_header else 0x1F
    errors = []
    tried = set()
    # The key phase bit is itself protected, so each candidate protection key
    # is used to unmask the first byte and the revealed phase is then checked
    # against that generation.  Trying every known generation newest-first
    # keeps old-phase packets working even after a few updates (and stops a
    # wrong candidate key set from poisoning a later, correct one).
    last = len(dirkeys.gens) - 1
    cand = list(range(last, -1, -1))
    if len(dirkeys.gens) < 8:
        cand.append(len(dirkeys.gens))
    for gen_index in cand:
        if gen_index < 0 or gen_index in tried:
            continue
        tried.add(gen_index)
        gen = dirkeys.gen(gen_index)
        try:
            mask = header_protection_mask(aead, gen.hp, info["sample"])
        except QuicError as exc:
            errors.append(str(exc))
            continue
        first = b0 ^ (mask[0] & first_mask)
        pn_len = (first & 0x03) + 1
        if pn_offset + pn_len > end:
            continue
        # The key phase bit only exists in the short (1-RTT) header.  Long
        # header packets are not expected in this post-handshake capture.
        phase = 0 if long_header else ((first >> 2) & 1)
        # NOTE: the generation's nominal phase is only a hint.  A capsule may
        # already describe the post-update (phase 1) secret, and the AEAD tag is
        # the authoritative test, so phase-mismatched generations are tried too.
        pn_bytes = bytes(data[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
        truncated = int.from_bytes(pn_bytes, "big")
        cid = info.get("dcid", b"")
        ciphertext = bytes(data[pn_offset + pn_len : end])
        if len(ciphertext) < 16:
            continue
        # RFC 9001 5.3: AAD is the header with the *unprotected* first byte
        # and the unprotected packet number.
        aad = bytes([first]) + bytes(data[1:pn_offset]) + pn_bytes
        for pn in dirkeys.pn_candidates(cid, truncated, pn_len):
            nonce = xor_bytes(gen.iv, pn.to_bytes(12, "big"))
            try:
                plaintext = aead_decrypt(aead, gen.key, nonce, ciphertext, aad)
            except QuicError:
                continue
            return {
                "pn": pn,
                "plaintext": plaintext,
                "pn_len": pn_len,
                "gen_index": gen_index,
                "first": first,
                "key_phase": phase,
            }
    raise QuicError("; ".join(errors) if errors else "no key generation matched")


# ---------------------------------------------------------------------------
# QUIC frame parsing
# ---------------------------------------------------------------------------
FRAME_NAMES = {
    0x00: "PADDING",
    0x01: "PING",
    0x02: "ACK",
    0x03: "ACK_ECN",
    0x04: "RESET_STREAM",
    0x05: "STOP_SENDING",
    0x06: "CRYPTO",
    0x07: "NEW_TOKEN",
    0x10: "MAX_DATA",
    0x11: "MAX_STREAM_DATA",
    0x12: "MAX_STREAMS_BIDI",
    0x13: "MAX_STREAMS_UNI",
    0x14: "DATA_BLOCKED",
    0x15: "STREAM_DATA_BLOCKED",
    0x16: "STREAMS_BLOCKED_BIDI",
    0x17: "STREAMS_BLOCKED_UNI",
    0x18: "NEW_CONNECTION_ID",
    0x19: "RETIRE_CONNECTION_ID",
    0x1A: "PATH_CHALLENGE",
    0x1B: "PATH_RESPONSE",
    0x1C: "CONNECTION_CLOSE",
    0x1D: "CONNECTION_CLOSE_APP",
    0x1E: "HANDSHAKE_DONE",
    0x30: "DATAGRAM",
    0x31: "DATAGRAM_LEN",
}


def frame_name(ftype):
    if 0x08 <= ftype <= 0x0F:
        return "STREAM"
    if 0x02 <= ftype <= 0x03:
        return "ACK" if ftype == 2 else "ACK_ECN"
    return FRAME_NAMES.get(ftype, "UNKNOWN_%#x" % ftype)


def parse_frames(payload):
    """Parse a decrypted QUIC payload into a list of frame dicts."""
    frames = []
    pos = 0
    n = len(payload)
    while pos < n:
        try:
            ftype, pos = read_varint(payload, pos)
        except NeedMore:
            frames.append({"type": "TRUNCATED", "at": pos})
            break
        name = frame_name(ftype)
        rec = {"type": name, "type_value": ftype, "offset": pos}
        try:
            if ftype == 0x00:  # PADDING (one zero byte consumed)
                rec["padding_bytes"] = 1
                frames.append(rec)
                # fast-forward over padding
                start = pos
                while pos < n and payload[pos] == 0:
                    pos += 1
                if pos > start:
                    rec["padding_bytes"] += pos - start
                    # merge into previous padding frame if present
                continue
            if ftype == 0x01:  # PING
                frames.append(rec)
                continue
            if ftype in (0x02, 0x03):  # ACK / ACK_ECN
                largest, pos = read_varint(payload, pos)
                delay, pos = read_varint(payload, pos)
                rng_count, pos = read_varint(payload, pos)
                first_range, pos = read_varint(payload, pos)
                ranges = []
                for _ in range(rng_count):
                    gap, pos = read_varint(payload, pos)
                    rlen, pos = read_varint(payload, pos)
                    ranges.append((gap, rlen))
                rec.update(
                    largest=largest,
                    delay=delay,
                    range_count=rng_count,
                    first_range=first_range,
                    ranges=ranges,
                )
                if ftype == 3:
                    ect0, pos = read_varint(payload, pos)
                    ect1, pos = read_varint(payload, pos)
                    ce, pos = read_varint(payload, pos)
                    rec.update(ect0=ect0, ect1=ect1, ce=ce)
                frames.append(rec)
                continue
            if ftype == 0x04:  # RESET_STREAM
                sid, pos = read_varint(payload, pos)
                err, pos = read_varint(payload, pos)
                fsize, pos = read_varint(payload, pos)
                rec.update(stream_id=sid, error_code=err, final_size=fsize)
                frames.append(rec)
                continue
            if ftype == 0x05:  # STOP_SENDING
                sid, pos = read_varint(payload, pos)
                err, pos = read_varint(payload, pos)
                rec.update(stream_id=sid, error_code=err)
                frames.append(rec)
                continue
            if ftype == 0x06:  # CRYPTO
                off, pos = read_varint(payload, pos)
                ln, pos = read_varint(payload, pos)
                if pos + ln > n:
                    raise NeedMore
                rec.update(offset=off, length=ln, data=bytes(payload[pos : pos + ln]))
                pos += ln
                frames.append(rec)
                continue
            if ftype == 0x07:  # NEW_TOKEN
                ln, pos = read_varint(payload, pos)
                if pos + ln > n:
                    raise NeedMore
                rec.update(length=ln, data=bytes(payload[pos : pos + ln]))
                pos += ln
                frames.append(rec)
                continue
            if 0x08 <= ftype <= 0x0F:  # STREAM
                sid, pos = read_varint(payload, pos)
                off = 0
                if ftype & 0x04:
                    off, pos = read_varint(payload, pos)
                ln = None
                if ftype & 0x02:
                    ln, pos = read_varint(payload, pos)
                if ln is None:
                    ln = n - pos
                if pos + ln > n:
                    raise NeedMore
                data = bytes(payload[pos : pos + ln])
                pos += ln
                rec.update(
                    stream_id=sid,
                    offset=off,
                    length=ln,
                    data=data,
                    fin=bool(ftype & 0x01),
                )
                frames.append(rec)
                continue
            if ftype == 0x10:
                v, pos = read_varint(payload, pos)
                rec["maximum"] = v
                frames.append(rec)
                continue
            if ftype == 0x11:
                sid, pos = read_varint(payload, pos)
                v, pos = read_varint(payload, pos)
                rec.update(stream_id=sid, maximum=v)
                frames.append(rec)
                continue
            if ftype in (0x12, 0x13):
                v, pos = read_varint(payload, pos)
                rec["maximum"] = v
                frames.append(rec)
                continue
            if ftype == 0x14:
                v, pos = read_varint(payload, pos)
                rec["limit"] = v
                frames.append(rec)
                continue
            if ftype == 0x15:
                sid, pos = read_varint(payload, pos)
                v, pos = read_varint(payload, pos)
                rec.update(stream_id=sid, limit=v)
                frames.append(rec)
                continue
            if ftype in (0x16, 0x17):
                v, pos = read_varint(payload, pos)
                rec["limit"] = v
                frames.append(rec)
                continue
            if ftype == 0x18:  # NEW_CONNECTION_ID
                seq, pos = read_varint(payload, pos)
                retire, pos = read_varint(payload, pos)
                if pos >= n:
                    raise NeedMore
                ln = payload[pos]
                pos += 1
                if pos + ln + 16 > n:
                    raise NeedMore
                cid = bytes(payload[pos : pos + ln])
                pos += ln
                token = bytes(payload[pos : pos + 16])
                pos += 16
                rec.update(sequence=seq, retire_prior_to=retire, cid=cid, token=token)
                frames.append(rec)
                continue
            if ftype == 0x19:
                seq, pos = read_varint(payload, pos)
                rec["sequence"] = seq
                frames.append(rec)
                continue
            if ftype in (0x1A, 0x1B):
                if pos + 8 > n:
                    raise NeedMore
                rec["data"] = bytes(payload[pos : pos + 8])
                pos += 8
                frames.append(rec)
                continue
            if ftype in (0x1C, 0x1D):
                err, pos = read_varint(payload, pos)
                rec["error_code"] = err
                if ftype == 0x1C:
                    ft, pos = read_varint(payload, pos)
                    rec["frame_type"] = ft
                ln, pos = read_varint(payload, pos)
                if pos + ln > n:
                    raise NeedMore
                rec["reason"] = bytes(payload[pos : pos + ln])
                pos += ln
                frames.append(rec)
                continue
            if ftype == 0x1E:
                frames.append(rec)
                continue
            if ftype in (0x30, 0x31):
                ln = n - pos
                if ftype == 0x31:
                    ln, pos = read_varint(payload, pos)
                if pos + ln > n:
                    raise NeedMore
                rec.update(length=ln, data=bytes(payload[pos : pos + ln]))
                pos += ln
                frames.append(rec)
                continue
            # Unknown frame type: cannot safely skip it.
            rec["error"] = "unknown frame type"
            frames.append(rec)
            break
        except NeedMore:
            rec["error"] = "truncated frame"
            frames.append(rec)
            break
    return frames


# ---------------------------------------------------------------------------
# QUIC stream reassembly
# ---------------------------------------------------------------------------
class RecvStream:
    __slots__ = ("segments", "next", "final_size", "conflicts", "duplicates")

    def __init__(self):
        self.segments = {}
        self.next = 0
        self.final_size = None
        self.conflicts = 0
        self.duplicates = 0

    def push(self, offset, data, fin):
        """Return newly contiguous bytes starting at the current 'next'."""
        data = bytes(data)
        if fin:
            end = offset + len(data)
            if self.final_size is None or end < self.final_size:
                self.final_size = end
        if offset + len(data) <= self.next:
            self.duplicates += 1
            return b""
        if offset < self.next:
            data = data[self.next - offset :]
            offset = self.next
        existing = self.segments.get(offset)
        if existing is not None:
            if existing != data:
                # Prefer the longer/first copy, count conflict.
                self.conflicts += 1
                if len(existing) >= len(data):
                    return b""
            else:
                self.duplicates += 1
                return b""
        self.segments[offset] = data
        out = bytearray()
        while True:
            seg = self.segments.pop(self.next, None)
            if seg is None:
                break
            out += seg
            self.next += len(seg)
        return bytes(out)

    def complete(self):
        return self.final_size is not None and self.next >= self.final_size


# ---------------------------------------------------------------------------
# HTTP/3 + QPACK stream processing
# ---------------------------------------------------------------------------
H3_DATA = 0x00
H3_HEADERS = 0x01
H3_CANCEL_PUSH = 0x03
H3_SETTINGS = 0x04
H3_PUSH_PROMISE = 0x05
H3_GOAWAY = 0x07
H3_MAX_PUSH_ID = 0x0D

UNI_CONTROL = 0x00
UNI_PUSH = 0x01
UNI_QPACK_ENCODER = 0x02
UNI_QPACK_DECODER = 0x03


def is_grease(value):
    return value >= 0x21 and (value - 0x21) % 0x1F == 0


class FrameParser:
    """Incremental HTTP/3 frame parser."""

    def __init__(self, handler):
        self.buf = bytearray()
        self.handler = handler
        self.errors = []

    def feed(self, data):
        self.buf.extend(data)
        while True:
            t, p = read_varint_loose(self.buf, 0)
            if t is None:
                return
            length, p2 = read_varint_loose(self.buf, p)
            if length is None:
                return
            if len(self.buf) < p2 + length:
                return
            payload = bytes(self.buf[p2 : p2 + length])
            del self.buf[: p2 + length]
            try:
                self.handler(t, payload)
            except Exception as exc:  # keep decoding other frames/streams
                self.errors.append("frame %#x: %s" % (t, exc))


class UniStream:
    """A unidirectional stream: type varint then type-specific content."""

    def __init__(self, space, stream_id, direction, decoder):
        self.space = space
        self.stream_id = stream_id
        self.direction = direction
        self.decoder = decoder
        self.typ = None
        self.buf = bytearray()
        self.frames = None
        self.errors = []

    def feed(self, data):
        if self.typ is None:
            self.buf.extend(data)
            t, p = read_varint_loose(self.buf, 0)
            if t is None:
                return
            self.typ = t
            rest = bytes(self.buf[p:])
            self.buf = bytearray()
            self.decoder.on_uni_stream_type(self, t)
            data = rest
        if not data:
            return
        d = self.decoder
        if is_grease(self.typ):
            return
        if self.typ == UNI_CONTROL:
            if self.frames is None:
                self.frames = FrameParser(lambda ft, pl: d.on_control_frame(self, ft, pl))
            self.frames.feed(data)
        elif self.typ == UNI_QPACK_ENCODER:
            ctx = d.encoder_ctx(self.space, self.direction)
            ctx.feed_encoder(data, on_change=lambda: d.flush_blocked(self.space, self.direction))
        elif self.typ == UNI_QPACK_DECODER:
            ctx = d.decoder_ctx(self.space, self.direction)
            ctx.feed_decoder(data)
        elif self.typ == UNI_PUSH:
            if self.frames is None:
                self.frames = FrameParser(lambda ft, pl: d.on_push_frame(self, ft, pl))
            self.frames.feed(data)
        else:
            # Unknown/reserved stream type: ignore content.
            pass


class Response:
    def __init__(self, space, stream_id):
        self.space = space
        self.stream_id = stream_id
        self.sections = []  # list of (headers, prefixinfo) from server
        self.request_sections = []
        self.request_headers = []
        self.body = bytearray()
        self.frames = []
        self.fin = False
        self.final_size = None
        self.first_time = None
        self.errors = []
        self.data_frames = 0
        self.header_frames = 0

    def add_headers(self, headers, meta, source="response"):
        if source == "response":
            self.sections.append((headers, meta))
            self.header_frames += 1
        else:
            self.request_sections.append((headers, meta))

    def add_data(self, payload):
        self.body.extend(payload)
        self.data_frames += 1


class Http3Decoder:
    def __init__(self):
        self.assemblers = {}
        self.response = {}
        self.uni = {}
        self.qpack_enc = {}
        self.qpack_dec = {}
        self.pending = defaultdict(list)  # (space, dir) -> [(response, data)]
        self.settings = {}
        self.goaway = {}
        self.errors = []
        self.stream_log = []
        self.push_promises = []
        self.control_seen = set()
        self.encoder_seen = set()

    # -- spaces ----------------------------------------------------------
    def space_key(self, space, direction):
        return (space, direction)

    def encoder_ctx(self, space, direction):
        key = (space, direction)
        if key not in self.qpack_enc:
            self.qpack_enc[key] = QpackContext()
        return self.qpack_enc[key]

    def decoder_ctx(self, space, direction):
        key = (space, direction)
        if key not in self.qpack_dec:
            self.qpack_dec[key] = QpackContext()
        return self.qpack_dec[key]

    def get_response(self, space, stream_id):
        key = (space, stream_id)
        if key not in self.response:
            self.response[key] = Response(space, stream_id)
        return self.response[key]

    # -- stream entry ----------------------------------------------------
    def feed_stream(self, space, stream_id, direction, data, fin, time):
        """Feed newly contiguous stream bytes (already reassembled)."""
        if not data and not fin:
            return
        is_uni = bool(stream_id & 0x02)
        if is_uni:
            key = (space, stream_id, direction)
            uni = self.uni.get(key)
            if uni is None:
                uni = UniStream(space, stream_id, direction, self)
                self.uni[key] = uni
            if data:
                uni.feed(data)
            return
        # bidirectional: request stream (client) or response stream (server)
        resp = self.get_response(space, stream_id)
        if resp.first_time is None:
            resp.first_time = time
        if fin:
            resp.fin = True
        key = (space, stream_id, direction)
        fp = self.assemblers.get(key)
        if fp is None:
            if direction == "c2s":
                fp = FrameParser(lambda ft, pl: self.on_request_frame(resp, ft, pl))
            else:
                fp = FrameParser(lambda ft, pl: self.on_response_frame(resp, ft, pl))
            self.assemblers[key] = fp
        if data:
            fp.feed(data)

    # -- frame handlers --------------------------------------------------
    def on_request_frame(self, resp, ftype, payload):
        if ftype == H3_HEADERS:
            self._decode_headers(resp, payload, "request")
        elif ftype == H3_DATA:
            # request body: not interesting for rr-ledger
            resp.frames.append(("request_data", len(payload)))

    def on_response_frame(self, resp, ftype, payload):
        if ftype == H3_HEADERS:
            self._decode_headers(resp, payload, "response")
        elif ftype == H3_DATA:
            resp.body.extend(payload)
            resp.data_frames += 1
            resp.frames.append(("data", len(payload)))
        elif ftype == H3_PUSH_PROMISE:
            try:
                push_id, pos = read_varint(payload, 0)
                headers, meta = decode_field_section(
                    payload[pos:], self.encoder_ctx(resp.space, "s2c")
                )
                self.push_promises.append(
                    {"space": resp.space, "push_id": push_id, "headers": headers}
                )
            except Exception as exc:
                resp.errors.append("pus promise: %s" % exc)
        elif ftype == H3_GOAWAY:
            try:
                sid, _ = read_varint(payload, 0)
                self.goaway[resp.space] = sid
            except Exception:
                pass
        else:
            resp.frames.append(("type_%#x" % ftype, len(payload)))

    def on_control_frame(self, uni, ftype, payload):
        if ftype == H3_SETTINGS:
            pairs = []
            pos = 0
            try:
                while pos < len(payload):
                    ident, pos = read_varint(payload, pos)
                    val, pos = read_varint(payload, pos)
                    pairs.append((ident, val))
            except Exception:
                uni.errors.append("bad SETTINGS")
            self.settings[(uni.space, uni.direction)] = pairs
            # SETTINGS sent by endpoint D describe the limits D imposes on the
            # peer's encoder, i.e. on field sections flowing in the opposite
            # direction.  In particular the peer's QPACK max table capacity
            # governs Required-Insert-Count reconstruction.
            peer_dir = "s2c" if uni.direction == "c2s" else "c2s"
            for ident, val in pairs:
                if ident == 0x01:
                    ctx = self.encoder_ctx(uni.space, peer_dir)
                    if val > ctx.max_capacity:
                        ctx.max_capacity = val
        elif ftype == H3_GOAWAY:
            try:
                sid, _ = read_varint(payload, 0)
                self.goaway[uni.space] = sid
            except Exception:
                pass
        elif ftype == H3_MAX_PUSH_ID:
            pass

    def on_push_frame(self, uni, ftype, payload):
        if ftype == H3_HEADERS:
            try:
                headers, meta = decode_field_section(
                    payload, self.encoder_ctx(uni.space, uni.direction)
                )
                self.push_promises.append(
                    {"space": uni.space, "stream_id": uni.stream_id, "headers": headers}
                )
            except Exception as exc:
                uni.errors.append(str(exc))

    def on_uni_stream_type(self, uni, t):
        if is_grease(t):
            return
        if t == UNI_CONTROL:
            if (uni.space, uni.direction) in self.control_seen:
                self.errors.append("duplicate control stream %s" % (uni.space,))
            self.control_seen.add((uni.space, uni.direction))
        elif t == UNI_QPACK_ENCODER:
            if (uni.space, uni.direction) in self.encoder_seen:
                self.errors.append("duplicate encoder stream %s" % (uni.space,))
            self.encoder_seen.add((uni.space, uni.direction))

    # -- QPACK field sections --------------------------------------------
    def _decode_headers(self, resp, payload, source):
        ctx = self.encoder_ctx(resp.space, "s2c" if source == "response" else "c2s")
        try:
            headers, meta = decode_field_section(payload, ctx)
        except Blocked as exc:
            self.pending[(resp.space, "s2c" if source == "response" else "c2s")].append(
                (resp, payload, source)
            )
            resp.errors.append("headers blocked on dynamic table insert: %s" % exc)
            return
        except NeedMore:
            resp.errors.append("QPACK error: truncated field section")
            return
        except Exception as exc:
            resp.errors.append("QPACK error: %s" % exc)
            return
        if source == "response":
            resp.add_headers(headers, meta, "response")
        else:
            resp.add_headers(headers, meta, "request")

    def flush_blocked(self, space, direction):
        key = (space, direction)
        remain = []
        for resp, payload, source in self.pending.get(key, []):
            ctx = self.encoder_ctx(space, direction)
            try:
                headers, meta = decode_field_section(payload, ctx)
            except NeedMore:
                remain.append((resp, payload, source))
                continue
            except Blocked:
                remain.append((resp, payload, source))
                continue
            except Exception as exc:
                resp.errors.append("QPACK error after unblock: %s" % exc)
                continue
            resp.add_headers(headers, meta, source)
            if resp.errors and resp.errors[-1].startswith("headers blocked"):
                resp.errors.pop()
        self.pending[key] = remain


# ---------------------------------------------------------------------------
# Capsule loading (tolerant of naming)
# ---------------------------------------------------------------------------
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def maybe_bytes(value):
    """Interpret a capsule value as raw bytes (hex or base64)."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x < 256 for x in value):
        return bytes(value)
    if not isinstance(value, str):
        return None
    s = value.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    # Hex, tolerating separators such as "aa:bb:.." or "aa bb ..".
    compact = re.sub(r"[\s:]", "", s)
    if len(compact) >= 2 and len(compact) % 2 == 0 and HEX_RE.match(compact):
        try:
            return bytes.fromhex(compact)
        except ValueError:
            pass
    # Base64 (standard or URL-safe), with or without padding.
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            b = decoder(padded, validate=True) if decoder is base64.b64decode else decoder(padded)
            if b:
                return b
        except Exception:
            pass
    try:
        return s.encode("latin-1")
    except Exception:
        return None


def load_capsule(path):
    raw = open(path, "rb").read()
    text = raw.decode("utf-8", "replace")
    stripped = text.lstrip("\ufeff \t\r\n")
    prefix = None
    if stripped.startswith("RRTC5"):
        prefix = stripped[:6]
        stripped = stripped[6:].lstrip("\x00 \t\r\n")
    stripped = stripped.strip().strip("\x00")
    doc = None
    try:
        doc = json.loads(stripped)
    except Exception:
        pass
    if doc is None:
        # Locate the JSON document inside surrounding noise, if any.
        start_candidates = [i for i in (stripped.find("{"), stripped.find("[")) if i >= 0]
        end_candidates = [i for i in (stripped.rfind("}"), stripped.rfind("]")) if i >= 0]
        if not start_candidates or not end_candidates:
            raise ValueError("capsule does not contain a JSON document")
        start = min(start_candidates)
        end = max(end_candidates)
        doc = json.loads(stripped[start : end + 1])
    return doc, {"prefix": prefix, "raw_len": len(raw), "json_offset": 0}


def walk_json(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_json(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_json(v, path + ("[%d]" % i,))
    else:
        yield path, obj


def find_keys(doc, patterns, value_test=None):
    """Find leaves whose key path matches any regex; return [(path, value)]."""
    out = []
    for path, value in walk_json(doc):
        key = ".".join(path).lower()
        if any(re.search(p, key) for p in patterns):
            if value_test is None or value_test(value):
                out.append((path, value))
    return out


def norm_key(path):
    return re.sub(r"[^a-z0-9]+", "_", ".".join(path).lower())


def extract_first(doc, patterns, value_test=None):
    got = find_keys(doc, patterns, value_test)
    if not got:
        return None, None
    return got[0][1], got[0][0]


SECRET_EXCLUDE = ("resumption", "early", "exporter", "ku")


def classify_direction(path):
    s = ".".join(str(p) for p in path).lower()
    client_tokens = ("client", "initiator", "c2s", "to_server", "upstream", "request", "send")
    server_tokens = ("server", "responder", "s2c", "from_server", "downstream", "response", "recv")
    for t in client_tokens:
        if t in s:
            return "c2s"
    for t in server_tokens:
        if t in s:
            return "s2c"
    return None


def looks_like_secret(value):
    b = maybe_bytes(value)
    return b is not None and len(b) in (16, 32, 48) and len(value) != 0


def _secret_leaves(obj, path=(), parent=None):
    """Yield (path, value, containing-object) for every scalar leaf."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _secret_leaves(v, path + (str(k),), obj)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _secret_leaves(v, path + ("[%d]" % i,), obj)
    else:
        yield path, obj, parent


def _direction_with_context(path, parent):
    direction = classify_direction(path)
    if direction:
        return direction
    if isinstance(parent, dict):
        for key in ("role", "side", "direction", "peer", "endpoint", "party", "name"):
            value = parent.get(key)
            if isinstance(value, str):
                direction = classify_direction((key, value))
                if direction:
                    return direction
    return None


def collect_secret_candidates(doc):
    out = []
    for path, value, parent in _secret_leaves(doc):
        key = ".".join(str(p) for p in path).lower()
        if "secret" not in key:
            continue
        if any(x in key for x in SECRET_EXCLUDE):
            continue
        b = maybe_bytes(value)
        if b is None or len(b) not in (16, 32, 48):
            continue
        out.append(
            {
                "path": path,
                "parent": path[:-1],
                "value": b,
                "direction": _direction_with_context(path, parent),
            }
        )
    if out:
        return out
    # Fallback for capsules that name the secret fields without the word
    # "secret" (e.g. {"keys": {"client": "<hex>", "server": "<hex>"}}).
    exclude = SECRET_EXCLUDE + (
        "public",
        "private",
        "iv",
        "hp",
        "tag",
        "salt",
        "root",
        "ticket",
        "node",
        "prev",
        "hash",
        "cid",
    )
    for path, value, parent in _secret_leaves(doc):
        key = ".".join(str(p) for p in path).lower()
        if any(x in key for x in exclude):
            continue
        b = maybe_bytes(value)
        if b is None or len(b) not in (32, 48):
            continue
        direction = _direction_with_context(path, parent)
        if direction is None and not re.search(
            r"client|server|c2s|s2c|initiator|responder|traffic|quic|tls|keys?", key
        ):
            continue
        out.append(
            {
                "path": path,
                "parent": path[:-1],
                "value": b,
                "direction": direction,
            }
        )
    return out


def _secret_pairs_for_group(group):
    """Candidate (client, server) pairs inside one parent object."""
    c2s = [c for c in group if c["direction"] == "c2s"]
    s2c = [c for c in group if c["direction"] == "s2c"]
    unknown = [c for c in group if c["direction"] is None]
    pairs = []
    complete = bool(c2s and s2c)
    if c2s and s2c:
        for a in c2s[:4]:
            for b in s2c[:4]:
                pairs.append((a, b))
    elif c2s or s2c:
        only = c2s or s2c
        for a in only[:2]:
            pairs.append((a, a))
        for a in only[:2]:
            for b in unknown[:2]:
                pairs.append((a, b) if c2s else (b, a))
    elif unknown:
        # Deduplicate identical values while preserving order.
        uniq = []
        for c in unknown:
            if not any(c["value"] == u["value"] for u in uniq):
                uniq.append(c)
        if len(uniq) == 1:
            pairs.append((uniq[0], uniq[0]))
        elif len(uniq) == 2:
            pairs.append((uniq[0], uniq[1]))
        else:
            # Unknown ordering (e.g. a flat list of several connections):
            # try ordered pairings; AEAD rejects the wrong ones.
            for i in range(len(uniq)):
                for j in range(len(uniq)):
                    if i != j:
                        pairs.append((uniq[i], uniq[j]))
    return pairs, complete


def find_secret_sets(doc):
    """Return candidate (client_secret, server_secret) pairs from the capsule.

    Secrets are grouped by their parent JSON object; single-direction groups
    that are siblings (e.g. secrets.client.value / secrets.server.value) are
    paired within their common grandparent, so nested representations work.
    Remaining single-direction candidates are cross-paired as a last resort.
    Extra candidates are harmless: the AEAD tag decides which pair is real.
    """
    candidates = collect_secret_candidates(doc)
    if not candidates:
        return []
    groups = {}
    order = []
    for cand in candidates:
        parent = cand["parent"]
        if parent not in groups:
            groups[parent] = []
            order.append(parent)
        groups[parent].append(cand)

    suite_val, _ = extract_first(doc, (r"cipher", r"suite"))
    suite = parse_cipher(suite_val) if suite_val is not None else "TLS_AES_128_GCM_SHA256"

    sets = []

    def add_pair(a, b, label):
        sets.append(
            {
                "label": label,
                "suite": suite,
                "client_secret": a["value"],
                "server_secret": b["value"],
                "paths": (a["path"], b["path"]),
            }
        )

    used = set()
    # 1) groups that contain both directions
    for parent in order:
        pairs, complete = _secret_pairs_for_group(groups[parent])
        if not complete:
            continue
        used.add(parent)
        label = ".".join(parent) if parent else "root"
        for a, b in pairs[:8]:
            add_pair(a, b, label)
    # 2) sibling single-direction groups (same grandparent)
    by_grandparent = {}
    for parent in order:
        if parent in used:
            continue
        gp = parent[:-1]
        by_grandparent.setdefault(gp, []).append(parent)
    for gp, parents in by_grandparent.items():
        client_groups = [
            p for p in parents
            if any(c["direction"] == "c2s" for c in groups[p])
            and not any(c["direction"] == "s2c" for c in groups[p])
        ]
        server_groups = [
            p for p in parents
            if any(c["direction"] == "s2c" for c in groups[p])
            and not any(c["direction"] == "c2s" for c in groups[p])
        ]
        for pg in client_groups[:4]:
            a = next(c for c in groups[pg] if c["direction"] == "c2s")
            for ps in server_groups[:4]:
                b = next(c for c in groups[ps] if c["direction"] == "s2c")
                add_pair(a, b, ".".join(gp) if gp else "root")
                used.add(pg)
                used.add(ps)
    # 3) last resort: cross-pair whatever is left
    rem_c2s = []
    rem_s2c = []
    for parent in order:
        for c in groups[parent]:
            if c["direction"] == "c2s" and c not in rem_c2s:
                rem_c2s.append(c)
            elif c["direction"] == "s2c" and c not in rem_s2c:
                rem_s2c.append(c)
    for a in rem_c2s[:4]:
        for b in rem_s2c[:4]:
            if any(s["client_secret"] == a["value"] and s["server_secret"] == b["value"] for s in sets):
                continue
            add_pair(a, b, "cross")
    return sets[:16]


def walk_nodes(obj, path=()):
    """Yield (path, node) for every node including containers."""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_nodes(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_nodes(v, path + ("[%d]" % i,))


def parse_next_pn_map(doc):
    """Extract expected next packet numbers per direction / per CID."""
    out = {"c2s": None, "s2c": None, "per_cid": {}}

    def cid_from_tokens(tokens):
        for tok in tokens:
            b = maybe_bytes(tok)
            if b is not None and len(b) == 8:
                return b.hex()
        return None

    def take(path, value, cid=None):
        if cid is None:
            cid = cid_from_tokens(list(path))
        if isinstance(value, str) and value.strip().isdigit():
            value = int(value.strip())
        if isinstance(value, int):
            direction = classify_direction(path)
            if cid:
                out["per_cid"][cid] = value
            if direction:
                out[direction] = value
            elif not cid:
                # A single unqualified "next packet number": use it as a hint
                # for both directions (harmless: PN candidates are tried).
                if out["c2s"] is None:
                    out["c2s"] = value
                if out["s2c"] is None:
                    out["s2c"] = value
            return
        if isinstance(value, list):
            if len(value) >= 2 and all(isinstance(x, int) for x in value[:2]):
                out["c2s"], out["s2c"] = value[0], value[1]
            return
        if isinstance(value, dict):
            for k, v in value.items():
                take(path + (str(k),), v, cid)

    seen_paths = set()
    for path, node in walk_nodes(doc):
        key = ".".join(path).lower()
        if not re.search(r"next.*(pn|packet)|expected.*(pn|packet)|pn.*next", key):
            continue
        if isinstance(node, (dict, list, int)) and path not in seen_paths:
            seen_paths.add(path)
            take(path, node, cid_from_tokens(list(path)))
    return out


# ---------------------------------------------------------------------------
# rr-ledger validation
# ---------------------------------------------------------------------------
NODE_PREFIX = b"RR node 5\x00"


def parse_ledger_headers(headers):
    """Combine field lines, reject duplicate application fields."""
    combined = {}
    counts = {}
    for name, value in headers:
        n = name.lower()
        counts[n] = counts.get(n, 0) + 1
        combined.setdefault(n, value)
    app_dups = sorted(n for n in counts if counts[n] > 1 and n.startswith("x-rr-"))
    return combined, counts, app_dups


def response_to_record(resp, now=None):
    headers = []
    metas = []
    for hdrs, meta in resp.sections:
        headers.extend(hdrs)
        metas.append(meta)
    combined, counts, app_dups = parse_ledger_headers(headers)
    rec = {
        "space": resp.space,
        "stream_id": resp.stream_id,
        "time": float(resp.first_time) if resp.first_time is not None else None,
        "headers": [[n, v] for n, v in headers],
        "header_prefixes": metas,
        "field_counts": counts,
        "body_hex": bytes(resp.body).hex(),
        "body_len": len(resp.body),
        "data_frames": resp.data_frames,
        "header_frames": resp.header_frames,
        "fin": resp.fin,
        "errors": list(resp.errors),
        "valid_node": False,
        "node": None,
        "ticket": None,
        "seq": None,
        "prev": None,
        "reasons": [],
    }
    if app_dups:
        rec["reasons"].append("duplicate application fields: %s" % ",".join(app_dups))
        rec["errors"].append(rec["reasons"][-1])
        return rec
    # A field section sequence may include informational (1xx) responses;
    # the final status is the last one seen.
    status = None
    for name, value in headers:
        if name.lower() == ":status":
            status = value
    rec["status"] = status
    if status != "200":
        rec["reasons"].append("status is not 200")
        return rec
    needed = ("x-rr-ticket", "x-rr-seq", "x-rr-prev", "x-rr-node")
    missing = [n for n in needed if n not in combined]
    if missing:
        rec["reasons"].append("missing headers: %s" % ",".join(missing))
        return rec
    try:
        ticket = bytes.fromhex(combined["x-rr-ticket"].strip())
    except ValueError:
        rec["reasons"].append("bad x-rr-ticket hex")
        return rec
    try:
        prev = bytes.fromhex(combined["x-rr-prev"].strip())
    except ValueError:
        rec["reasons"].append("bad x-rr-prev hex")
        return rec
    try:
        node = bytes.fromhex(combined["x-rr-node"].strip())
    except ValueError:
        rec["reasons"].append("bad x-rr-node hex")
        return rec
    try:
        seq = int(combined["x-rr-seq"].strip(), 10)
    except ValueError:
        rec["reasons"].append("bad x-rr-seq decimal")
        return rec
    if len(ticket) != 16:
        rec["reasons"].append("ticket length %d != 16" % len(ticket))
        return rec
    if len(prev) != 32:
        rec["reasons"].append("prev length %d != 32" % len(prev))
        return rec
    if len(node) != 32:
        rec["reasons"].append("node length %d != 32" % len(node))
        return rec
    if not (0 <= seq < 1 << 32):
        rec["reasons"].append("sequence out of u32 range")
        return rec
    calc = hashlib.sha256(
        NODE_PREFIX + ticket + prev + struct.pack(">I", seq) + bytes(resp.body)
    ).digest()
    rec.update(
        ticket=ticket.hex(),
        seq=seq,
        prev=prev.hex(),
        node=node.hex(),
        node_calc=calc.hex(),
        body_sha256=hashlib.sha256(bytes(resp.body)).hexdigest(),
    )
    if calc != node:
        rec["reasons"].append("node hash mismatch (computed %s)" % calc.hex())
        return rec
    rec["valid_node"] = True
    return rec


def build_ledgers(records, requirements):
    """Group valid node records by ticket, validate chains, select a ledger."""
    groups = defaultdict(dict)  # ticket -> seq -> record
    conflicts = defaultdict(list)
    for rec in records:
        if not rec["valid_node"]:
            continue
        t = rec["ticket"]
        seq = rec["seq"]
        if seq in groups[t]:
            prev = groups[t][seq]
            if prev["node"] == rec["node"] and prev["body_hex"] == rec["body_hex"]:
                continue  # duplicate capture of the same response
            conflicts[t].append(seq)
            continue
        groups[t][seq] = rec

    ledgers = []
    req_lengths = sorted({int(r["length"]) for r in requirements if r.get("length") is not None})
    for ticket, nodes in groups.items():
        # When the capsule fixes the ledger length, sequences at or beyond it
        # are not part of the selected ledger (an unrelated proposal could
        # reuse the ticket); ignore them and record what was dropped.
        ignored = []
        if len(req_lengths) == 1:
            limit = req_lengths[0]
            ignored = sorted(s for s in nodes if s >= limit)
            if ignored:
                nodes = {s: rec for s, rec in nodes.items() if s < limit}
        seqs = sorted(nodes)
        length = len(seqs)
        ledger = {
            "ticket": ticket,
            "length": length,
            "seqs": seqs,
            "conflicts": conflicts.get(ticket, []),
            "ignored_out_of_range": ignored,
            "checks": {},
            "chain_ok": False,
            "chain_links_ok": False,
            "nodes": [],
        }
        reasons = []
        gaps = [i for i in range(length) if i not in nodes]
        if gaps:
            reasons.append("missing sequences %s" % gaps[:10])
            ledger["checks"]["sequence_gaps"] = gaps
        # Determine the expected node count: prefer a capsule length match,
        # but also report the observed contiguous run.
        first = nodes.get(0)
        chain_broken = []
        if first is None:
            reasons.append("no sequence 0")
        else:
            if first["prev"] != "00" * 32:
                reasons.append("sequence 0 prev is not all-zero")
            # The interoperability note lists the selection conditions
            # explicitly (length, sequences, zero first prev, ticket, terminal
            # root); the prev->node linkage is reported but not made fatal.
            for i in range(1, length):
                if i not in nodes:
                    break
                if nodes[i]["prev"] != nodes[i - 1]["node"]:
                    chain_broken.append(i)
        ledger["checks"]["reasons"] = reasons
        ledger["checks"]["chain_broken_at"] = chain_broken
        ledger["chain_links_ok"] = bool(first is not None and not gaps and not chain_broken)
        ledger["nodes"] = [
            {
                "seq": s,
                "prev": nodes[s]["prev"],
                "node": nodes[s]["node"],
                "body_hex": nodes[s]["body_hex"],
                "space": nodes[s]["space"],
                "stream_id": nodes[s]["stream_id"],
                "time": nodes[s]["time"],
            }
            for s in seqs
        ]
        # Compare against every requirement set that mentions a ticket/root.
        req_eval = []
        for req in requirements:
            ok = True
            detail = []
            if req.get("ticket") is not None:
                if req["ticket"] != ticket:
                    ok = False
                    detail.append("ticket mismatch")
            if req.get("length") is not None:
                if int(req["length"]) != length:
                    ok = False
                    detail.append("length %d != %d" % (length, int(req["length"])))
            if req.get("root") is not None:
                if length >= 1 and nodes.get(length - 1, {}).get("node") != req["root"]:
                    ok = False
                    detail.append("terminal node != root")
            if not reasons and ok:
                pass
            req_eval.append({"requirement": req, "matches": ok and not reasons, "detail": detail})
        ledger["requirements"] = [
            {
                "ticket": r.get("ticket"),
                "root": r.get("root"),
                "length": r.get("length"),
                "source": r.get("source"),
            }
            for r in requirements
        ]
        ledger["requirement_eval"] = req_eval
        ledger["matches_capsule"] = any(x["matches"] for x in req_eval) if req_eval else None
        ledger["chain_ok"] = not reasons
        ledger["selected"] = bool(
            ledger["chain_ok"]
            and (not req_eval or any(x["matches"] for x in req_eval))
        )
        ledgers.append(ledger)

    ledgers.sort(
        key=lambda L: (
            not L["selected"],
            not L["chain_ok"],
            -(L["length"]),
        )
    )
    selected = next((L for L in ledgers if L["selected"]), None)
    if selected is None and ledgers:
        # fall back to a structurally valid chain when the capsule omits metadata
        cand = [L for L in ledgers if L["chain_ok"]]
        if len(cand) == 1:
            selected = cand[0]
            selected["selected"] = True
            selected["fallback"] = True
    if selected is not None:
        bodies = [selected["nodes"][i]["body_hex"] for i in range(selected["length"])]
        selected["bodies_hex"] = bodies
        selected["root"] = selected["nodes"][-1]["node"] if selected["nodes"] else None
        selected["node_count"] = selected["length"]
        selected["concatenated_hex"] = "".join(bodies)
        selected["concatenated_sha256"] = hashlib.sha256(
            b"".join(bytes.fromhex(b) for b in bodies)
        ).hexdigest()
    return ledgers, selected


# ---------------------------------------------------------------------------
# Capture decoding driver
# ---------------------------------------------------------------------------
class Capture:
    def __init__(self, path):
        self.path = path
        self.interfaces = []
        self.packets = []
        self.datagrams = []
        self.reassembly = None
        self.duplicates = 0
        self.unparsed = []
        self.quic_failures = []
        self.packet_records = []
        self.stream_frames = []
        self.frame_stats = defaultdict(int)
        self.dcid_stats = defaultdict(set)
        self.cid_len = None
        self.cid_guess = None
        self.other_frames = []

    # -- layer 1-4 -------------------------------------------------------
    def load(self):
        self.interfaces, self.packets = read_pcapng(self.path)
        self.reassembly = IPReassembler()
        raw_datagrams = []
        for pk in self.packets:
            info = link_to_ip(pk.iface.linktype, pk.data)
            if info is None:
                self.unparsed.append({"packet": pk.index, "reason": "not IP"})
                continue
            version, off = info
            ip = parse_ipv4(pk.data, off) if version == 4 else parse_ipv6(pk.data, off)
            if ip is None:
                self.unparsed.append({"packet": pk.index, "reason": "bad IP header"})
                continue
            key = (version, ip["src"], ip["dst"], ip["id"], ip["proto"])
            if ip["offset"] != 0 or ip["mf"]:
                done = self.reassembly.add(
                    key, ip["offset"], ip["payload"], ip["mf"], pk.t
                )
                if done is None:
                    continue
                datagram, t = done
                raw_datagrams.append(
                    {
                        "t": t,
                        "iface": pk.iface.name,
                        "src": ip["src"],
                        "dst": ip["dst"],
                        "packet": pk.index,
                        "reassembled": True,
                    }
                )
            else:
                datagram = ip["payload"]
                raw_datagrams.append(
                    {
                        "t": pk.t,
                        "iface": pk.iface.name,
                        "src": ip["src"],
                        "dst": ip["dst"],
                        "packet": pk.index,
                        "reassembled": False,
                    }
                )
            udp = parse_udp(datagram)
            if udp is None:
                self.unparsed.append({"packet": pk.index, "reason": "bad UDP"})
                continue
            raw_datagrams[-1].update(
                {
                    "sport": udp["sport"],
                    "dport": udp["dport"],
                    "payload": udp["payload"],
                    "udp_length": udp["length"],
                }
            )
        # sort by exact merged time; drop exact duplicate QUIC payloads
        raw_datagrams.sort(key=lambda d: (d["t"], d["packet"]))
        seen = {}
        for d in raw_datagrams:
            q = d.get("payload")
            if q is None:
                continue
            if q in seen:
                self.duplicates += 1
                continue
            seen[q] = True
            self.datagrams.append(d)
        # heuristic CID length for --parse-only reporting
        self.cid_guess = guess_cid_len([d["payload"] for d in self.datagrams])

    # -- QUIC ------------------------------------------------------------
    def decrypt(self, keysets, cid_len):
        self.cid_len = cid_len
        for d in self.datagrams:
            q = d["payload"]
            if not q:
                continue
            sport = d["sport"]
            dport = d["dport"]
            if dport == 443 and sport != 443:
                direction = "c2s"
            elif sport == 443 and dport != 443:
                direction = "s2c"
            else:
                direction = "c2s" if dport <= sport else "s2c"
            d["direction"] = direction
            try:
                info = parse_quic_packet(q, cid_len)
            except (QuicError, NeedMore, ValueError) as exc:
                self.quic_failures.append(
                    {"time": float(d["t"]), "direction": direction, "reason": str(exc)}
                )
                continue
            d["quic"] = {
                k: info[k]
                for k in ("kind", "first_byte", "long", "dcid", "pn_offset", "end")
                if k in info
            }
            if "scid" in info:
                d["quic"]["scid"] = info["scid"]
            self.dcid_stats[direction].add(info.get("dcid", b"").hex())
            if info.get("kind") != "short":
                # No Initial/Handshake packets expected; record and skip.
                self.quic_failures.append(
                    {
                        "time": float(d["t"]),
                        "direction": direction,
                        "reason": "non-short-header packet (%s)" % info.get("kind"),
                    }
                )
                continue
            success = None
            for ks in keysets:
                # mapped secret first, then opposite (capsule naming may swap)
                for use_dir in (direction, "s2c" if direction == "c2s" else "c2s"):
                    dk = ks.keys[use_dir]
                    try:
                        res = decrypt_quic_packet(q, info, dk)
                    except QuicError:
                        continue
                    except Exception as exc:  # noqa: BLE001 - keep other sets alive
                        if not getattr(ks, "_warned", False):
                            print(
                                "WARNING: key set %d unexpected decryption error (%s); continuing"
                                % (ks.index, exc),
                                file=sys.stderr,
                            )
                            ks._warned = True
                        continue
                    success = (ks, use_dir, dk, res)
                    break
                if success:
                    break
            if success is None:
                d["decrypt_error"] = True
                self.quic_failures.append(
                    {
                        "time": float(d["t"]),
                        "direction": direction,
                        "dcid": info.get("dcid", b"").hex(),
                        "reason": "no key set decrypted the packet",
                    }
                )
                continue
            ks, used_dir, dk, res = success
            if used_dir != direction:
                ks.reverse_ok[direction] += 1
            ks.packets += 1
            dk.note_success(info.get("dcid", b""), res["pn"], res["gen_index"])
            secret_tag = hashlib.sha256(
                dk.secret + b"\x00" + ks.suite.encode("ascii")
            ).hexdigest()[:12]
            frames = parse_frames(res["plaintext"])
            rec = {
                "index": len(self.packet_records),
                "time": d["t"],
                "iface": d["iface"],
                "direction": direction,
                "keyset": ks.index,
                "secret_tag": secret_tag,
                "dcid": info.get("dcid", b"").hex(),
                "pn": res["pn"],
                "pn_len": res["pn_len"],
                "key_phase": res["key_phase"],
                "gen": res["gen_index"],
                "length": len(q),
                "frames": frames,
            }
            self.packet_records.append(rec)
            for fr in frames:
                self.frame_stats[fr["type"]] += 1
                if fr["type"] == "STREAM":
                    self.stream_frames.append(
                        {
                            "time": d["t"],
                            "index": rec["index"],
                            "direction": direction,
                            "keyset": ks.index,
                            "secret_tag": secret_tag,
                            "dcid": info.get("dcid", b"").hex(),
                            "stream_id": fr["stream_id"],
                            "offset": fr["offset"],
                            "data": fr["data"],
                            "fin": fr["fin"],
                        }
                    )
                elif fr["type"] in ("CONNECTION_CLOSE", "CONNECTION_CLOSE_APP"):
                    self.other_frames.append(
                        {
                            "packet": rec["index"],
                            "type": fr["type"],
                            "error_code": fr.get("error_code"),
                            "reason": fr.get("reason", b"").decode("latin-1", "replace"),
                        }
                    )

    def reset_decrypt(self):
        """Clear per-packet decode state so another cid_len can be tried."""
        self.cid_len = None
        self.packet_records = []
        self.stream_frames = []
        self.frame_stats = defaultdict(int)
        self.dcid_stats = defaultdict(set)
        self.quic_failures = []
        self.other_frames = []
        for d in self.datagrams:
            for k in ("direction", "quic", "decrypt_error"):
                d.pop(k, None)


def guess_cid_len(payloads):
    """Heuristic only (parse-only reporting): the CID length is a capsule field."""
    short = [p for p in payloads if p and not (p[0] & 0x80)]
    if not short:
        return None
    best = None
    prev_distinct = None
    for L in range(1, 21):
        distinct = len({p[1 : 1 + L] for p in short if len(p) > L})
        if prev_distinct is not None and prev_distinct <= 32 and distinct > max(64, 4 * prev_distinct):
            best = L - 1
            break
        prev_distinct = distinct
    return best


# ---------------------------------------------------------------------------
# Grouping decoded packets into logical connections
# ---------------------------------------------------------------------------
def make_space_of(mode):
    """Return the packet -> logical-connection mapping for a grouping mode."""

    def space_of(rec):
        if mode == "cid":
            # Group by the key material actually used, not by key-set index:
            # duplicate/cross candidate key sets that share a secret must still
            # land in the same stream space.
            return "%s:%s" % (rec.get("secret_tag", "ks%d" % rec["keyset"]), rec["dcid"])
        return "g"

    return space_of


def detect_groups(capture):
    """Return a function (direction, dcid) -> space key.

    If packet-number spaces overlap between destination CIDs, the CIDs belong
    to distinct connections; otherwise they are CIDs of one connection.
    """
    overlap = False
    detail = {}
    for direction in ("c2s", "s2c"):
        by_cid = defaultdict(set)
        for rec in capture.packet_records:
            if rec["direction"] != direction:
                continue
            by_cid[rec["dcid"]].add(rec["pn"])
        cids = list(by_cid)
        intersections = []
        for i in range(len(cids)):
            for j in range(i + 1, len(cids)):
                inter = by_cid[cids[i]] & by_cid[cids[j]]
                if inter:
                    intersections.append([cids[i], cids[j], len(inter)])
        if intersections:
            overlap = True
        detail[direction] = {
            "cids": {c: len(v) for c, v in by_cid.items()},
            "intersections": intersections,
        }
    # Also separate by key set: distinct secrets imply distinct connections.
    keysets = {rec["keyset"] for rec in capture.packet_records}
    multi_keyset = len(keysets) > 1
    mode = "cid" if (overlap or multi_keyset) else "global"
    return mode, make_space_of(mode), detail


def decode_http3(capture, mode, space_of):
    h3 = Http3Decoder()
    frames = sorted(
        capture.stream_frames, key=lambda f: (f["time"], f["index"], f["direction"])
    )
    assemblers = {}
    for fr in frames:
        space = space_of(fr)
        key = (space, fr["stream_id"], fr["direction"])
        asm = assemblers.get(key)
        if asm is None:
            asm = RecvStream()
            assemblers[key] = asm
        new = asm.push(fr["offset"], fr["data"], fr["fin"])
        if new:
            h3.feed_stream(
                space, fr["stream_id"], fr["direction"], new, fr["fin"], fr["time"]
            )
        if fr["fin"] and asm.complete() and new == b"":
            # FIN with no new bytes still needs to mark the stream finished
            h3.feed_stream(space, fr["stream_id"], fr["direction"], b"", True, fr["time"])
    # Flush any field sections that were blocked on missing inserts.
    for (space, direction) in list(h3.pending):
        h3.flush_blocked(space, direction)
    return h3, assemblers


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------
def fmt_time(t):
    return "%.9f" % float(t)


def print_parse_report(capture):
    print("=" * 78)
    print("Read Receipt / RR3-063 -- uplink.pcapng structural parse (no secrets)")
    print("=" * 78)
    print("file: %s" % capture.path)
    print("interfaces:")
    for ifc in capture.interfaces:
        print("  [%d] %s" % (ifc.index, ifc.describe()))
    print("EPB packets: %d" % len(capture.packets))
    print(
        "UDP datagrams after merge: %d (duplicate QUIC payloads dropped: %d)"
        % (len(capture.datagrams), capture.duplicates)
    )
    ra = capture.reassembly
    print(
        "IPv4 reassembly: %d fragment packets -> %d datagrams; duplicate fragments %d; "
        "conflicts %d; incomplete %d"
        % (
            ra.fragment_packets,
            ra.completed,
            ra.duplicate_fragments,
            ra.conflicts,
            ra.unfinished(),
        )
    )
    if capture.packets:
        print(
            "merged time range: %s .. %s (%s s)"
            % (
                fmt_time(capture.packets[0].t),
                fmt_time(capture.packets[-1].t),
                fmt_time(capture.packets[-1].t - capture.packets[0].t),
            )
        )
        by_iface = defaultdict(int)
        for pk in capture.packets:
            by_iface[pk.iface.name] += 1
        print("packets per interface: %s" % dict(by_iface))
        frag_iface = defaultdict(int)
        for d in capture.datagrams:
            if d.get("reassembled"):
                frag_iface[d["iface"]] += 1
        print("reassembled datagrams per interface: %s" % dict(frag_iface))

    shorts = [d for d in capture.datagrams if d.get("payload") and not (d["payload"][0] & 0x80)]
    longs = [d for d in capture.datagrams if d.get("payload") and (d["payload"][0] & 0x80)]
    print("QUIC datagrams: %d short-header, %d long-header" % (len(shorts), len(longs)))
    tuples = defaultdict(int)
    for d in capture.datagrams:
        tuples[(d["sport"], d["dport"])] += 1
    print("UDP 5-tuples (sport,dport): %s" % {k: v for k, v in sorted(tuples.items())})
    pnlen = defaultdict(int)
    firstb = defaultdict(int)
    for d in shorts:
        b0 = d["payload"][0]
        pnlen[(b0 & 3) + 1] += 1
        firstb[b0] += 1
    print("short-header PN lengths: %s" % dict(sorted(pnlen.items())))
    print(
        "short-header first bytes: %s"
        % " ".join("%02x:%d" % (k, firstb[k]) for k in sorted(firstb))
    )
    cid_len = capture.cid_len if capture.cid_len is not None else capture.cid_guess
    print("CID length: %s (heuristic; authoritative value comes from the capsule)" % cid_len)
    if cid_len:
        per_dir = defaultdict(lambda: defaultdict(int))
        for d in shorts:
            q = d["payload"]
            if len(q) < 1 + cid_len + 1:
                continue
            direction = "c2s" if d["dport"] == 443 else ("s2c" if d["sport"] == 443 else "?")
            per_dir[direction][q[1 : 1 + cid_len].hex()] += 1
        for direction, counts in per_dir.items():
            print("  %s destination CIDs (%d):" % (direction, len(counts)))
            for cid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
                print("    %s  %d packets" % (cid, n))
    print("first/last merged datagrams:")
    for d in capture.datagrams[:3] + capture.datagrams[-3:]:
        q = d.get("payload", b"")
        print(
            "  %s if=%-8s %s:%d->%s:%d len=%d %s"
            % (
                fmt_time(d["t"]),
                d["iface"],
                ".".join(str(b) for b in d["src"]),
                d["sport"],
                ".".join(str(b) for b in d["dst"]),
                d["dport"],
                len(q),
                q[:20].hex(),
            )
        )
    print("unparsed frames: %d; QUIC framing failures: %d" % (len(capture.unparsed), len(capture.quic_failures)))
    for f in capture.quic_failures[:5]:
        print("  ! %s" % f)
    print()
    print("Next step: full decode needs the capsule secrets:")
    print("  python solve.py ../capsule.json")
    print("=" * 78)


# ---------------------------------------------------------------------------
# Program entry helpers
# ---------------------------------------------------------------------------
def extract_requirements(args, doc):
    """Ledger selection requirements from CLI options and the capsule."""
    req = {"source": "capsule"}
    if args.ticket:
        b = maybe_bytes(args.ticket)
        if b:
            req["ticket"] = b.hex()
    if args.root:
        b = maybe_bytes(args.root)
        if b:
            req["root"] = b.hex()
    if args.length is not None:
        req["length"] = int(args.length)
    if doc is not None:
        if "ticket" not in req:
            val, _ = extract_first(doc, (r"x_rr_ticket", r"(^|\.)ticket(_hex)?$", r"ledger.*ticket"))
            b = maybe_bytes(val) if val is not None else None
            if b is not None and len(b) == 16:
                req["ticket"] = b.hex()
        if "root" not in req:
            val, _ = extract_first(
                doc,
                (r"x_rr_node", r"(^|\.)root(_hash)?$", r"ledger.*root", r"terminal.*node"),
            )
            b = maybe_bytes(val) if val is not None else None
            if b is not None and len(b) == 32:
                req["root"] = b.hex()
        if "length" not in req:
            val, _ = extract_first(
                doc,
                (
                    r"ledger.*(length|count|nodes)",
                    r"(^|\.)node_count$",
                    r"(^|\.)ledger_length$",
                    r"(^|\.)length$",
                ),
                value_test=lambda v: isinstance(v, int) or (isinstance(v, str) and v.isdigit()),
            )
            if val is not None:
                req["length"] = int(val)
    if any(k in req for k in ("ticket", "root", "length")):
        return [req]
    return []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def make_key_sets(secret_sets, next_pn, verbose=True):
    keysets = []
    seen = set()
    for i, s in enumerate(secret_sets):
        c = s.get("client_secret")
        sv = s.get("server_secret")
        if c is None or sv is None:
            continue
        if len(c) not in (16, 32, 48) or len(sv) not in (16, 32, 48):
            print(
                "WARNING: secret lengths client=%d server=%d look unusual"
                % (len(c), len(sv)),
                file=sys.stderr,
            )
        key = (c, sv, s["suite"])
        if key in seen:
            continue
        seen.add(key)
        ks = KeySet(len(keysets), s["suite"], c, sv, s.get("label", "set%d" % i))
        ks.keys["c2s"].capsule_next = next_pn.get("c2s")
        ks.keys["s2c"].capsule_next = next_pn.get("s2c")
        ks.keys["c2s"].capsule_per_cid = dict(next_pn.get("per_cid", {}))
        ks.keys["s2c"].capsule_per_cid = dict(next_pn.get("per_cid", {}))
        keysets.append(ks)
        if verbose:
            print(
                "key set %d (%s): cipher=%s client_secret=%s... server_secret=%s..."
                % (ks.index, ks.label, ks.suite, c.hex()[:12], sv.hex()[:12])
            )
    return keysets


def derive_filename_defaults(capsule_path):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    pcap = os.path.join(root, "uplink.pcapng")
    if not os.path.exists(pcap):
        pcap = os.path.join(os.getcwd(), "uplink.pcapng")
    out = os.path.join(here, "ledger.json")
    return pcap, out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read Receipt RR3-063 QUIC/HTTP-3/QPACK transit-capsule decoder"
    )
    ap.add_argument("capsule", nargs="?", help="path to capsule JSON (or RRTC5 receipt plaintext)")
    ap.add_argument("--pcap", default=None, help="path to uplink.pcapng")
    ap.add_argument("--out", default=None, help="path to write ledger.json")
    ap.add_argument("--parse-only", action="store_true", help="parse capture without secrets")
    ap.add_argument("--cid-len", type=int, default=None, help="QUIC destination CID length")
    ap.add_argument("--cipher", default=None, help="TLS cipher suite name")
    ap.add_argument("--client-secret", default=None, help="client->server traffic secret (hex/base64)")
    ap.add_argument("--server-secret", default=None, help="server->client traffic secret (hex/base64)")
    ap.add_argument("--next-pn-client", type=int, default=None)
    ap.add_argument("--next-pn-server", type=int, default=None)
    ap.add_argument("--ticket", default=None, help="expected ledger ticket (hex, 16 bytes)")
    ap.add_argument("--root", default=None, help="expected ledger root (hex, 32 bytes)")
    ap.add_argument("--length", type=int, default=None, help="expected ledger node count")
    ap.add_argument("--dump-packets", type=int, default=0, help="print N packet records after decode")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    pcap_default, out_default = derive_filename_defaults(args.capsule)
    pcap_path = args.pcap or pcap_default
    out_path = args.out or out_default
    if not os.path.exists(pcap_path):
        ap.error("pcap not found: %s" % pcap_path)

    capture = Capture(pcap_path)
    capture.load()

    if args.parse_only:
        print_parse_report(capture)
        if args.capsule:
            try:
                doc, meta = load_capsule(args.capsule)
                print("capsule keys: %s" % (list(doc.keys()) if isinstance(doc, dict) else type(doc).__name__))
                if meta.get("prefix"):
                    print("capsule prefix: %r" % meta["prefix"])
                sets = find_secret_sets(doc)
                for s in sets:
                    print(
                        "  secret set %s: suite=%s client=%d bytes server=%d bytes"
                        % (
                            s["label"],
                            s["suite"],
                            len(s["client_secret"]),
                            len(s["server_secret"]),
                        )
                    )
                print("  next_pn: %s" % parse_next_pn_map(doc))
            except Exception as exc:
                print("capsule load failed: %s" % exc)
        return 0

    # ---------------- full decode ----------------
    if not CRYPTO_AVAILABLE:
        print("ERROR: need cryptography or pycryptodome for AEAD", file=sys.stderr)
        return 3

    doc = None
    capsule_meta = {}
    if args.capsule:
        if not os.path.exists(args.capsule):
            ap.error("capsule not found: %s" % args.capsule)
        try:
            doc, capsule_meta = load_capsule(args.capsule)
        except Exception as exc:  # JSON errors, bad prefix, ...
            print("ERROR: could not load capsule %s: %s" % (args.capsule, exc), file=sys.stderr)
            return 2
        if not args.quiet:
            print("capsule: %s" % args.capsule)
            if capsule_meta.get("prefix"):
                print("  prefix: %r (RRTC5 transit capsule)" % capsule_meta["prefix"])
            print("  keys: %s" % list(doc.keys()) if isinstance(doc, dict) else "  (root is %s)" % type(doc).__name__)
            pretty = json.dumps(doc, indent=2, sort_keys=True)
            if len(pretty) > 4000:
                pretty = pretty[:4000] + "\n... (truncated)"
            print(pretty)

    # --- resolve secrets -------------------------------------------------
    secret_sets = []
    if args.client_secret and args.server_secret:
        c = maybe_bytes(args.client_secret)
        s = maybe_bytes(args.server_secret)
        suite = parse_cipher(args.cipher) if args.cipher else "TLS_AES_128_GCM_SHA256"
        secret_sets.append(
            {"label": "command line", "suite": suite, "client_secret": c, "server_secret": s}
        )
    elif doc is not None:
        secret_sets = find_secret_sets(doc)
    if not secret_sets and doc is not None:
        # last resort: any hex string of secret length in the capsule
        for path, value in walk_json(doc):
            b = maybe_bytes(value)
            if b is not None and len(b) in (32, 48) and "secret" in ".".join(path).lower():
                secret_sets.append(
                    {
                        "label": ".".join(path),
                        "suite": parse_cipher(args.cipher or "TLS_AES_128_GCM_SHA256"),
                        "client_secret": b,
                        "server_secret": b,
                    }
                )
                break
    if not secret_sets:
        print("ERROR: no traffic secrets found; pass --client-secret/--server-secret", file=sys.stderr)
        return 2

    # --- resolve cipher / cid length / next PN ---------------------------
    suite_arg = args.cipher
    if suite_arg:
        for s in secret_sets:
            s["suite"] = parse_cipher(suite_arg)

    cid_len = args.cid_len
    cap_cid_len = None
    if doc is not None:
        val, _ = extract_first(
            doc,
            (r"(^|[._])(dcid|cid|connection_id)[._]?(len|length)$", r"cid_length", r"dcid_length"),
        )
        if isinstance(val, int):
            cap_cid_len = val
        elif isinstance(val, str) and val.strip().isdigit():
            cap_cid_len = int(val.strip())
    if cid_len is None:
        cid_len = cap_cid_len
    if cid_len is None:
        cid_len = capture.cid_guess
        print(
            "WARNING: capsule did not provide cid_len; using heuristic %s"
            % cid_len,
            file=sys.stderr,
        )
    if cid_len is None:
        cid_len = 8
        print("WARNING: defaulting cid_len=8", file=sys.stderr)

    next_pn = {"c2s": None, "s2c": None, "per_cid": {}}
    if doc is not None:
        next_pn = parse_next_pn_map(doc)
    if args.next_pn_client is not None:
        next_pn["c2s"] = args.next_pn_client
    if args.next_pn_server is not None:
        next_pn["s2c"] = args.next_pn_server

    # --- build key sets ---------------------------------------------------
    keysets = make_key_sets(secret_sets, next_pn)

    if not keysets:
        print("ERROR: could not construct any usable key set", file=sys.stderr)
        return 2

    print("cid_len=%d  next_pn=%s" % (cid_len, next_pn))
    capture.decrypt(keysets, cid_len)

    # Safety net: if nothing decrypted and the CID length was not fixed on the
    # command line, try other common CID lengths.  AEAD authentication makes a
    # wrong length fail loudly (no false positives).
    if not capture.packet_records and args.cid_len is None:
        for alt in (8, 4, 16, 0, 12):
            if alt == cid_len:
                continue
            capture.reset_decrypt()
            trial = make_key_sets(secret_sets, next_pn, verbose=False)
            capture.decrypt(trial, alt)
            if capture.packet_records:
                print(
                    "NOTE: cid_len=%s produced no decryptions; cid_len=%d decrypted %d packets"
                    % (cid_len, alt, len(capture.packet_records)),
                    file=sys.stderr,
                )
                cid_len = alt
                keysets = trial
                break
            capture.reset_decrypt()

    # --- grouping and HTTP/3 ---------------------------------------------
    mode, space_of, group_detail = detect_groups(capture)
    print(
        "decrypted packets: %d/%d; grouping mode: %s"
        % (len(capture.packet_records), len(capture.datagrams), mode)
    )
    for ks in keysets:
        print(
            "  key set %d: %d packets (reverse-direction fallback: c2s=%d s2c=%d)"
            % (ks.index, ks.packets, ks.reverse_ok["c2s"], ks.reverse_ok["s2c"])
        )
    print("  PN spaces by direction: %s" % json.dumps(group_detail, default=str))

    # --- ledger requirements --------------------------------------------
    requirements = extract_requirements(args, doc)
    if requirements:
        print("ledger requirement: %s" % json.dumps(requirements[0]))
    else:
        print("WARNING: capsule has no ticket/root/length; selecting structurally valid chain only")

    def analyze(grouping_mode):
        h3x, _assemblers = decode_http3(capture, grouping_mode, make_space_of(grouping_mode))
        recs = []
        for (space, stream_id), resp in sorted(
            h3x.response.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])
        ):
            if not resp.sections and not resp.body:
                continue
            recs.append(response_to_record(resp))
        recs.sort(key=lambda r: (r["time"] if r["time"] is not None else 0, r["stream_id"]))
        leds, sel = build_ledgers(recs, requirements)
        return h3x, recs, leds, sel

    h3, records, ledgers, selected = analyze(mode)
    if selected is None:
        alt_mode = "cid" if mode == "global" else "global"
        h3b, records_b, ledgers_b, selected_b = analyze(alt_mode)
        if selected_b is not None:
            print(
                "NOTE: %s grouping produced no selectable ledger; %s grouping selected one"
                % (mode, alt_mode)
            )
            mode, h3, records, ledgers, selected = alt_mode, h3b, records_b, ledgers_b, selected_b
            group_detail["selected_mode"] = alt_mode
        else:
            # keep the alternative only if it validates more node records
            if sum(1 for r in records_b if r["valid_node"]) > sum(1 for r in records if r["valid_node"]):
                mode, h3, records, ledgers, selected = alt_mode, h3b, records_b, ledgers_b, selected_b
                group_detail["selected_mode"] = alt_mode

    # --- output ----------------------------------------------------------
    node_records = []
    for rec in records:
        r = dict(rec)
        node_records.append(r)

    h3_errors = []
    for key, fp in h3.assemblers.items():
        if fp.errors:
            h3_errors.append({"stream": list(key), "errors": fp.errors[:5]})
    for key, uni in h3.uni.items():
        errs = list(uni.errors)
        if uni.frames is not None:
            errs.extend(uni.frames.errors)
        if errs:
            h3_errors.append({"uni_stream": list(key), "errors": errs[:5]})
    control_settings = [
        {"space": key[0], "direction": key[1], "settings": pairs}
        for key, pairs in h3.settings.items()
    ]

    output = {
        "generator": "solve.py (Read Receipt RR3-063 QUIC/HTTP-3 decoder)",
        "pcap": os.path.abspath(pcap_path),
        "capsule": os.path.abspath(args.capsule) if args.capsule else None,
        "capsule_prefix": capsule_meta.get("prefix"),
        "config": {
            "cid_len": cid_len,
            "cipher_suites": [s.suite for s in keysets],
            "next_pn": next_pn,
            "grouping": mode,
        },
        "interfaces": [
            {
                "index": i.index,
                "name": i.name,
                "linktype": i.linktype,
                "tsresol": i.tsresol,
                "tsresol_base": i.base,
                "tsoffset": i.tsoffset,
            }
            for i in capture.interfaces
        ],
        "capture": {
            "packets": len(capture.packets),
            "datagrams": len(capture.datagrams),
            "duplicate_datagrams": capture.duplicates,
            "fragment_packets": capture.reassembly.fragment_packets,
            "reassembled_datagrams": capture.reassembly.completed,
            "incomplete_fragmented_datagrams": capture.reassembly.unfinished(),
            "decrypted_packets": len(capture.packet_records),
            "frame_counts": dict(capture.frame_stats),
            "decrypt_failures": capture.quic_failures,
        },
        "responses": node_records,
        "ledgers": ledgers,
        "selected": selected,
        "http3": {
            "control_settings": control_settings,
            "goaway": {str(k): v for k, v in h3.goaway.items()},
            "stream_errors": h3_errors[:20],
            "pending_blocked_sections": {str(k): len(v) for k, v in h3.pending.items() if v},
            "stream_assemblers": len(h3.assemblers),
            "uni_streams": len(h3.uni),
        },
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, sort_keys=False)
    print("wrote %s" % out_path)

    # --- console summary -------------------------------------------------
    valid = [r for r in records if r["valid_node"]]
    print(
        "responses: %d parsed, %d with valid x-rr-node; ledgers: %d"
        % (len(records), len(valid), len(ledgers))
    )
    for L in ledgers:
        print(
            "  ledger ticket=%s length=%d chain_ok=%s matches_capsule=%s selected=%s %s"
            % (
                L["ticket"][:16] + "...",
                L["length"],
                L["chain_ok"],
                L["matches_capsule"],
                L.get("selected"),
                ("reasons: " + "; ".join(L["checks"].get("reasons", []))) if L["checks"].get("reasons") else "",
            )
        )
    if args.dump_packets:
        for rec in capture.packet_records[: args.dump_packets]:
            print(
                "  pkt %s %s dcid=%s pn=%d frames=%s"
                % (
                    rec["index"],
                    rec["direction"],
                    rec["dcid"],
                    rec["pn"],
                    ",".join(fr["type"] for fr in rec["frames"]),
                )
            )
    if selected is None:
        print("NO VALID LEDGER SELECTED")
        if not capture.packet_records:
            print("  hint: no packets decrypted -- check secrets/cipher/cid_len")
        return 2
    print(
        "SELECTED ledger: ticket=%s length=%d root=%s"
        % (selected["ticket"], selected["length"], selected["nodes"][-1]["node"] if selected["nodes"] else None)
    )
    print("bodies (hex, in sequence order):")
    for i, b in enumerate(selected.get("bodies_hex", [])):
        print("  [%d] %s" % (i, b))
    print("concatenated sha256: %s" % selected.get("concatenated_sha256"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
