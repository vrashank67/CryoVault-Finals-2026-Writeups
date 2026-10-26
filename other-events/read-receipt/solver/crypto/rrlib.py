"""rrlib.py -- crypto / GF(256) / catalog primitives for the RR-3 "Read Receipt" case.

Implemented from ``rr3/service.txt`` (RR-3 interoperability note, revision 4.0)
and ``rr3/BRIEF.md``.  Pure Python 3.12 + pycryptodome; no network access.

Sections
--------
* GF(256) arithmetic, reduction polynomial 0x11d (x^8+x^4+x^3+x^2+1).
* Bytewise linear algebra over GF(256): Gauss-Jordan with partial pivoting,
  packed 1024-byte right-hand sides, particular solution + nullspace basis.
* Codec ``rr-package-1`` (seal / open / unpack).
* ``RR export 4`` receipt key and AES-256-GCM receipt decryption.
* ``RR delivery 5`` delivery key and AES-256-GCM delivery decryption.
* ``RR node 5`` ledger node hash.
* Read-only loader for the SQLite catalog snapshots ``rr3/tx0.db .. tx9.db``.

Run ``python rrlib.py`` for the built-in self-test.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sqlite3
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from Crypto.Cipher import AES

__all__ = [
    # GF(256)
    "POLY", "gf_add", "gf_mul", "gf_inv", "gf_div", "gf_pow", "gf_mul_bytes",
    "gf_self_test",
    # bytewise linear algebra
    "ByteRowReducer", "ByteSolution", "solve_bytewise", "apply_matrix",
    "check_solution",
    # rr-package-1
    "RR_PACKAGE_PREFIX", "rr_package_seal", "rr_package_open_compressed",
    "rr_package_pack", "rr_package_unpack",
    # receipts / delivery / ledger
    "AuthenticationError", "export_key", "receipt_decrypt",
    "delivery_key", "delivery_decrypt", "node_hash",
    # catalog
    "rr3_root", "load_catalog", "load_jobs", "load_device", "parse_view",
    "catalog_cookie", "catalog_cookie_hex", "symbol_sort_key",
    "catalog_symbol_order", "build_catalog_system", "Job", "View",
    # self-test
    "self_test",
]

# ---------------------------------------------------------------------------
# GF(256), polynomial 0x11d
# ---------------------------------------------------------------------------

POLY = 0x11D  # x^8 + x^4 + x^3 + x^2 + 1
_GF_ORDER = 255


def _build_gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * (2 * _GF_ORDER)
    log = [0] * 256
    x = 1
    for i in range(_GF_ORDER):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= POLY
    for i in range(_GF_ORDER, 2 * _GF_ORDER):
        exp[i] = exp[i - _GF_ORDER]
    return exp, log


_GF_EXP, _GF_LOG = _build_gf_tables()

# 256 translation tables: _MUL_TABLE[c][b] == gf_mul(c, b).
_MUL_TABLE: tuple[bytes, ...] = tuple(
    bytes(
        (_GF_EXP[_GF_LOG[c] + _GF_LOG[b]] if (c and b) else 0)
        for b in range(256)
    )
    for c in range(256)
)


def _check_byte(value: int, name: str = "value") -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an int in 0..255, got {type(value).__name__}")
    if not 0 <= value <= 255:
        raise ValueError(f"{name} must be in 0..255, got {value}")
    return value


def gf_add(a: int, b: int) -> int:
    """Addition in GF(256): XOR."""
    return _check_byte(a, "a") ^ _check_byte(b, "b")


def gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(256) with reduction polynomial 0x11d."""
    _check_byte(a, "a")
    _check_byte(b, "b")
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(256).  ``gf_inv(0)`` raises."""
    if _check_byte(a, "a") == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in GF(256)")
    return _GF_EXP[_GF_ORDER - _GF_LOG[a]]


def gf_div(a: int, b: int) -> int:
    """Division in GF(256): ``a * b^-1``."""
    _check_byte(a, "a")
    if _check_byte(b, "b") == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_ORDER - _GF_LOG[b]]


def gf_pow(a: int, exponent: int) -> int:
    """``a ** exponent`` in GF(256); negative exponents use the inverse."""
    _check_byte(a, "a")
    if not isinstance(exponent, int):
        raise TypeError("exponent must be an int")
    if a == 0:
        if exponent < 0:
            raise ZeroDivisionError("0 has no inverse in GF(256)")
        return 1 if exponent == 0 else 0
    if exponent < 0:
        a = gf_inv(a)
        exponent = -exponent
    exponent %= _GF_ORDER
    return _GF_EXP[(_GF_LOG[a] * exponent) % _GF_ORDER]


def gf_mul_bytes(coeff: int, data: bytes | bytearray | memoryview) -> bytes:
    """Scalar-multiply every byte of *data* by *coeff* over GF(256)."""
    _check_byte(coeff, "coeff")
    raw = bytes(data)
    if coeff == 0:
        return b"\x00" * len(raw)
    if coeff == 1:
        return raw
    return raw.translate(_MUL_TABLE[coeff])


# --- internal packed-row helpers -------------------------------------------------


def _scale_int(value: int, coeff: int, length: int) -> int:
    """Multiply each little-endian byte lane of packed *value* by *coeff*."""
    if coeff == 0:
        return 0
    if coeff == 1:
        return value
    return int.from_bytes(
        value.to_bytes(length, "little").translate(_MUL_TABLE[coeff]), "little"
    )


def _pack_values(row: Sequence[int], length: int) -> int:
    if len(row) != length:
        raise ValueError(f"row has length {len(row)}, expected {length}")
    try:
        raw = bytes(row)  # validates ints 0..255
    except (TypeError, ValueError) as exc:
        raise ValueError(f"matrix row entries must be ints in 0..255: {exc}") from None
    return int.from_bytes(raw, "little")


# ---------------------------------------------------------------------------
# Bytewise linear algebra over GF(256)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ByteSolution:
    """Solution of ``A * X = B`` over GF(256), bytewise.

    ``particular`` is a list of ``n`` byte strings (one per source symbol), each
    of length ``length`` (normally 1024).  The general solution is::

        X = particular
        for f, payload in free_values.items():   # f in free_columns
            X += payload * nullspace[index_of_f(f)]

    where ``payload * vector`` is bytewise GF(256) scalar multiplication.
    ``nullspace`` is a basis of the homogeneous system with one vector per free
    column, in the same order as ``free_columns``.  Each vector is length ``n``
    with integer coefficients 0..255.
    """

    particular: tuple[bytes, ...]
    nullspace: tuple[tuple[int, ...], ...]
    free_columns: tuple[int, ...]
    pivot_columns: tuple[int, ...]
    rank: int
    nullity: int
    length: int
    consistent: bool
    inconsistent_rows: tuple[int, ...]
    inconsistent_positions: tuple[int, ...]

    @property
    def n(self) -> int:
        """Number of source symbols (columns of A)."""
        return len(self.particular)

    def expand(self, free_values: Mapping[int, bytes]) -> list[bytes]:
        """Build a full solution from payload values for chosen free columns.

        ``free_values`` maps column index (must be in :attr:`free_columns`) to a
        payload of exactly :attr:`length` bytes.  Unspecified free columns stay
        zero.  The returned list has ``n`` byte strings.
        """
        unknown = set(free_values) - set(self.free_columns)
        if unknown:
            raise KeyError(f"not free columns: {sorted(unknown)}")
        x = [bytearray(v) for v in self.particular]
        index = {f: i for i, f in enumerate(self.free_columns)}
        for f, payload in free_values.items():
            raw = bytes(payload)
            if len(raw) != self.length:
                raise ValueError(
                    f"free value for column {f} has length {len(raw)}, "
                    f"expected {self.length}"
                )
            vec = self.nullspace[index[f]]
            alpha = int.from_bytes(raw, "little")
            for p, coeff in enumerate(vec):
                if coeff == 0:
                    continue
                if coeff == 1:
                    x[p] = (int.from_bytes(x[p], "little") ^ alpha).to_bytes(
                        self.length, "little"
                    )
                else:
                    scaled = _scale_int(alpha, coeff, self.length)
                    x[p] = (int.from_bytes(x[p], "little") ^ scaled).to_bytes(
                        self.length, "little"
                    )
        return [bytes(v) for v in x]


class ByteRowReducer:
    """Gauss-Jordan reduction of an ``m x n`` GF(256) matrix.

    The row operations are accumulated in a transformation matrix ``T`` so the
    expensive elimination is done once.  ``transform(B)`` applies ``T`` to any
    right-hand side with ``m`` payload rows, each of arbitrary common length
    (e.g. 1024), using packed little-endian integers and ``bytes.translate`` to
    process all byte columns at once.

    Pivoting is deterministic partial pivoting: among the rows at/below the
    current position, prefer a unit coefficient in the pivot column, otherwise
    take the first nonzero coefficient.
    """

    def __init__(self, A: Sequence[Sequence[int]], *, n_columns: int | None = None):
        rows = list(A)
        m = len(rows)
        if m:
            n = len(rows[0])
            for i, row in enumerate(rows):
                if len(row) != n:
                    raise ValueError(
                        f"A row {i} has length {len(row)}, expected {n}"
                    )
        else:
            n = 0
        if n_columns is not None:
            if m and n_columns != n:
                raise ValueError(
                    f"n_columns={n_columns} conflicts with A row length {n}"
                )
            n = n_columns
        self.m = m
        self.n = n
        a = [_pack_values(row, n) for row in rows]
        t = [1 << (8 * i) for i in range(m)]
        self.pivot_columns: list[int] = []
        self.pivot_rows: list[int] = []

        row = 0
        for col in range(n):
            if row >= m:
                break
            pivot = None
            unit = None
            for r in range(row, m):
                coeff = (a[r] >> (8 * col)) & 0xFF
                if coeff == 1:
                    unit = r
                    break
                if coeff and pivot is None:
                    pivot = r
            pivot = unit if unit is not None else pivot
            if pivot is None:
                continue
            if pivot != row:
                a[row], a[pivot] = a[pivot], a[row]
                t[row], t[pivot] = t[pivot], t[row]
            pv = (a[row] >> (8 * col)) & 0xFF
            if pv != 1:
                ipv = _GF_EXP[_GF_ORDER - _GF_LOG[pv]]
                a[row] = _scale_int(a[row], ipv, n)
                t[row] = _scale_int(t[row], ipv, m)
            pivot_row_a = a[row]
            pivot_row_t = t[row]
            for r in range(m):
                if r == row:
                    continue
                factor = (a[r] >> (8 * col)) & 0xFF
                if factor:
                    a[r] ^= _scale_int(pivot_row_a, factor, n)
                    t[r] ^= _scale_int(pivot_row_t, factor, m)
            self.pivot_columns.append(col)
            self.pivot_rows.append(row)
            row += 1

        self.rank = row
        self.reduced_rows: tuple[bytes, ...] = tuple(
            v.to_bytes(n, "little") for v in a
        )
        self.transform_rows: tuple[bytes, ...] = tuple(
            v.to_bytes(m, "little") for v in t
        )
        self._terms: tuple[tuple[tuple[int, int], ...], ...] = tuple(
            tuple((j, c) for j, c in enumerate(trow) if c)
            for trow in self.transform_rows
        )

    @property
    def free_columns(self) -> tuple[int, ...]:
        pivots = set(self.pivot_columns)
        return tuple(c for c in range(self.n) if c not in pivots)

    @property
    def nullity(self) -> int:
        return self.n - self.rank

    def transform(
        self,
        B: Sequence[bytes | bytearray] | bytes | bytearray,
        *,
        length: int | None = None,
    ) -> list[bytes]:
        """Return ``T * B``, one byte string per equation row.

        All payloads in *B* must have the same length.  A single bytes-like
        object is accepted when ``m == 1``.  Each byte position is an
        independent GF(256) system; packing a 1024-byte payload into one Python
        int lets the elimination reuse its row operation across all columns.
        """
        brows, L = _normalize_rhs(B, self.m, length)
        packed = [int.from_bytes(r, "little") for r in brows]
        out: list[bytes] = []
        for terms in self._terms:
            if not terms:
                out.append(b"\x00" * L)
                continue
            if len(terms) == 1 and terms[0][1] == 1:
                out.append(brows[terms[0][0]])
                continue
            acc = 0
            for j, coeff in terms:
                if coeff == 1:
                    acc ^= packed[j]
                else:
                    acc ^= _scale_int(packed[j], coeff, L)
            out.append(acc.to_bytes(L, "little"))
        return out

    def is_consistent(
        self,
        B: Sequence[bytes | bytearray] | bytes | bytearray,
        *,
        length: int | None = None,
    ) -> bool:
        """Whether the bottom (all-zero) RREF rows are zero after transforming B."""
        rows = self.transform(B, length=length)
        for i in range(self.rank, self.m):
            if any(rows[i]):
                return False
        return True

    def solve(
        self,
        B: Sequence[bytes | bytearray] | bytes | bytearray,
        *,
        length: int | None = None,
    ) -> ByteSolution:
        """Solve ``A * X = B`` bytewise and report rank/consistency."""
        brows, L = _normalize_rhs(B, self.m, length)
        reduced_b = self.transform(brows, length=L)

        inconsistent_rows: list[int] = []
        bad_positions: set[int] = set()
        for i in range(self.rank, self.m):
            row = reduced_b[i]
            if any(row):
                inconsistent_rows.append(i)
                for k, value in enumerate(row):
                    if value:
                        bad_positions.add(k)

        particular = [b"\x00" * L for _ in range(self.n)]
        for i, col in enumerate(self.pivot_columns):
            particular[col] = reduced_b[i]

        free = self.free_columns
        nullspace: list[tuple[int, ...]] = []
        for f in free:
            vec = [0] * self.n
            vec[f] = 1
            for i, p in enumerate(self.pivot_columns):
                vec[p] = self.reduced_rows[i][f]
            nullspace.append(tuple(vec))

        return ByteSolution(
            particular=tuple(particular),
            nullspace=tuple(nullspace),
            free_columns=free,
            pivot_columns=tuple(self.pivot_columns),
            rank=self.rank,
            nullity=self.nullity,
            length=L,
            consistent=not inconsistent_rows,
            inconsistent_rows=tuple(inconsistent_rows),
            inconsistent_positions=tuple(sorted(bad_positions)),
        )


def _normalize_rhs(
    B: Sequence[bytes | bytearray] | bytes | bytearray,
    m: int,
    length: int | None,
) -> tuple[list[bytes], int]:
    if isinstance(B, (bytes, bytearray, memoryview)):
        if m != 1:
            raise TypeError(
                f"a single bytes-like RHS is only valid for m=1 (got m={m}); "
                "pass a sequence of payload rows"
            )
        rows = [bytes(B)]
    else:
        rows = [bytes(row) for row in B]
    if len(rows) != m:
        raise ValueError(f"B has {len(rows)} rows, expected m={m}")
    if rows:
        L = len(rows[0])
        if length is not None and L != length:
            raise ValueError(f"B row length {L} conflicts with length={length}")
        for i, row in enumerate(rows):
            if len(row) != L:
                raise ValueError(
                    f"B row {i} has length {len(row)}, expected {L}"
                )
    else:
        L = 0 if length is None else length
        if L < 0:
            raise ValueError("length must be non-negative")
    return rows, L


def solve_bytewise(
    A: Sequence[Sequence[int]],
    B: Sequence[bytes | bytearray] | bytes | bytearray,
    *,
    n_columns: int | None = None,
    length: int | None = None,
) -> ByteSolution:
    """Convenience wrapper: reduce ``A`` once and solve for payload rows ``B``."""
    return ByteRowReducer(A, n_columns=n_columns).solve(B, length=length)


def apply_matrix(
    A: Sequence[Sequence[int]], X: Sequence[bytes | bytearray]
) -> list[bytes]:
    """Compute ``A * X`` over GF(256), bytewise.  ``X`` has one row per column."""
    rows = list(A)
    x = [bytes(v) for v in X]
    if rows:
        n = len(rows[0])
        for i, row in enumerate(rows):
            if len(row) != n:
                raise ValueError(f"A row {i} has length {len(row)}, expected {n}")
        if len(x) != n:
            raise ValueError(f"X has {len(x)} rows, expected n={n}")
    else:
        n = len(x)
    L = len(x[0]) if x else 0
    for i, v in enumerate(x):
        if len(v) != L:
            raise ValueError(f"X row {i} has length {len(v)}, expected {L}")
    out: list[bytes] = []
    for row in rows:
        acc = 0
        for coeff, value in zip(row, x):
            coeff = _check_byte(coeff, "A coefficient")
            if coeff == 0:
                continue
            if coeff == 1:
                acc ^= int.from_bytes(value, "little")
            else:
                acc ^= _scale_int(int.from_bytes(value, "little"), coeff, L)
        out.append(acc.to_bytes(L, "little"))
    return out


def check_solution(
    A: Sequence[Sequence[int]],
    X: Sequence[bytes | bytearray] | bytes | bytearray,
    B: Sequence[bytes | bytearray] | bytes | bytearray,
) -> bool:
    """Return True iff ``A * X == B`` over GF(256), byte for byte."""
    rows = list(A)
    m = len(rows)
    if m == 0:
        return True
    if isinstance(X, (bytes, bytearray, memoryview)):
        if len(rows[0]) != 1:
            raise TypeError(
                "a single bytes-like X is only valid when A has one column; "
                "pass one payload per source symbol"
            )
        x = [bytes(X)]
    else:
        x = [bytes(v) for v in X]
    if len(x) != len(rows[0]):
        return False
    b, L = _normalize_rhs(B, m, None)
    try:
        got = apply_matrix(rows, x)
    except ValueError:
        return False
    if len(got) != len(b):
        return False
    return all(g == r for g, r in zip(got, b))


# ---------------------------------------------------------------------------
# rr-package-1
# ---------------------------------------------------------------------------

RR_PACKAGE_PREFIX = b"RR package 1\x00"


def _require_length(value: bytes | bytearray, expected: int, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(raw)}")
    return raw


def _ctr_crypt(key: bytes, data: bytes) -> bytes:
    """AES-256-CTR, all-zero 16-byte initial counter, big-endian increment."""
    if len(key) != 32:
        raise ValueError(f"CTR key must be 32 bytes, got {len(key)}")
    return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=0).encrypt(data)


def rr_package_seal(
    compressed: bytes | bytearray, key: bytes | None = None
) -> bytes:
    """Inverse of :func:`rr_package_open_compressed`.

    ``compressed`` is the zlib-compressed stream.  A random 32-byte key is used
    unless supplied.  Layout: ``C || T`` with ``T = key XOR SHA256(prefix + C)``.
    The tag T is necessarily computed last: pick K, encrypt to get C, then T.
    """
    comp = bytes(compressed)
    k = os.urandom(32) if key is None else _require_length(key, 32, "key")
    ciphertext = _ctr_crypt(k, comp)
    h = hashlib.sha256(RR_PACKAGE_PREFIX + ciphertext).digest()
    tag = bytes(a ^ b for a, b in zip(k, h))
    return ciphertext + tag


def rr_package_open_compressed(stream: bytes | bytearray) -> bytes:
    """Recover the zlib-compressed stream from an rr-package-1 package."""
    raw = bytes(stream)
    if len(raw) < 32:
        raise ValueError(
            f"rr-package-1 stream must be at least 32 bytes, got {len(raw)}"
        )
    ciphertext, tag = raw[:-32], raw[-32:]
    h = hashlib.sha256(RR_PACKAGE_PREFIX + ciphertext).digest()
    key = bytes(a ^ b for a, b in zip(tag, h))
    return _ctr_crypt(key, ciphertext)


def rr_package_pack(data: bytes | bytearray, key: bytes | None = None) -> bytes:
    """Compress *data* then seal it as an rr-package-1 package."""
    return rr_package_seal(zlib.compress(bytes(data)), key=key)


def rr_package_unpack(stream: bytes | bytearray) -> bytes:
    """Open and zlib-decompress an rr-package-1 package.

    Raises ``zlib.error`` if the recovered stream is not valid zlib data (the
    practical signature of a corrupted tag/key).
    """
    return zlib.decompress(rr_package_open_compressed(stream))


# ---------------------------------------------------------------------------
# Keys, receipt, delivery, ledger hash
# ---------------------------------------------------------------------------


class AuthenticationError(ValueError):
    """Raised when an AES-GCM tag does not authenticate."""


def export_key(canonical_export: bytes | bytearray) -> bytes:
    """Receipt key: SHA256("RR export 4" + NUL + canonical export)."""
    return hashlib.sha256(b"RR export 4\x00" + bytes(canonical_export)).digest()


def _gcm_decrypt(
    key: bytes | bytearray,
    nonce: bytes | bytearray,
    sealed: bytes | bytearray,
    aad: bytes | bytearray,
    label: str,
) -> bytes:
    k = _require_length(key, 32, f"{label} key")
    n = _require_length(nonce, 12, f"{label} nonce")
    a = bytes(aad)
    if len(a) != 48:
        raise ValueError(
            f"{label} AAD must be raw ticket[16] || 32-byte component = 48 bytes, "
            f"got {len(a)}"
        )
    blob = bytes(sealed)
    if len(blob) < 16:
        raise ValueError(
            f"{label} sealed blob must contain ciphertext plus a 16-byte tag, "
            f"got {len(blob)} bytes"
        )
    ciphertext, tag = blob[:-16], blob[-16:]
    cipher = AES.new(k, AES.MODE_GCM, nonce=n)
    cipher.update(a)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:  # pycryptodome raises ValueError on MAC mismatch
        raise AuthenticationError(
            f"{label}: AES-256-GCM authentication failed (wrong key, nonce, "
            "AAD, or corrupted ciphertext/tag)"
        ) from exc


def receipt_decrypt(
    key: bytes | bytearray,
    nonce: bytes | bytearray,
    sealed: bytes | bytearray,
    aad: bytes | bytearray,
) -> bytes:
    """Decrypt the receipt job: AES-256-GCM, ``sealed = ct || tag[16]``.

    ``aad`` is ``raw ticket[16] || raw catalog cookie[32]`` (48 bytes).
    """
    return _gcm_decrypt(key, nonce, sealed, aad, "receipt")


def delivery_key(
    sparse_export_key: bytes | bytearray, concat_bodies: bytes | bytearray
) -> bytes:
    """Delivery key: SHA256("RR delivery 5" + NUL + export key[32] + SHA256(bodies))."""
    export = _require_length(sparse_export_key, 32, "sparse export key")
    bodies_hash = hashlib.sha256(bytes(concat_bodies)).digest()
    return hashlib.sha256(b"RR delivery 5\x00" + export + bodies_hash).digest()


def delivery_decrypt(
    key: bytes | bytearray,
    nonce: bytes | bytearray,
    blob: bytes | bytearray,
    aad: bytes | bytearray,
) -> bytes:
    """Decrypt delivery.bin: AES-256-GCM, ``blob = ct || tag[16]``.

    ``aad`` is ``raw capsule.ticket[16] || raw capsule.root[32]`` (48 bytes).
    The key is :func:`delivery_key`; nonce is the first 12 bytes of delivery.bin.
    """
    return _gcm_decrypt(key, nonce, blob, aad, "delivery")


def node_hash(
    ticket: bytes | bytearray,
    prev: bytes | bytearray,
    seq: int,
    data: bytes | bytearray,
) -> bytes:
    """Ledger node hash: SHA256("RR node 5" + NUL + ticket + prev + u32be(seq) + data)."""
    t = _require_length(ticket, 16, "ticket")
    p = _require_length(prev, 32, "prev")
    if not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if not 0 <= seq <= 0xFFFFFFFF:
        raise ValueError(f"seq must fit in u32, got {seq}")
    return hashlib.sha256(
        b"RR node 5\x00" + t + p + struct.pack(">I", seq) + bytes(data)
    ).digest()


# ---------------------------------------------------------------------------
# Catalog snapshots (read-only)
# ---------------------------------------------------------------------------


def rr3_root() -> Path:
    """Directory containing the challenge files (``.../rr3``)."""
    return Path(__file__).resolve().parents[1]


def _open_ro(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} not found; run `python wal_replay.py` in {path.parent} "
            "to regenerate tx0.db .. tx9.db from catalog.db + catalog.db-wal"
        )
    con = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    con.execute("PRAGMA query_only = ON")
    return con


def _tx_path(tx_index: int, root: Path | None = None) -> Path:
    if not isinstance(tx_index, int) or tx_index < 0:
        raise ValueError(f"tx_index must be a non-negative int, got {tx_index!r}")
    base = rr3_root() if root is None else Path(root).resolve()
    return base / f"tx{tx_index}.db"


def load_catalog(
    tx_index: int,
    *,
    name: str | None = None,
    root: str | os.PathLike[str] | None = None,
    auto_replay: bool = False,
) -> tuple[str, int, bytes, dict]:
    """Load ``rr3/tx{tx_index}.db`` read-only.

    Returns ``(name, format, value_bytes, json_obj)`` where ``value_bytes`` is
    the zlib-compressed catalog blob from the ``catalog`` table and ``json_obj``
    is ``json.loads(zlib.decompress(value_bytes))``.

    The txN.db files are pre-built transaction snapshots (WAL frames applied).
    If one is missing and ``auto_replay=True``, ``wal_replay.py`` is executed in
    the rr3 directory first; otherwise a FileNotFoundError explains how to make
    them.  The databases themselves are never modified here.
    """
    path = _tx_path(tx_index, Path(root) if root is not None else None)
    if not path.is_file() and auto_replay:
        script = path.parent / "wal_replay.py"
        subprocess.run(
            [sys.executable, str(script)],
            cwd=str(path.parent),
            check=True,
        )
    con = _open_ro(path)
    try:
        if name is None:
            rows = con.execute("SELECT name, format, value FROM catalog").fetchall()
            if not rows:
                raise KeyError(f"{path}: catalog table is empty")
            if len(rows) > 1:
                raise ValueError(
                    f"{path}: multiple catalog rows {[r[0] for r in rows]}; "
                    "pass name=..."
                )
        else:
            rows = con.execute(
                "SELECT name, format, value FROM catalog WHERE name = ?", (name,)
            ).fetchall()
            if not rows:
                raise KeyError(f"{path}: no catalog row named {name!r}")
    finally:
        con.close()
    row_name, fmt, value = rows[0]
    value_bytes = bytes(value)
    try:
        obj = json.loads(zlib.decompress(value_bytes))
    except Exception as exc:
        raise ValueError(
            f"{path}: catalog value for {row_name!r} is not zlib-compressed JSON: {exc}"
        ) from exc
    return str(row_name), int(fmt), value_bytes, obj


@dataclass(frozen=True)
class View:
    """Pack/4 view descriptor: magic R4VW, namespace[16], handle[6], u64 offset, u64 length."""

    namespace: bytes
    handle: bytes
    offset: int
    length: int


def parse_view(view: bytes | bytearray) -> View:
    raw = bytes(view)
    if len(raw) != 42:
        raise ValueError(f"view must be 42 bytes, got {len(raw)}")
    if raw[:4] != b"R4VW":
        raise ValueError(f"view magic must be R4VW, got {raw[:4]!r}")
    return View(
        namespace=raw[4:20],
        handle=raw[20:26],
        offset=int.from_bytes(raw[26:34], "big"),
        length=int.from_bytes(raw[34:42], "big"),
    )


@dataclass(frozen=True)
class Job:
    """A row of the ``jobs`` table."""

    ticket: bytes
    state: str
    catalog_name: str
    view: bytes
    nonce: bytes
    sealed: bytes

    def parsed_view(self) -> View:
        return parse_view(self.view)


def load_jobs(
    tx_index: int, *, root: str | os.PathLike[str] | None = None
) -> list[Job]:
    """Load all ``jobs`` rows from a tx snapshot, in rowid order."""
    path = _tx_path(tx_index, Path(root) if root is not None else None)
    con = _open_ro(path)
    try:
        rows = con.execute(
            "SELECT ticket, state, catalog_name, view, nonce, sealed FROM jobs "
            "ORDER BY rowid"
        ).fetchall()
    finally:
        con.close()
    return [
        Job(
            ticket=bytes(ticket),
            state=str(state),
            catalog_name=str(catalog_name),
            view=bytes(view),
            nonce=bytes(nonce),
            sealed=bytes(sealed),
        )
        for ticket, state, catalog_name, view, nonce, sealed in rows
    ]


def load_device(
    tx_index: int, *, root: str | os.PathLike[str] | None = None
) -> dict[str, str]:
    """Load the ``device`` key/value table from a tx snapshot."""
    path = _tx_path(tx_index, Path(root) if root is not None else None)
    con = _open_ro(path)
    try:
        rows = con.execute("SELECT name, value FROM device ORDER BY name").fetchall()
    finally:
        con.close()
    return {str(name): str(value) for name, value in rows}


def catalog_cookie(value_bytes: bytes | bytearray) -> bytes:
    """Catalog cookie = SHA-256 of the stored compressed catalog value (raw 32 bytes)."""
    return hashlib.sha256(bytes(value_bytes)).digest()


def catalog_cookie_hex(value_bytes: bytes | bytearray) -> str:
    """Catalog cookie as lowercase hex (as carried in RRP2 COMMIT/CONFIRM JSON)."""
    return catalog_cookie(value_bytes).hex()


def symbol_sort_key(symbol: str) -> tuple[int, int]:
    """Natural order for source symbols like ``"2:17"`` -> (2, 17)."""
    head, sep, tail = str(symbol).partition(":")
    if not sep:
        raise ValueError(f"symbol must look like 'generation:index', got {symbol!r}")
    return int(head), int(tail)


def catalog_symbol_order(catalog: Mapping) -> list[str]:
    """All symbols referenced by the catalog rows or declared in ``symbols``."""
    symbols: set[str] = set(catalog.get("symbols", {}))
    for row in catalog.get("rows", []):
        for term in row.get("terms", []):
            symbols.add(term[0])
    return sorted(symbols, key=symbol_sort_key)


def build_catalog_system(
    catalog: Mapping,
    payloads: Mapping[tuple, bytes | bytearray] | Callable[[Mapping], bytes | bytearray],
    *,
    symbol_order: Sequence[str] | None = None,
) -> tuple[list[list[int]], list[bytes], list[str]]:
    """Turn catalog rows into ``(A, B, symbol_order)`` for :func:`solve_bytewise`.

    ``payloads`` is either a mapping from locator ``(chip, slot, cycle)`` to the
    chosen 1024-byte row payload, or a callable ``payloads(row) -> bytes`` when
    candidate selection is per row.  Duplicate terms for one symbol are XORed.
    """
    rows = list(catalog.get("rows", []))
    order = list(symbol_order) if symbol_order is not None else catalog_symbol_order(catalog)
    index = {symbol: i for i, symbol in enumerate(order)}
    if len(index) != len(order):
        raise ValueError("symbol_order contains duplicates")
    width = catalog.get("width")
    A: list[list[int]] = []
    B: list[bytes] = []
    for ri, row in enumerate(rows):
        coeffs = [0] * len(order)
        for term in row.get("terms", []):
            symbol, coeff = term[0], int(term[1])
            if symbol not in index:
                raise KeyError(f"row {ri}: symbol {symbol!r} is not in symbol_order")
            _check_byte(coeff, f"row {ri} coefficient for {symbol}")
            coeffs[index[symbol]] ^= coeff
        A.append(coeffs)
        if callable(payloads):
            payload = payloads(row)
        else:
            payload = payloads[tuple(row["at"])]
        raw = bytes(payload)
        if width is not None and len(raw) != int(width):
            raise ValueError(
                f"row {ri} payload has length {len(raw)}, catalog width is {width}"
            )
        B.append(raw)
    if B:
        L = len(B[0])
        for i, raw in enumerate(B):
            if len(raw) != L:
                raise ValueError(f"B row {i} has length {len(raw)}, expected {L}")
    return A, B, order


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _gf_mul_slow(a: int, b: int) -> int:
    """Independent bit-serial GF(256) multiply, used only by the self-test."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= POLY
    return result


def _matmul(A: Sequence[Sequence[int]], X: Sequence[bytes]) -> list[bytes]:
    return apply_matrix(A, X)


def _solver_self_test() -> None:
    rnd = random.Random(0xC0FFEE)

    A = [[rnd.randrange(256) for _ in range(12)] for _ in range(8)]
    X = [bytes(rnd.randrange(256) for _ in range(16)) for _ in range(12)]
    B = _matmul(A, X)
    sol = solve_bytewise(A, B)
    assert sol.consistent, "consistent random system reported inconsistent"
    assert check_solution(A, sol.particular, B), "particular solution does not check"
    assert sol.rank <= min(8, 12)
    if sol.free_columns:
        free_values = {
            f: bytes(rnd.randrange(256) for _ in range(16))
            for f in sol.free_columns
        }
        assert check_solution(A, sol.expand(free_values), B), "nullspace expansion fails"

    A_bad = [[1, 1], [1, 1]]
    B_bad = [b"\x01\x02", b"\x03\x04"]
    bad = solve_bytewise(A_bad, B_bad)
    assert not bad.consistent, "inconsistent system reported consistent"
    assert not check_solution(A_bad, bad.particular, B_bad)
    assert bad.inconsistent_positions == (0, 1)

    # zero matrix: everything is free, consistency requires B == 0
    zero = ByteRowReducer([[0, 0], [0, 0]])
    assert zero.solve([b"\x00\x00", b"\x00\x00"]).consistent
    assert not zero.solve([b"\x00\x00", b"\x01\x00"]).consistent
    assert zero.solve([b"\x00\x00", b"\x00\x00"]).nullity == 2
    # no equations: n columns supplied explicitly
    empty = ByteRowReducer([], n_columns=3)
    es = empty.solve([], length=4)
    assert es.consistent and es.rank == 0 and es.nullity == 3
    assert es.particular == (b"\x00" * 4,) * 3


def gf_self_test(verbose: bool = False) -> bool:
    """Exhaustive/structural GF(256) self-test.  Raises AssertionError on failure."""
    # table consistency
    for a in range(1, 256):
        assert _GF_EXP[_GF_LOG[a]] == a
    # all 65536 products vs independent bit-serial implementation
    for a in range(256):
        for b in range(256):
            assert gf_mul(a, b) == _gf_mul_slow(a, b), f"mul({a:#x},{b:#x})"
    # known spot checks (0x11d field)
    vectors = {
        (0x53, 0xCA): 0x8F,
        (0x02, 0x80): 0x1D,
        (0x03, 0x07): 0x09,
        (0x11, 0x13): 0x3E,
        (0xFF, 0xFF): 0xE2,
        (0x80, 0x80): 0x13,
        (0x1D, 0x02): 0x3A,
        (0x57, 0x83): 0x31,
    }
    for (a, b), expected in vectors.items():
        assert gf_mul(a, b) == expected, f"spot check mul({a:#x},{b:#x})"
    # inverses for every nonzero element
    for a in range(1, 256):
        inv = gf_inv(a)
        assert gf_mul(a, inv) == 1, f"inverse of {a:#x}"
        assert gf_div(1, a) == inv
        assert gf_mul_bytes(a, b"\x01\x02") == bytes([a, gf_mul(a, 2)])
    assert gf_inv(2) == 0x8E
    assert gf_inv(0x53) == 0x8C
    # associative + distributive (deterministic random samples)
    rnd = random.Random(0x11D)
    for _ in range(3000):
        a, b, c = (rnd.randrange(256) for _ in range(3))
        assert gf_mul(gf_mul(a, b), c) == gf_mul(a, gf_mul(b, c))
        assert gf_mul(a, gf_add(b, c)) == gf_add(gf_mul(a, b), gf_mul(a, c))
        assert gf_add(a, a) == 0
    # power / scalar helpers
    for a in range(1, 256):
        assert gf_pow(a, 0) == 1
        assert gf_pow(a, 1) == a
        assert gf_pow(a, 255) == 1
        assert gf_pow(a, -1) == gf_inv(a)
        assert gf_pow(a, 256) == a
    assert gf_mul_bytes(0x02, b"\x80\x01\x00") == b"\x1d\x02\x00"
    if verbose:
        print("GF(256) 0x11d: 65536 products, all inverses, laws, spot checks OK")
    return True


def _package_self_test() -> None:
    data = b"Read Receipt self-test packet\x00" + bytes(range(256)) * 3
    compressed = zlib.compress(data)
    key = bytes(range(32))
    package = rr_package_seal(compressed, key=key)
    assert rr_package_open_compressed(package) == compressed
    assert rr_package_unpack(package) == data
    assert package[-32:] == bytes(
        a ^ b
        for a, b in zip(
            key, hashlib.sha256(RR_PACKAGE_PREFIX + package[:-32]).digest()
        )
    )
    # pack() compresses on its own
    assert rr_package_unpack(rr_package_pack(data, key=key)) == data
    # deliberately corrupted final tag byte must fail the zlib check
    bad = package[:-1] + bytes([package[-1] ^ 0x01])
    try:
        rr_package_unpack(bad)
    except zlib.error:
        pass
    else:
        raise AssertionError("corrupted rr-package tag did not fail zlib")
    try:
        rr_package_unpack(b"\x00" * 10)
    except ValueError:
        pass
    else:
        raise AssertionError("short package did not raise")


def _crypto_self_test() -> None:
    # export key
    canon = b"R4SP" + (7).to_bytes(8, "big") + b"\x00"
    assert export_key(canon) == hashlib.sha256(b"RR export 4\x00" + canon).digest()

    # node hash fixed vectors (independently computed with hashlib)
    ticket = bytes(range(16))
    prev = bytes(range(32))
    assert (
        node_hash(ticket, prev, 7, b"ledger body bytes").hex()
        == "e17384aa744e9946389488596d610d1e23d32cf8f4c5de224f8e5caa78eda569"
    )
    assert (
        node_hash(b"\x00" * 16, b"\x00" * 32, 0, b"").hex()
        == "be36eb78167435a0ff66b456bb9e53dead2b91c659e2e43c44786ea412ed2962"
    )
    assert node_hash(ticket, prev, 5, b"abc") == hashlib.sha256(
        b"RR node 5\x00" + ticket + prev + struct.pack(">I", 5) + b"abc"
    ).digest()

    # receipt GCM round trip / tag failure
    rkey = bytes(range(32))
    nonce = bytes(range(12))
    aad = ticket + bytes(range(32))
    plaintext = b"RRTC5\x00" + b'{"test":true}'
    enc = AES.new(rkey, AES.MODE_GCM, nonce=nonce)
    enc.update(aad)
    ct, tag = enc.encrypt_and_digest(plaintext)
    assert receipt_decrypt(rkey, nonce, ct + tag, aad) == plaintext
    for args in (
        (rkey, nonce, ct + bytes([tag[0] ^ 1]) + tag[1:], aad),
        (rkey, nonce, ct + tag, bytes([aad[0] ^ 1]) + aad[1:]),
    ):
        try:
            receipt_decrypt(*args)
        except AuthenticationError:
            pass
        else:
            raise AssertionError("receipt tag failure not detected")

    # delivery key / GCM round trip
    sparse = bytes(range(32))
    bodies = b"DATA payload" * 17
    dkey = delivery_key(sparse, bodies)
    expected = hashlib.sha256(
        b"RR delivery 5\x00" + sparse + hashlib.sha256(bodies).digest()
    ).digest()
    assert dkey == expected
    enc = AES.new(dkey, AES.MODE_GCM, nonce=nonce)
    enc.update(aad)
    ct, tag = enc.encrypt_and_digest(b"final receipt")
    assert delivery_decrypt(dkey, nonce, ct + tag, aad) == b"final receipt"
    try:
        delivery_decrypt(bytes(32), nonce, ct + tag, aad)
    except AuthenticationError:
        pass
    else:
        raise AssertionError("delivery tag failure not detected")


def _catalog_self_test() -> None:
    root = rr3_root()
    if not (root / "tx3.db").is_file():
        return
    name, fmt, value, obj = load_catalog(3)
    assert name == "spool" and isinstance(fmt, int)
    assert catalog_cookie(value) == hashlib.sha256(value).digest()
    assert json.loads(zlib.decompress(value)) == obj
    assert obj["stream"]["codec"] == "rr-package-1"
    assert len(obj["rows"]) > 0


def self_test(verbose: bool = True) -> bool:
    """Run all built-in self-tests.  Returns True or raises AssertionError."""
    gf_self_test(verbose=verbose)
    _solver_self_test()
    _package_self_test()
    _crypto_self_test()
    _catalog_self_test()
    if verbose:
        print("solver: consistent/inconsistent, nullspace expansion OK")
        print("rr-package-1: seal/open/pack/unpack + corrupted tag OK")
        print("export/receipt/delivery/node-hash: fixed vectors + GCM OK")
        if (rr3_root() / "tx3.db").is_file():
            name, fmt, value, obj = load_catalog(3)
            print(
                f"catalog: tx3 name={name} format={fmt} value={len(value)}B "
                f"rows={len(obj['rows'])} cookie={catalog_cookie_hex(value)[:16]}..."
            )
        print("ALL SELF-TESTS PASSED")
    return True


if __name__ == "__main__":
    self_test(verbose=True)
