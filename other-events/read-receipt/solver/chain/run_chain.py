#!/usr/bin/env python3
"""Read Receipt (RR3-063) post-selection chain driver.

This script consumes the already-solved source stream (generation 1, 61291
bytes) and runs everything after it:

    stream.bin  -> rr-package-1 unpack -> pack/4 container
                -> R4SP canonical export (accepted job view)
                -> receipt key -> AES-256-GCM receipt
                -> RRTC5 transit capsule -> QUIC/HTTP-3 ledger (rr3/quic/solve.py)
                -> delivery key -> AES-256-GCM delivery.bin -> final receipt

Usage (from the project root, or anywhere):

    python rr3\\chain\\run_chain.py                    # ../stream.bin
    python rr3\\chain\\run_chain.py C:\\path\\stream.bin
    python rr3\\chain\\run_chain.py --selftest         # synthetic end-to-end test

Exit codes: 0 success, 1 chain failure (details in the message/log), 2 usage.
Nothing outside rr3/chain is written except rr3/capsule.json (required by the
chain) and rr3/quic/ledger.json (written by rr3/quic/solve.py itself).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

# ---------------------------------------------------------------------------
# locations / imports
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
RR3 = HERE.parent
PROJECT = RR3.parent

CRYPTO_DIR = RR3 / "crypto"
PACK4_DIR = RR3 / "pack4"
QUIC_DIR = RR3 / "quic"

for _p in (CRYPTO_DIR, PACK4_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import rrlib  # noqa: E402  (rr3/crypto/rrlib.py)
import pack4  # noqa: E402  (rr3/pack4/pack4.py)

try:  # recovery layer for the real capture's PN jumps / key updates
    import quic_rescue  # noqa: E402  (rr3/chain/quic_rescue.py)
except Exception as _rescue_exc:  # pragma: no cover - optional dependency
    quic_rescue = None
    _RESCUE_IMPORT_ERROR = _rescue_exc
else:
    _RESCUE_IMPORT_ERROR = None

# The accepted (COMMIT+CONFIRM) acquisition: WAL tx4/tx5 job, generation 1.
EXPECTED_SHA256 = "581d1bf2f89db0afc4633ce34a6e01147ec2f388c8ea6e88844116f42aef20b6"
EXPECTED_BYTES = 61291
RRTC5_PREFIX = b"RRTC5\x00"
FLAG_RE = re.compile(r"^isfcr\{[^{}\r\n]*\}$")

# Alternate catalog cookies from the link/acquisition history.  The accepted
# one (204d...) is always tried first; these are the other plausible values.
COOKIE_ACCEPTED = "204d906edf11f70d8a5d60fa4aeb9a5b3c3b578c7703831a379699949260e6b5"
COOKIE_TX3 = "1cc7ce6cadfef9a21a86b934cab79b8b40f0d7240a70d34c13f2c30b2de1c7f9"
COOKIE_CURRENT = "750af412d4eeb73b24c269816a79382da9e094465b9dfec76b3f9e1ebc49b048"


class ChainError(RuntimeError):
    """A clean, reportable chain failure (never a bare traceback for users)."""


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------


class Log:
    def __init__(self, path: Optional[Path] = None, echo: bool = True):
        self.path = path
        self.echo = echo
        self.lines: list[str] = []
        self._fh = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")

    def __call__(self, message: str = "") -> None:
        text = str(message)
        self.lines.append(text)
        if self.echo:
            print(text)
        if self._fh is not None:
            self._fh.write(text + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _hexdump_snippet(data: bytes, limit: int = 64) -> str:
    h = data.hex()
    if len(data) > limit:
        return h[: limit * 2] + f"... ({len(data)} bytes)"
    return h


# ---------------------------------------------------------------------------
# artifacts / options
# ---------------------------------------------------------------------------


@dataclass
class Paths:
    chain_dir: Path = HERE
    container: Path = HERE / "container.bin"
    export: Path = HERE / "export.r4sp"
    capsule_rr3: Path = RR3 / "capsule.json"
    capsule_chain: Path = HERE / "capsule.json"
    final_receipt: Path = HERE / "final_receipt.txt"
    ledger: Path = QUIC_DIR / "ledger.json"
    result: Path = HERE / "result.json"
    log: Optional[Path] = HERE / "run.log"

    @classmethod
    def under(cls, directory: Path, *, capsule_rr3: Optional[Path] = None) -> "Paths":
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        return cls(
            chain_dir=d,
            container=d / "container.bin",
            export=d / "export.r4sp",
            capsule_rr3=Path(capsule_rr3) if capsule_rr3 else d / "capsule.json",
            capsule_chain=d / "capsule.json",
            final_receipt=d / "final_receipt.txt",
            ledger=d / "ledger.json",
            result=d / "result.json",
            log=d / "run.log",
        )


@dataclass
class JobCandidate:
    label: str
    ticket: bytes
    nonce: bytes
    sealed: bytes
    view: bytes


@dataclass
class Accepted:
    ticket: bytes
    cookie: bytes
    nonce: bytes
    sealed: bytes
    view: bytes
    cookie_alternates: list[bytes] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# selection input (findings.json)
# ---------------------------------------------------------------------------


def load_accepted(findings_path: Path) -> Accepted:
    """Read the verified accepted job out of rr3/link/findings.json."""
    findings_path = Path(findings_path)
    if not findings_path.exists():
        raise ChainError(f"findings file not found: {findings_path}")
    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ChainError(f"cannot parse {findings_path}: {exc}") from exc

    ar = doc.get("accepted_receipt")
    if not isinstance(ar, dict):
        raise ChainError(f"{findings_path} has no accepted_receipt object")

    try:
        ticket = bytes.fromhex(ar["ticket"])
        cookie = bytes.fromhex(ar["cookie"])
        nonce = bytes.fromhex(ar["nonce_hex"])
        sealed = bytes.fromhex(ar["sealed_hex"])
        view = bytes.fromhex(ar["view"]["hex"])
    except KeyError as exc:
        raise ChainError(f"accepted_receipt is missing {exc}") from exc
    except ValueError as exc:
        raise ChainError(f"accepted_receipt has malformed hex: {exc}") from exc

    if len(ticket) != 16:
        raise ChainError(f"accepted ticket is {len(ticket)} bytes, expected 16")
    if len(cookie) != 32:
        raise ChainError(f"accepted cookie is {len(cookie)} bytes, expected 32")
    if len(nonce) != 12:
        raise ChainError(f"accepted nonce is {len(nonce)} bytes, expected 12")
    if len(view) != 42:
        raise ChainError(f"accepted view is {len(view)} bytes, expected 42")
    expected_sealed_sha = ar.get("sealed_sha256")
    if expected_sealed_sha and hashlib.sha256(sealed).hexdigest() != expected_sealed_sha:
        raise ChainError(
            "accepted sealed blob does not match its recorded sha256 "
            f"({hashlib.sha256(sealed).hexdigest()} != {expected_sealed_sha})"
        )
    aad_hex = ar.get("aad_hex")
    if aad_hex and (ticket + cookie).hex() != aad_hex:
        raise ChainError("accepted ticket||cookie does not match recorded aad_hex")

    # Other plausible catalog cookies, taken from the link findings (offers).
    alternates: list[bytes] = []
    for offer in (doc.get("handover") or {}).get("offers") or []:
        try:
            cand = bytes.fromhex(offer["cookie"])
        except Exception:
            continue
        if len(cand) == 32 and cand != cookie and cand not in alternates:
            alternates.append(cand)
    for hex_cookie in (COOKIE_TX3, COOKIE_CURRENT):
        cand = bytes.fromhex(hex_cookie)
        if cand != cookie and cand not in alternates:
            alternates.append(cand)

    return Accepted(
        ticket=ticket,
        cookie=cookie,
        nonce=nonce,
        sealed=sealed,
        view=view,
        cookie_alternates=alternates,
        raw=ar,
    )


def load_jobs_candidates(accepted: Accepted, jobs_tx: Optional[int]) -> list[JobCandidate]:
    """Accepted job first, then any other WAL job as a fallback."""
    jobs = [
        JobCandidate(
            label=f"accepted (findings, tx{jobs_tx if jobs_tx is not None else 4})",
            ticket=accepted.ticket,
            nonce=accepted.nonce,
            sealed=accepted.sealed,
            view=accepted.view,
        )
    ]
    if jobs_tx is None:
        return jobs
    try:
        db_jobs = rrlib.load_jobs(jobs_tx)
    except Exception:
        # txN.db snapshot may be absent; the findings blob is authoritative.
        return jobs
    for job in db_jobs:
        if job.sealed == accepted.sealed:
            continue
        if not job.view:
            continue
        jobs.append(
            JobCandidate(
                label=f"tx{jobs_tx} job ticket={job.ticket.hex()[:8]}",
                ticket=bytes(job.ticket),
                nonce=bytes(job.nonce),
                sealed=bytes(job.sealed),
                view=bytes(job.view),
            )
        )
    return jobs


# ---------------------------------------------------------------------------
# steps 1-2: stream verification and rr-package-1 unpack
# ---------------------------------------------------------------------------


def verify_stream(stream: bytes, expect_sha: Optional[str], expect_bytes: Optional[int]) -> str:
    digest = hashlib.sha256(stream).hexdigest()
    problems: list[str] = []
    if expect_sha is not None and digest != expect_sha:
        problems.append(f"sha256 mismatch: got {digest}, expected {expect_sha}")
    if expect_bytes is not None and len(stream) != expect_bytes:
        problems.append(f"length mismatch: got {len(stream)} bytes, expected {expect_bytes}")
    if problems:
        raise ChainError(
            "stream is not the accepted generation-1 stream ("
            + "; ".join(problems)
            + "); if this is a different catalog generation, the receipt job "
            "will not decrypt"
        )
    return digest


def unpack_stream(stream: bytes, log: Log) -> bytes:
    try:
        container = rrlib.rr_package_unpack(stream)
    except Exception as exc:
        # zlib.error is the practical signature of a wrong tag/key, i.e. a
        # stream that is not the accepted generation-1 stream.
        raise ChainError(
            f"rr-package-1 unpack failed ({type(exc).__name__}: {exc}); "
            "the stream is not a valid rr-package-1 package"
        ) from exc
    log(f"[2] rr-package-1 unpacked: {len(container)} container bytes")
    if len(container) < 20 or container[:8] != b"RRPCK4\x00\x00":
        raise ChainError(
            "decompressed stream is not a pack/4 container "
            f"(magic={container[:8]!r}, {len(container)} bytes)"
        )
    return container


# ---------------------------------------------------------------------------
# step 3-4: pack/4 view -> canonical R4SP export
# ---------------------------------------------------------------------------


class HashSink:
    """Hash-only sink used when an export is too large to materialize."""

    def __init__(self) -> None:
        self._h = hashlib.sha256(b"RR export 4\x00")
        self.total = 0

    def write(self, chunk: bytes) -> int:
        self._h.update(chunk)
        self.total += len(chunk)
        return len(chunk)

    def digest(self) -> bytes:
        return self._h.digest()


def _parse_container_lenient(container_bytes: bytes, log: Log):
    try:
        return pack4.parse_container(container_bytes), False
    except pack4.ParseError as strict_exc:
        try:
            cont = pack4.parse_container(container_bytes, allow_trailing=True)
        except pack4.ParseError:
            raise ChainError(f"pack/4 container parse failed: {strict_exc}") from strict_exc
        log(f"[4] note: container has trailing bytes ({strict_exc}); parsed leniently")
        return cont, True


def build_export(
    container_bytes: bytes,
    view_bytes: bytes,
    endian: str,
    *,
    export_cap: int,
    hash_cap: int,
    log: Log,
    persist: Optional[Path] = None,
) -> tuple[bytes, dict]:
    """Resolve the view to canonical R4SP bytes under one endianness reading.

    Returns (export_bytes, meta).  When the export would be larger than
    export_cap it is streamed into a hash sink instead of RAM (export_bytes is
    then b"" and meta["hash_only"] is True); export_key is identical either way.
    """
    fmt = "<" if endian in ("le", "little", "<") else ">"
    container, lenient = _parse_container_lenient(container_bytes, log)
    try:
        view = pack4.parse_view(view_bytes, endian=fmt)
    except pack4.Pack4Error as exc:
        raise ChainError(f"view parse failed ({endian}): {exc}") from exc

    resolver = pack4.Resolver(container)
    try:
        segments = resolver.resolve_view_segments(view)
    except pack4.Pack4Error as exc:
        raise ChainError(f"view resolution failed ({endian}): {exc}") from exc

    allocated = sum(seg.length for seg in segments if seg.allocated)
    runs = pack4.group_runs(segments, view.length)
    node_id = resolver.lookup_view(view)
    meta: dict[str, Any] = {
        "endian": "le" if fmt == "<" else "be",
        "view_offset": view.offset,
        "view_length": view.length,
        "namespace": view.namespace_id.hex(),
        "handle": view.handle.hex(),
        "bound_node": node_id.hex() if node_id else None,
        "segments": len(segments),
        "runs": len(runs),
        "allocated_bytes": allocated,
        "lenient_container": lenient,
        "hash_only": False,
        "export_bytes": None,
    }

    if allocated > hash_cap:
        raise ChainError(
            f"canonical export under the {meta['endian']} view would contain "
            f"{allocated} allocated bytes (> --hash-cap {hash_cap}); refusing to "
            "hash it blindly. Re-run with a larger --hash-cap if this is expected."
        )

    if allocated > export_cap:
        # Stream the export into a hash sink: no giant RAM allocation, no giant
        # file.  The bytes are only needed for SHA-256.
        sink = HashSink()
        resolver.write_canonical_export(view, sink)
        meta["hash_only"] = True
        meta["export_bytes"] = sink.total
        log(
            f"[4] {meta['endian']} view: {view.length} bytes requested, "
            f"{allocated} allocated, {len(runs)} runs -> hashed "
            f"{sink.total} export bytes (not materialized)"
        )
        # Recompute the key from the streamed bytes is impossible after the
        # fact, so return a marker; export_key is derived by the caller.
        return b"", meta

    if not lenient:
        export = pack4.resolve_view(container_bytes, view_bytes, view_endian=fmt)
    else:
        buf = io.BytesIO()
        resolver.write_canonical_export(view, buf)
        export = buf.getvalue()

    if not export.startswith(b"R4SP"):
        raise ChainError(f"canonical export has bad magic: {export[:8]!r}")
    declared = struct.unpack(">Q", export[4:12])[0]
    if declared != view.length:
        raise ChainError(
            f"canonical export declares length {declared}, view says {view.length}"
        )
    meta["export_bytes"] = len(export)
    log(
        f"[4] {meta['endian']} view: namespace={meta['namespace']} "
        f"handle=0x{meta['handle']} offset={view.offset} length={view.length} "
        f"node={meta['bound_node'] or '<unbound>'} runs={len(runs)} "
        f"allocated={allocated} export={len(export)} bytes"
    )
    if persist is not None:
        persist.write_bytes(export)
    return export, meta


# ---------------------------------------------------------------------------
# step 5: receipt key + AES-256-GCM job decryption
# ---------------------------------------------------------------------------


def receipt_attempts(
    container_bytes: bytes,
    jobs: Sequence[JobCandidate],
    cookies: Sequence[bytes],
    endians: Sequence[str],
    accepted: Accepted,
    paths: Paths,
    *,
    export_cap: int,
    hash_cap: int,
    log: Log,
) -> dict:
    """Try every (endianness, job, cookie) combination until GCM authenticates."""
    tried: list[dict] = []
    fallback_export: Optional[bytes] = None
    fallback_meta: Optional[dict] = None

    for endian in endians:
        export_path = paths.chain_dir / f"export.{'le' if endian == 'le' else 'be'}.r4sp"
        export, meta = build_export(
            container_bytes,
            accepted.view,
            endian,
            export_cap=export_cap,
            hash_cap=hash_cap,
            log=log,
            persist=export_path,
        )
        if meta["hash_only"]:
            # The hash sink already consumed SHA256("RR export 4\0"+export).
            key = None  # computed below via a second streaming pass is wasteful
            raise ChainError(
                "internal: hash-only export path needs a streaming key; "
                "increase --export-cap so the export fits in memory"
            )
        key = rrlib.export_key(export)
        if fallback_export is None:
            fallback_export, fallback_meta = export, meta
        log(
            f"[5] {meta['endian']} export {len(export)} bytes -> key {key.hex()[:16]}..."
        )
        for job in jobs:
            for cookie in cookies:
                aad = job.ticket + cookie
                try:
                    plaintext = rrlib.receipt_decrypt(
                        key, job.nonce, job.sealed, aad
                    )
                except rrlib.AuthenticationError:
                    tried.append(
                        {
                            "endian": meta["endian"],
                            "job": job.label,
                            "ticket": job.ticket.hex(),
                            "cookie": cookie.hex(),
                            "aad": aad.hex(),
                            "sealed_sha256": hashlib.sha256(job.sealed).hexdigest(),
                            "result": "GCM tag mismatch",
                        }
                    )
                    log(
                        f"    x {meta['endian']} job={job.ticket.hex()[:8]} "
                        f"cookie={cookie.hex()[:8]} -> GCM tag mismatch"
                    )
                    continue
                except Exception as exc:  # noqa: BLE001 - report, keep trying
                    tried.append(
                        {
                            "endian": meta["endian"],
                            "job": job.label,
                            "ticket": job.ticket.hex(),
                            "cookie": cookie.hex(),
                            "result": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    log(
                        f"    x {meta['endian']} job={job.ticket.hex()[:8]} "
                        f"cookie={cookie.hex()[:8]} -> {type(exc).__name__}: {exc}"
                    )
                    continue

                paths.export.write_bytes(export)
                log(
                    f"[5] SUCCESS endianness={meta['endian']} "
                    f"job={job.label} ticket={job.ticket.hex()} "
                    f"cookie={cookie.hex()} export={len(export)} bytes"
                )
                return {
                    "plaintext": plaintext,
                    "key": key,
                    "export": export,
                    "meta": meta,
                    "job": job,
                    "cookie": cookie,
                    "attempts": tried,
                    "chosen": {
                        "endian": meta["endian"],
                        "ticket": job.ticket.hex(),
                        "cookie": cookie.hex(),
                        "nonce": job.nonce.hex(),
                        "sealed_sha256": hashlib.sha256(job.sealed).hexdigest(),
                    },
                }

    # Nothing authenticated: keep the default (little-endian) export as the
    # canonical artifact and report exactly what was tried.
    if fallback_export is not None:
        paths.export.write_bytes(fallback_export)
    raise ChainError(
        "receipt GCM authentication failed for every candidate:\n"
        + "\n".join(
            f"  - endian={t['endian']} job={t['ticket'][:8]} "
            f"cookie={t['cookie'][:8]} ({t['result']})"
            for t in tried
        )
        + "\nThis means the export bytes are not the accepted view's canonical "
        "export (wrong container/view/endianness), or the selected stream is not "
        "the accepted generation-1 stream."
    )


# ---------------------------------------------------------------------------
# step 6a: transit capsule
# ---------------------------------------------------------------------------


def _walk_json(obj: Any, path: tuple[str, ...] = ()):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _walk_json(value, path + (str(key),))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_json(value, path + (f"[{i}]",))
    else:
        yield path, obj


def extract_hex_field(
    doc: Any, patterns: Sequence[str], nbytes: int
) -> tuple[Optional[bytes], Optional[str]]:
    for path, value in _walk_json(doc):
        key = ".".join(path).lower()
        if not any(re.search(p, key) for p in patterns):
            continue
        if not isinstance(value, str):
            continue
        text = value.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            continue
        if len(raw) == nbytes:
            return raw, ".".join(path)
    return None, None


def extract_int_field(doc: Any, patterns: Sequence[str]) -> Optional[int]:
    for path, value in _walk_json(doc):
        key = ".".join(path).lower()
        if not any(re.search(p, key) for p in patterns):
            continue
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


TICKET_PATTERNS = (r"x[_-]?rr[_-]?ticket", r"(^|\.)ticket(_hex)?$", r"ledger.*ticket")
ROOT_PATTERNS = (
    r"x[_-]?rr[_-]?node",
    r"(^|\.)root(_hash)?$",
    r"ledger.*root",
    r"terminal.*node",
)
LENGTH_PATTERNS = (
    r"ledger.*(length|count|nodes)",
    r"(^|\.)node_count$",
    r"(^|\.)ledger_length$",
    r"(^|\.)length$",
)


def parse_capsule(plaintext: bytes, paths: Paths, log: Log) -> tuple[bytes, dict]:
    body = plaintext[len(RRTC5_PREFIX):]
    body = body.rstrip(b"\x00").rstrip()
    if not body:
        raise ChainError("receipt is an RRTC5 capsule but the JSON body is empty")
    try:
        doc = json.loads(body.decode("utf-8"))
    except Exception as exc:
        preview = body[:200]
        raise ChainError(
            f"capsule JSON parse failed: {exc}; body starts with {preview!r}"
        ) from exc
    if not isinstance(doc, dict):
        raise ChainError(f"capsule JSON is {type(doc).__name__}, expected an object")

    # Write verbatim (the exact bytes that followed the RRTC5\0 prefix).
    paths.capsule_rr3.parent.mkdir(parents=True, exist_ok=True)
    paths.capsule_rr3.write_bytes(body)
    paths.capsule_chain.parent.mkdir(parents=True, exist_ok=True)
    paths.capsule_chain.write_bytes(body)
    log(f"[6] capsule written to {paths.capsule_rr3} and {paths.capsule_chain}")
    log(f"    capsule keys: {list(doc.keys())}")
    for key, value in doc.items():
        rendered = json.dumps(value, sort_keys=True)
        if len(rendered) > 400:
            rendered = rendered[:400] + "... (truncated)"
        log(f"    {key} = {rendered}")
    return body, doc


# ---------------------------------------------------------------------------
# step 6b: QUIC ledger + delivery
# ---------------------------------------------------------------------------


def run_quic_solver(paths: Paths, capsule_path: Path, log: Log, timeout: int) -> dict:
    solver = QUIC_DIR / "solve.py"
    if not solver.exists():
        raise ChainError(f"QUIC solver not found: {solver}")
    cmd = [sys.executable, str(solver), str(capsule_path)]
    log(f"[6] running: {' '.join(cmd)}")
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ChainError(f"QUIC solver timed out after {timeout}s") from exc
    elapsed = time.time() - started
    log(f"    solver exit={proc.returncode} in {elapsed:.1f}s")
    tail = (proc.stdout or "").strip().splitlines()
    for line in tail[-40:]:
        log(f"    | {line}")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        for line in err[-20:]:
            log(f"    ! {line}")
        raise ChainError(
            f"QUIC solver failed (exit {proc.returncode}); see {paths.log or 'stdout'}"
        )
    ledger_path = paths.ledger
    if not ledger_path.exists():
        raise ChainError(
            f"QUIC solver reported success but {ledger_path} does not exist"
        )
    try:
        return json.loads(ledger_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ChainError(f"cannot parse {ledger_path}: {exc}") from exc


def _ledger_bodies(ledger: dict) -> list[bytes]:
    bodies = []
    for entry in ledger.get("bodies_hex") or []:
        bodies.append(bytes.fromhex(entry))
    return bodies


def ledger_requirements(capsule_doc: dict) -> list[dict]:
    """Capsule-derived ledger selection requirements (same shape as solve.py)."""
    req: dict[str, Any] = {"source": "capsule"}
    ticket, _ = extract_hex_field(capsule_doc, TICKET_PATTERNS, 16)
    root, _ = extract_hex_field(capsule_doc, ROOT_PATTERNS, 32)
    length = extract_int_field(capsule_doc, LENGTH_PATTERNS)
    if ticket:
        req["ticket"] = ticket.hex()
    if root:
        req["root"] = root.hex()
    if length is not None:
        req["length"] = int(length)
    return [req] if len(req) > 1 else []


def ledger_matches_capsule(ledger: dict, capsule_doc: dict) -> bool:
    """Strictly check the selected ledger against the capsule and its own chain."""
    selected = ledger.get("selected")
    if not isinstance(selected, dict):
        return False
    ticket, _ = extract_hex_field(capsule_doc, TICKET_PATTERNS, 16)
    root, _ = extract_hex_field(capsule_doc, ROOT_PATTERNS, 32)
    length = extract_int_field(capsule_doc, LENGTH_PATTERNS)
    if ticket and selected.get("ticket") != ticket.hex():
        return False
    if length is not None and selected.get("length") != int(length):
        return False
    nodes = selected.get("nodes") or []
    if not nodes:
        return False
    if root and nodes[-1].get("node") != root.hex():
        return False
    if nodes[0].get("prev") != "00" * 32:
        return False
    for i in range(1, len(nodes)):
        if nodes[i].get("prev") != nodes[i - 1].get("node"):
            return False
    return True


def finalize_ledger(ledger: dict, capsule_doc: dict, log: Log) -> dict:
    """Last resort: rebuild the selected ledger by walking prev links from root."""
    if ledger_matches_capsule(ledger, capsule_doc):
        return ledger
    if quic_rescue is None:
        return ledger
    requirements = ledger_requirements(capsule_doc)
    chain = quic_rescue.reconstruct_ledger_chain(
        ledger.get("responses") or [], requirements
    )
    if chain is None:
        return ledger
    log(
        "[6] rebuilt ledger from prev-links: nodes=%d concat_sha256=%s"
        % (chain["length"], chain["concatenated_sha256"])
    )
    rebuilt = dict(ledger)
    rebuilt["selected"] = chain
    rebuilt["ledgers"] = [chain] + [
        cand
        for cand in (ledger.get("ledgers") or [])
        if isinstance(cand, dict) and cand.get("ticket") != chain["ticket"]
    ]
    return rebuilt


def run_quic_recovery(paths: Paths, capsule_path: Path, log: Log, timeout: int) -> Optional[dict]:
    """In-process solver run with PN-jump / key-update / fork recovery."""
    if quic_rescue is None:
        log(f"[6] recovery layer unavailable: {_RESCUE_IMPORT_ERROR}")
        return None
    log("[6] running solve.py with PN-jump + key-update + fork recovery")
    stats = quic_rescue.run_rescue(
        capsule_path,
        paths.ledger,
        log,
        max_seconds=max(60, timeout),
    )
    if not paths.ledger.exists():
        return None
    try:
        ledger = json.loads(paths.ledger.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"[6] cannot parse recovered ledger: {exc}")
        return None
    try:
        (paths.chain_dir / "ledger.recovered.json").write_text(
            json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8"
        )
    except Exception:
        pass
    log(
        "[6] recovery stats: decrypted=%s/%s jumps=%s key_updates=%s passes=%s"
        % (
            stats.get("decrypted"),
            stats.get("decrypted", 0) + stats.get("pending", 0),
            stats.get("jumps"),
            stats.get("key_updates"),
            stats.get("passes"),
        )
    )
    return ledger


def ledger_candidates(ledger: dict, log: Log) -> list[dict]:
    """Selected ledger first, then every other structurally valid chain."""
    out: list[dict] = []
    selected = ledger.get("selected")
    all_ledgers = ledger.get("ledgers") or []
    if isinstance(selected, dict):
        out.append(selected)
    for cand in all_ledgers:
        if not isinstance(cand, dict) or cand is selected:
            continue
        if cand not in out and cand.get("chain_ok"):
            out.append(cand)
    for cand in out:
        if not cand.get("bodies_hex"):
            bodies = [
                node.get("body_hex") for node in (cand.get("nodes") or [])
            ]
            if all(isinstance(b, str) for b in bodies):
                cand["bodies_hex"] = bodies
    log(
        f"[6] ledger candidates: {len(out)} "
        f"(selected={'yes' if isinstance(selected, dict) else 'no'}, "
        f"total={len(all_ledgers)})"
    )
    return out


def finish_delivery(
    capsule_doc: dict,
    ledger: dict,
    export_key: bytes,
    paths: Paths,
    log: Log,
    delivery_blob: Optional[bytes] = None,
) -> dict:
    """Pick the matching ledger, derive the delivery key and decrypt delivery.bin."""
    delivery_path = RR3 / "delivery.bin"
    blob = delivery_blob if delivery_blob is not None else (
        delivery_path.read_bytes() if delivery_path.exists() else None
    )
    if blob is None:
        raise ChainError(f"delivery blob not found: {delivery_path}")
    if len(blob) < 12 + 16:
        raise ChainError(f"delivery blob is only {len(blob)} bytes")
    nonce, sealed = blob[:12], blob[12:]
    log(f"[7] delivery.bin: {len(blob)} bytes (nonce {nonce.hex()}, sealed {len(sealed)})")

    cap_ticket, cap_ticket_path = extract_hex_field(capsule_doc, TICKET_PATTERNS, 16)
    cap_root, cap_root_path = extract_hex_field(capsule_doc, ROOT_PATTERNS, 32)
    cap_length = extract_int_field(capsule_doc, LENGTH_PATTERNS)
    log(
        f"    capsule ticket={cap_ticket.hex() if cap_ticket else None}"
        f" (from {cap_ticket_path})"
    )
    log(f"    capsule root={cap_root.hex() if cap_root else None} (from {cap_root_path})")
    log(f"    capsule length={cap_length}")

    candidates = ledger_candidates(ledger, log)
    if not candidates:
        raise ChainError(
            "QUIC ledger.json has no selected or structurally valid ledger; "
            "cannot build the delivery key"
        )

    attempts: list[dict] = []
    for index, cand in enumerate(candidates):
        try:
            bodies = _ledger_bodies(cand)
        except ValueError as exc:
            log(f"    x candidate {index}: bad body hex ({exc})")
            continue
        concat = b"".join(bodies)
        digest = hashlib.sha256(concat).hexdigest()
        recorded = cand.get("concatenated_sha256")
        ledger_ticket_hex = cand.get("ticket")
        try:
            ledger_ticket = bytes.fromhex(ledger_ticket_hex) if ledger_ticket_hex else None
        except ValueError:
            ledger_ticket = None
        terminal = (cand.get("nodes") or [{}])[-1].get("node") if cand.get("nodes") else cand.get("root")
        ledger_root: Optional[bytes] = None
        if isinstance(terminal, str):
            try:
                ledger_root = bytes.fromhex(terminal)
            except ValueError:
                ledger_root = None
        length = cand.get("length", len(bodies))
        log(
            f"[7] candidate {index}: ticket={ledger_ticket_hex} length={length} "
            f"bodies={len(bodies)} concat_sha256={digest[:16]}..."
        )
        if recorded and recorded != digest:
            log(f"    ! recorded concatenated_sha256 {recorded[:16]}... != recomputed")
        if cap_length is not None and length != cap_length:
            log(f"    ! capsule length {cap_length} != ledger length {length}")
        if cap_ticket is not None and ledger_ticket is not None and cap_ticket != ledger_ticket:
            log("    ! capsule ticket != ledger ticket")

        dkey = rrlib.delivery_key(export_key, concat)
        aad_pairs: list[tuple[str, bytes]] = []
        if cap_ticket and cap_root:
            aad_pairs.append(("capsule.ticket||capsule.root", cap_ticket + cap_root))
        if ledger_ticket and ledger_root:
            aad_pairs.append(("ledger.ticket||ledger.root", ledger_ticket + ledger_root))
        # Deduplicate, keep order.
        seen_aad: set[bytes] = set()
        unique_pairs = []
        for label, aad in aad_pairs:
            if aad in seen_aad:
                continue
            seen_aad.add(aad)
            unique_pairs.append((label, aad))
        if not unique_pairs:
            log("    ! no usable ticket/root pair for the delivery AAD")
            continue

        for aad_label, aad in unique_pairs:
            try:
                plaintext = rrlib.delivery_decrypt(dkey, nonce, sealed, aad)
            except rrlib.AuthenticationError:
                attempts.append(
                    {
                        "candidate": index,
                        "ticket": ledger_ticket_hex,
                        "length": length,
                        "aad": aad_label,
                        "result": "GCM tag mismatch",
                    }
                )
                log(f"    x delivery aad={aad_label} -> GCM tag mismatch")
                continue
            except Exception as exc:  # noqa: BLE001
                attempts.append(
                    {
                        "candidate": index,
                        "ticket": ledger_ticket_hex,
                        "length": length,
                        "aad": aad_label,
                        "result": f"{type(exc).__name__}: {exc}",
                    }
                )
                log(f"    x delivery aad={aad_label} -> {type(exc).__name__}: {exc}")
                continue

            text = plaintext.decode("utf-8", "replace").rstrip("\x00")
            log(f"[7] SUCCESS delivery decrypted with candidate {index} "
                f"(aad={aad_label}, {len(plaintext)} bytes)")
            log(f"    final receipt: {text}")
            if not FLAG_RE.match(text.strip()):
                log("    ! WARNING: plaintext does not match ^isfcr{...}$")
            payload = plaintext.rstrip(b"\x00")
            if not payload.endswith(b"\n"):
                payload += b"\n"
            paths.final_receipt.write_bytes(payload)
            log(f"[8] final receipt saved to {paths.final_receipt}")
            return {
                "plaintext": plaintext,
                "text": text,
                "candidate": index,
                "aad": aad_label,
                "aad_hex": aad.hex(),
                "ledger_ticket": ledger_ticket_hex,
                "ledger_root": ledger_root.hex() if ledger_root else None,
                "length": length,
                "concat_sha256": digest,
                "delivery_key": dkey.hex(),
                "attempts": attempts,
            }

    raise ChainError(
        "delivery GCM authentication failed for every candidate ledger:\n"
        + "\n".join(
            f"  - candidate {a['candidate']} ticket={a['ticket']} "
            f"aad={a['aad']} ({a['result']})"
            for a in attempts
        )
    )


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    stream_path: Path,
    *,
    paths: Optional[Paths] = None,
    findings_path: Path = RR3 / "link" / "findings.json",
    jobs_tx: Optional[int] = 4,
    jobs: Optional[Sequence[JobCandidate]] = None,
    cookies: Optional[Sequence[bytes]] = None,
    view_bytes: Optional[bytes] = None,
    endians: Sequence[str] = ("le", "be"),
    expect_sha: Optional[str] = EXPECTED_SHA256,
    expect_bytes: Optional[int] = EXPECTED_BYTES,
    export_cap: int = 128 * 1024 * 1024,
    hash_cap: int = 16 * 1024 * 1024 * 1024,
    quic_timeout: int = 900,
    skip_quic: bool = False,
    injected_ledger: Optional[dict] = None,
    delivery_blob: Optional[bytes] = None,
    log: Optional[Log] = None,
) -> dict:
    own_log = log is None
    if log is None:
        paths = paths or Paths()
        log = Log(paths.log)
    paths = paths or Paths()
    if paths.chain_dir != HERE and paths.capsule_rr3 == RR3 / "capsule.json":
        paths.capsule_rr3 = paths.chain_dir / "capsule.json"
    result: dict[str, Any] = {
        "stream": str(Path(stream_path).resolve()),
        "status": "failed",
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    t0 = time.time()
    try:
        log("=" * 78)
        log(f"Read Receipt RR3-063 chain driver  {result['started']}")
        log(f"stream: {Path(stream_path).resolve()}")
        log(f"artifacts: {paths.chain_dir}")

        # ---- step 1: hash verification
        stream_bytes = Path(stream_path).read_bytes()
        digest = verify_stream(stream_bytes, expect_sha, expect_bytes)
        log(f"[1] stream OK: {len(stream_bytes)} bytes sha256={digest}")
        result["stream_sha256"] = digest
        result["stream_bytes"] = len(stream_bytes)

        # ---- step 2: rr-package-1 -> pack/4 container
        container_bytes = unpack_stream(stream_bytes, log)
        paths.container.write_bytes(container_bytes)
        log(f"    container saved to {paths.container} "
            f"(sha256={hashlib.sha256(container_bytes).hexdigest()})")
        result["container_bytes"] = len(container_bytes)
        result["container_sha256"] = hashlib.sha256(container_bytes).hexdigest()

        # ---- step 3: accepted job
        accepted = load_accepted(Path(findings_path))
        log(f"[3] accepted job: ticket={accepted.ticket.hex()} "
            f"cookie={accepted.cookie.hex()} nonce={accepted.nonce.hex()} "
            f"sealed={len(accepted.sealed)} bytes view={accepted.view.hex()}")
        job_list = list(jobs) if jobs is not None else load_jobs_candidates(accepted, jobs_tx)
        log(f"    job candidates: {len(job_list)}")
        for job in job_list:
            log(f"      - {job.label} ticket={job.ticket.hex()} "
                f"sealed_sha256={hashlib.sha256(job.sealed).hexdigest()[:16]}...")
        cookie_list = list(cookies) if cookies is not None else [
            accepted.cookie,
            *accepted.cookie_alternates,
        ]
        log(f"    cookie candidates: {', '.join(c.hex() for c in cookie_list)}")
        view = view_bytes if view_bytes is not None else accepted.view
        log(f"    view: {len(view)} bytes {view.hex()}")

        # ---- steps 4-5: export -> key -> receipt GCM
        receipt = receipt_attempts(
            container_bytes,
            job_list,
            cookie_list,
            endians,
            Accepted(
                ticket=accepted.ticket,
                cookie=accepted.cookie,
                nonce=accepted.nonce,
                sealed=accepted.sealed,
                view=view,
                cookie_alternates=accepted.cookie_alternates,
                raw=accepted.raw,
            ),
            paths,
            export_cap=export_cap,
            hash_cap=hash_cap,
            log=log,
        )
        result.update(
            {
                "export_sha256": hashlib.sha256(receipt["export"]).hexdigest(),
                "export_bytes": len(receipt["export"]),
                "export_endianness": receipt["meta"]["endian"],
                "view_length": receipt["meta"]["view_length"],
                "bound_node": receipt["meta"]["bound_node"],
                "receipt_key": receipt["key"].hex(),
                "receipt_attempts": receipt["attempts"],
                "receipt_choice": receipt["chosen"],
            }
        )
        if paths.export.exists():
            result["export_path"] = str(paths.export)

        plaintext = receipt["plaintext"]
        log(f"[5] receipt plaintext: {len(plaintext)} bytes, "
            f"prefix={plaintext[:16]!r}")

        # ---- step 6: capsule / delivery
        if plaintext.startswith(RRTC5_PREFIX):
            capsule_body, capsule_doc = parse_capsule(plaintext, paths, log)
            result["capsule_bytes"] = len(capsule_body)
            result["capsule_keys"] = list(capsule_doc.keys())
            result["capsule"] = capsule_doc
            if skip_quic and injected_ledger is None:
                log(
                    "[6] QUIC solver skipped (--skip-quic); capsule written, "
                    "delivery not attempted"
                )
                result["status"] = "capsule_only"
                result["elapsed_seconds"] = round(time.time() - t0, 2)
                if paths.result is not None:
                    paths.result.write_text(
                        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
                    )
                return result
            if skip_quic:
                ledger_doc = injected_ledger
                log("[6] QUIC solver skipped (injected ledger)")
            else:
                stock = None
                try:
                    stock = run_quic_solver(paths, paths.capsule_rr3, log, quic_timeout)
                except ChainError as exc:
                    log(f"[6] stock solver did not produce a usable run: {exc}")
                if stock is not None and ledger_matches_capsule(stock, capsule_doc):
                    ledger_doc = stock
                    log("[6] stock solver selected a capsule-consistent ledger")
                else:
                    if stock is not None:
                        log(
                            "[6] stock ledger does not match the capsule "
                            "(packet-number jumps / key updates / forked ledgers)"
                        )
                    recovered = run_quic_recovery(
                        paths, paths.capsule_rr3, log, quic_timeout
                    )
                    ledger_doc = recovered if recovered is not None else stock
                    if ledger_doc is None:
                        raise ChainError("QUIC decode produced no ledger at all")
                    ledger_doc = finalize_ledger(ledger_doc, capsule_doc, log)
                    if not ledger_matches_capsule(ledger_doc, capsule_doc):
                        log(
                            "[6] WARNING: recovered ledger still does not match the "
                            "capsule ticket/length/root"
                        )
            delivery = finish_delivery(
                capsule_doc, ledger_doc, receipt["key"], paths, log,
                delivery_blob=delivery_blob,
            )
            result.update(
                {
                    "final_receipt": delivery["text"],
                    "flag": delivery["text"].strip() if FLAG_RE.match(delivery["text"].strip()) else None,
                    "delivery": {k: v for k, v in delivery.items() if k != "plaintext"},
                }
            )
            result["status"] = "success"
        else:
            # Some builds inline the final receipt instead of a transit capsule.
            text = plaintext.decode("utf-8", "replace").rstrip("\x00")
            payload = plaintext.rstrip(b"\x00")
            if not payload.endswith(b"\n"):
                payload += b"\n"
            paths.final_receipt.write_bytes(payload)
            log(f"[6] receipt is not an RRTC5 capsule; treating as final receipt")
            log(f"    {text}")
            if not FLAG_RE.match(text.strip()):
                log("    ! WARNING: plaintext does not match ^isfcr{...}$")
            result.update(
                {
                    "status": "success",
                    "final_receipt": text,
                    "flag": text.strip() if FLAG_RE.match(text.strip()) else None,
                }
            )

        result["elapsed_seconds"] = round(time.time() - t0, 2)
        if paths.result is not None:
            paths.result.write_text(
                json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
            )
        log(f"chain complete in {result['elapsed_seconds']}s")
        if result.get("flag"):
            log("")
            log(f"FLAG: {result['flag']}")
        return result

    except ChainError as exc:
        result["error"] = str(exc)
        result["elapsed_seconds"] = round(time.time() - t0, 2)
        log(f"CHAIN FAILED: {exc}")
        if paths.result is not None:
            try:
                paths.result.write_text(
                    json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
                )
            except Exception:
                pass
        raise
    finally:
        if own_log:
            log.close()


# ---------------------------------------------------------------------------
# self-test (no real stream needed)
# ---------------------------------------------------------------------------


def _build_synthetic_container() -> tuple[bytes, bytes, bytes, bytes]:
    """Container + LE view + BE view + independently expected R4SP export."""
    from pack4 import (
        Atom,
        Namespace,
        Node,
        OpBind,
        OpClone,
        OpHole,
        OpLiteral,
        OpZero,
        Reference,
        build_container,
        build_view,
        make_handle,
    )

    ns_id = bytes.fromhex("11" * 16)
    atom_id = bytes.fromhex("aa" * 16)
    node_id = bytes.fromhex("bb" * 16)
    src_node_id = bytes.fromhex("cc" * 16)
    src_ns = bytes.fromhex("22" * 16)
    view_handle = make_handle(7, 1)
    src_handle = make_handle(9, 2)
    zero_ref = Reference(bytes(16), bytes(6))

    atoms = [
        Atom(atom_id, b"HELLO"),
        Atom(bytes.fromhex("dd" * 16), b"WXYZ"),
    ]
    namespaces = [
        Namespace(id=ns_id, base=bytes(16), ops=(OpBind(view_handle, node_id),)),
        Namespace(id=src_ns, base=bytes(16), ops=(OpBind(src_handle, src_node_id),)),
    ]
    src_node = Node(
        id=src_node_id,
        logical_size=4,
        base=zero_ref,
        ops=(OpLiteral(0, 4, bytes.fromhex("dd" * 16), 0),),
    )
    node = Node(
        id=node_id,
        logical_size=16,
        base=zero_ref,
        ops=(
            OpLiteral(0, 5, atom_id, 0),          # 0..5  "HELLO"
            OpHole(5, 3),                        # 5..8  hole
            OpZero(8, 4),                        # 8..12 allocated zero
            OpClone(12, 4, Reference(src_ns, src_handle), 0),  # 12..16 "WXYZ"
        ),
    )
    container = build_container(atoms, namespaces, [node, src_node])
    view_le = build_view(ns_id, view_handle, 0, 16, endian="<")
    view_be = build_view(ns_id, view_handle, 0, 16, endian=">")

    expected = (
        b"R4SP"
        + struct.pack(">Q", 16)
        + struct.pack(">BQQ", 1, 0, 5)
        + b"HELLO"
        + struct.pack(">BQQ", 0, 5, 3)
        + struct.pack(">BQQ", 1, 8, 8)
        + b"\x00" * 4
        + b"WXYZ"
    )
    return container, view_le, view_be, expected


def _encrypt_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag


def _make_fake_ledger(ticket: bytes, bodies: Sequence[bytes]) -> dict:
    prev = bytes(32)
    nodes = []
    for seq, body in enumerate(bodies):
        node_hash = rrlib.node_hash(ticket, prev, seq, body)
        nodes.append(
            {
                "seq": seq,
                "prev": prev.hex(),
                "node": node_hash.hex(),
                "body_hex": body.hex(),
                "space": "c2s",
                "stream_id": seq * 4,
                "time": seq,
            }
        )
        prev = node_hash
    concat = b"".join(bodies)
    return {
        "selected": {
            "ticket": ticket.hex(),
            "length": len(bodies),
            "seqs": list(range(len(bodies))),
            "nodes": nodes,
            "bodies_hex": [b.hex() for b in bodies],
            "root": nodes[-1]["node"],
            "node_count": len(bodies),
            "concatenated_hex": concat.hex(),
            "concatenated_sha256": hashlib.sha256(concat).hexdigest(),
            "chain_ok": True,
            "chain_links_ok": True,
            "selected": True,
            "matches_capsule": True,
        },
        "ledgers": [],
    }


def selftest() -> int:
    import shutil
    import zlib

    tmp = HERE / "_selftest"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    paths = Paths.under(tmp)
    log = Log(paths.log)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))

    log("=" * 78)
    log("Read Receipt RR3-063 chain --selftest")
    log("")

    # ---- 1. synthetic pack/4 container and independent expected export
    log("[A] pack/4 container -> canonical export")
    container_bytes, view_le, view_be, expected = _build_synthetic_container()
    try:
        got_le = pack4.resolve_view(container_bytes, view_le, view_endian="<")
        check("resolve_view(LE) matches hand-built R4SP export", got_le == expected,
              f"{len(got_le)} bytes")
        check("export header is R4SP + BE length 16",
              got_le[:12] == b"R4SP" + struct.pack(">Q", 16))
        got_be = pack4.resolve_view(container_bytes, view_be, view_endian=">")
        check("BE view with BE parsing matches too", got_be == expected)
        wrong = pack4.resolve_view(container_bytes, view_be, view_endian="<")
        check("LE reading of a BE view differs (endianness fallback is meaningful)",
              wrong != expected, f"{len(wrong)} bytes")
        key_le = rrlib.export_key(got_le)
        key_manual = hashlib.sha256(b"RR export 4\x00" + expected).digest()
        check("export_key equals independent SHA256(prefix+export)", key_le == key_manual)
    except Exception as exc:
        check("synthetic container export", False, f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())

    # ---- 2. sealed stream round-trip
    log("")
    log("[B] rr-package-1 seal/unpack round-trip")
    package_key = bytes.fromhex("5a" * 32)
    stream = rrlib.rr_package_seal(zlib.compress(container_bytes, 9), key=package_key)
    stream_path = tmp / "fake_stream.bin"
    stream_path.write_bytes(stream)
    try:
        digest = verify_stream(stream, None, None)
        check("verify_stream accepts the synthetic package", len(digest) == 64)
        opened = rrlib.rr_package_unpack(stream)
        check("rr_package_unpack returns the container bytes", opened == container_bytes)
    except Exception as exc:
        check("package round-trip", False, f"{type(exc).__name__}: {exc}")

    # ---- 3. full synthetic receipt (LE view, cookie tried second)
    log("")
    log("[C] receipt GCM path: LE view, correct cookie is the 2nd candidate")
    ticket = bytes.fromhex("0123456789abcdef0123456789abcdef")
    cookie_wrong = bytes.fromhex("ee" * 32)
    cookie_right = bytes.fromhex("20" * 32)
    fake_bodies = [b"body-zero", b"body-one", b"body-two"]
    fake_ledger = _make_fake_ledger(ticket, fake_bodies)
    fake_root = bytes.fromhex(fake_ledger["selected"]["root"])
    capsule_doc = {
        "application": "rr-ledger/1",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "secrets": {"client": "00" * 32, "server": "11" * 32},
        "next_pn": {"client": 1, "server": 1},
        "cid_len": 8,
        "ticket": ticket.hex(),
        "root": fake_root.hex(),
        "length": len(fake_bodies),
    }
    capsule_plaintext = RRTC5_PREFIX + json.dumps(capsule_doc, sort_keys=True).encode()
    nonce = bytes.fromhex("0102030405060708090a0b0c")
    receipt_sealed = _encrypt_gcm(
        rrlib.export_key(expected), nonce, capsule_plaintext, ticket + cookie_right
    )
    job = JobCandidate(
        label="selftest job", ticket=ticket, nonce=nonce, sealed=receipt_sealed, view=view_le
    )
    # Matching synthetic delivery.bin: same ticket/root, same export key.
    delivery_nonce = bytes.fromhex("c0ffee000102030405060708")
    delivery_blob = delivery_nonce + _encrypt_gcm(
        rrlib.delivery_key(rrlib.export_key(expected), b"".join(fake_bodies)),
        delivery_nonce,
        b"isfcr{SELFTEST-FAKE-DO-NOT-REPORT}",
        ticket + fake_root,
    )
    try:
        result = run_pipeline(
            stream_path,
            paths=paths,
            findings_path=RR3 / "link" / "findings.json",
            jobs=[job],
            cookies=[cookie_wrong, cookie_right],
            view_bytes=view_le,
            endians=("le", "be"),
            expect_sha=None,
            expect_bytes=None,
            skip_quic=True,
            injected_ledger=fake_ledger,
            delivery_blob=delivery_blob,
            log=log,
        )
        check("pipeline status success", result.get("status") == "success")
        check("receipt endianness is le", result.get("export_endianness") == "le")
        check("correct cookie chosen (2nd candidate)",
              result.get("receipt_choice", {}).get("cookie") == cookie_right.hex())
        check("export.r4sp matches the expected canonical export",
              paths.export.read_bytes() == expected)
        check("capsule.json written verbatim",
              paths.capsule_chain.read_bytes()
              == json.dumps(capsule_doc, sort_keys=True).encode())
        check("first cookie attempt is logged as a GCM failure",
              any(a.get("cookie") == cookie_wrong.hex()
                  and "mismatch" in str(a.get("result"))
                  for a in result.get("receipt_attempts", [])))
        check("fake final receipt recovered",
              result.get("final_receipt") == "isfcr{SELFTEST-FAKE-DO-NOT-REPORT}")
        check("delivery key/plaintext handled", bool(result.get("delivery")))
    except Exception as exc:
        check("synthetic receipt pipeline", False, f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())

    # ---- 4. BE-encoded view: LE must fail, BE must succeed
    log("")
    log("[D] receipt GCM path: BE-encoded view, LE reading must fail first")
    nonce_be = bytes.fromhex("0a0b0c0d0e0f101112131415")
    sealed_be = _encrypt_gcm(
        rrlib.export_key(expected), nonce_be, capsule_plaintext, ticket + cookie_right
    )
    job_be = JobCandidate(
        label="selftest BE job",
        ticket=ticket,
        nonce=nonce_be,
        sealed=sealed_be,
        view=view_be,
    )
    be_paths = Paths.under(tmp / "be")
    try:
        result_be = run_pipeline(
            stream_path,
            paths=be_paths,
            findings_path=RR3 / "link" / "findings.json",
            jobs=[job_be],
            cookies=[cookie_right],
            view_bytes=view_be,
            endians=("le", "be"),
            expect_sha=None,
            expect_bytes=None,
            skip_quic=True,
            injected_ledger=fake_ledger,
            delivery_blob=delivery_blob,
            log=log,
        )
        check("BE pipeline status success", result_be.get("status") == "success")
        check("endianness fallback selected be",
              result_be.get("export_endianness") == "be")
        check("BE attempt list contains the failed LE try",
              any(a.get("endian") == "le" for a in result_be.get("receipt_attempts", [])))
    except Exception as exc:
        check("BE fallback pipeline", False, f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())

    # ---- 5. clean failures
    log("")
    log("[E] clean failure modes")
    try:
        verify_stream(stream, EXPECTED_SHA256, EXPECTED_BYTES)
        check("bad sha256 rejected", False, "no exception")
    except ChainError as exc:
        check("bad sha256 rejected", "sha256 mismatch" in str(exc))

    try:
        verify_stream(b"abc", None, None) and unpack_stream(b"abc", log)
        check("short package rejected", False, "no exception")
    except ChainError as exc:
        check("short package rejected", "unpack failed" in str(exc), str(exc)[:60])

    corrupted = bytearray(stream)
    corrupted[-1] ^= 0xFF  # corrupt the rr-package tag -> wrong CTR key
    try:
        unpack_stream(bytes(corrupted), log)
        check("corrupted rr-package rejected", False, "no exception")
    except ChainError as exc:
        check("corrupted rr-package rejected", "unpack failed" in str(exc))

    try:
        bad_sealed = bytearray(job.sealed)
        bad_sealed[-1] ^= 0xFF  # corrupt the GCM tag only
        bad_job = JobCandidate(
            label="corrupted sealed blob",
            ticket=ticket,
            nonce=nonce,
            sealed=bytes(bad_sealed),
            view=view_le,
        )
        run_pipeline(
            stream_path,
            paths=Paths.under(tmp / "bads"),
            jobs=[bad_job],
            cookies=[cookie_right],
            view_bytes=view_le,
            endians=("le",),
            expect_sha=None,
            expect_bytes=None,
            skip_quic=True,
            injected_ledger=fake_ledger,
            delivery_blob=delivery_blob,
            log=log,
        )
        check("wrong sealed blob rejected with a clean error", False, "no exception")
    except ChainError as exc:
        check("wrong sealed blob rejected with a clean error",
              "receipt GCM authentication failed" in str(exc))

    # ---- 6. delivery plumbing with a wrong AAD must fail, right AAD must pass
    log("")
    log("[F] delivery AAD handling")
    exports_ok = expected
    dkey = rrlib.delivery_key(rrlib.export_key(exports_ok), b"".join(fake_bodies))
    final_pt = b"isfcr{SELFTEST-FAKE-DO-NOT-REPORT}"
    good_blob = (
        bytes.fromhex("aabbccddeeff001122334455")
        + _encrypt_gcm(dkey, bytes.fromhex("aabbccddeeff001122334455"),
                       final_pt, ticket + fake_root)
    )
    try:
        rrlib.delivery_decrypt(
            dkey, good_blob[:12], good_blob[12:], ticket + bytes(32)
        )
        check("delivery wrong AAD rejected", False, "no exception")
    except rrlib.AuthenticationError:
        check("delivery wrong AAD rejected", True)
    out = rrlib.delivery_decrypt(dkey, good_blob[:12], good_blob[12:], ticket + fake_root)
    check("delivery correct AAD decrypts", out == final_pt)
    try:
        finish_delivery(
            capsule_doc, fake_ledger, rrlib.export_key(exports_ok),
            Paths.under(tmp / "delivery"), log, delivery_blob=good_blob,
        )
        check("finish_delivery uses capsule ticket||root", True)
    except Exception as exc:
        check("finish_delivery uses capsule ticket||root", False,
              f"{type(exc).__name__}: {exc}")

    # ---- summary
    log("")
    passed = sum(1 for _, ok, _ in checks if ok)
    failed = [(n, d) for n, ok, d in checks if not ok]
    log(f"selftest: {passed}/{len(checks)} checks passed")
    if failed:
        for name, detail in failed:
            log(f"  FAILED: {name} ({detail})")
    log(f"artifacts under {tmp}")
    log.close()
    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Read Receipt RR3-063 post-selection chain driver",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("stream", nargs="?", default=str(RR3 / "stream.bin"),
                    help="path to the solved 61291-byte generation-1 stream")
    ap.add_argument("--findings", default=str(RR3 / "link" / "findings.json"),
                    help="link findings carrying the accepted job")
    ap.add_argument("--jobs-tx", type=int, default=4,
                    help="WAL snapshot with extra job fallbacks (0..9, -1 disables)")
    ap.add_argument("--cookie", action="append", default=None,
                    help="extra catalog cookie (hex), replaces the default list")
    ap.add_argument("--view-hex", default=None, help="override the 42-byte view")
    ap.add_argument("--ticket-hex", default=None, help="override the job ticket")
    ap.add_argument("--nonce-hex", default=None, help="override the job nonce")
    ap.add_argument("--sealed-hex", default=None, help="override the job sealed blob")
    ap.add_argument("--view-endian", choices=("auto", "le", "be"), default="auto",
                    help="view u64 byte order; auto tries little-endian first")
    ap.add_argument("--export-cap", type=int, default=128 * 1024 * 1024,
                    help="materialize exports up to this many allocated bytes")
    ap.add_argument("--hash-cap", type=int, default=16 * 1024 * 1024 * 1024,
                    help="refuse to hash exports above this many allocated bytes")
    ap.add_argument("--quic-timeout", type=int, default=900,
                    help="seconds allowed for rr3/quic/solve.py")
    ap.add_argument("--skip-quic", action="store_true",
                    help="do not run the QUIC solver (debugging; delivery cannot finish)")
    ap.add_argument("--expect-sha", default=EXPECTED_SHA256,
                    help="required stream sha256 (empty string disables)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip stream sha256/length verification (debugging only)")
    ap.add_argument("--out-dir", default=str(HERE),
                    help="directory for chain artifacts")
    ap.add_argument("--capsule-out", default=str(RR3 / "capsule.json"),
                    help="where to write the transit capsule JSON")
    ap.add_argument("--no-log-file", action="store_true",
                    help="do not append to <out-dir>/run.log")
    ap.add_argument("--selftest", action="store_true",
                    help="run the synthetic end-to-end self-test and exit")
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    if args.selftest:
        return selftest()

    paths = Paths()
    paths.chain_dir = Path(args.out_dir)
    paths.chain_dir.mkdir(parents=True, exist_ok=True)
    paths.container = paths.chain_dir / "container.bin"
    paths.export = paths.chain_dir / "export.r4sp"
    paths.capsule_rr3 = Path(args.capsule_out)
    paths.capsule_chain = paths.chain_dir / "capsule.json"
    paths.final_receipt = paths.chain_dir / "final_receipt.txt"
    paths.result = paths.chain_dir / "result.json"
    paths.log = None if args.no_log_file else paths.chain_dir / "run.log"
    paths.ledger = QUIC_DIR / "ledger.json"

    stream_path = Path(args.stream)
    if not stream_path.exists():
        print(f"ERROR: stream not found: {stream_path}", file=sys.stderr)
        print(
            "The physical/catalog selection step has not produced the stream yet. "
            "Wait for rr3/stream.bin, or run --selftest to verify the pipeline.",
            file=sys.stderr,
        )
        return 2

    endians = {"auto": ("le", "be"), "le": ("le",), "be": ("be",)}[args.view_endian]
    log = Log(paths.log)

    # Optional job overrides (debugging / manual experiments).
    jobs = None
    view_bytes = None
    cookies = None
    try:
        if args.view_hex:
            view_bytes = bytes.fromhex(args.view_hex)
            if len(view_bytes) != 42:
                raise ChainError(f"--view-hex must be 42 bytes, got {len(view_bytes)}")
        if args.ticket_hex or args.nonce_hex or args.sealed_hex:
            if not (args.ticket_hex and args.nonce_hex and args.sealed_hex):
                raise ChainError(
                    "--ticket-hex, --nonce-hex and --sealed-hex must be given together"
                )
            job_view = view_bytes or bytes.fromhex(
                "523456573482f636c8791b967977d19d29e97e475b000000030000000000000000001e770a4686000000"
            )
            jobs = [
                JobCandidate(
                    label="command line",
                    ticket=bytes.fromhex(args.ticket_hex),
                    nonce=bytes.fromhex(args.nonce_hex),
                    sealed=bytes.fromhex(args.sealed_hex),
                    view=job_view,
                )
            ]
            if view_bytes is None:
                view_bytes = job_view
        if args.cookie:
            cookies = [bytes.fromhex(c) for c in args.cookie]
            for c in cookies:
                if len(c) != 32:
                    raise ChainError(f"--cookie must be 32 bytes, got {len(c)}")
        result = run_pipeline(
            stream_path,
            paths=paths,
            findings_path=Path(args.findings),
            jobs_tx=None if args.jobs_tx < 0 else args.jobs_tx,
            jobs=jobs,
            cookies=cookies,
            view_bytes=view_bytes,
            endians=endians,
            expect_sha=None if (args.no_verify or not args.expect_sha) else args.expect_sha,
            expect_bytes=EXPECTED_BYTES if (args.expect_sha and not args.no_verify) else None,
            export_cap=args.export_cap,
            hash_cap=args.hash_cap,
            quic_timeout=args.quic_timeout,
            skip_quic=args.skip_quic,
            log=log,
        )
    except ChainError as exc:
        print("", file=sys.stderr)
        print(f"CHAIN FAILED: {exc}", file=sys.stderr)
        if paths.log:
            print(f"log: {paths.log}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        log.close()

    if result.get("flag"):
        print("")
        print(f"FLAG: {result['flag']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
