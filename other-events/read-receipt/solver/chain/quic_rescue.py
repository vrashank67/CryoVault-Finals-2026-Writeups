#!/usr/bin/env python3
"""QUIC recovery layer for rr3/quic/solve.py (RR3-063).

The real capture needs two things the stock solver does not do:

1. **Packet-number jumps.**  Full PNs jump by ~2**24 twice per direction while
   the wire carries only 1-2 truncated bytes, so RFC 9000 A.3 reconstruction
   from the largest PN seen fails.  ACK frames, however, carry the peer's full
   packet numbers in cleartext, so the PNs can be recovered from the opposite
   direction's ACKs.  Because ACKs reference earlier packets, this needs
   repeated passes.  (This is what "Packet numbers need not be consecutive.
   All packet authentication uses full packet numbers." is about.)

2. **Key updates keep the header-protection key.**  At t~0.202295 the AEAD key
   advances by one RFC 9001 "quic ku" generation (phase bit flips) while the
   header-protection key stays at generation 0.  The stock solver always pairs
   HP and AEAD from the same generation, so every post-update packet fails.

`run_rescue` runs rr3/quic/solve.py in-process and replaces only
`Capture.decrypt` with the recovery loop below; HTTP/3, QPACK, ledger building
and output stay exactly as the solver wrote them.  Nothing in rr3/quic is
modified on disk.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
RR3 = HERE.parent
QUIC_DIR = RR3 / "quic"
if str(QUIC_DIR) not in sys.path:
    sys.path.insert(0, str(QUIC_DIR))

import solve  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _acked_pns(frames, cap: int = 4096) -> set[int]:
    """Full packet numbers acknowledged by the ACK frames of one packet."""
    out: set[int] = set()
    for frame in frames:
        if frame.get("type") != "ACK":
            continue
        largest = int(frame["largest"])
        first = int(frame.get("first_range") or 0)
        first = min(first, cap)
        out.update(range(largest - first, largest + 1))
        cursor = largest - first - 1
        for gap, rlen in frame.get("ranges") or []:
            high = cursor - int(gap) - 1
            low = high - int(rlen)
            if high < 0 or len(out) > cap:
                break
            out.update(range(max(0, low), high + 1))
            cursor = low - 1
    return out


def _pn_candidates(trunc: int, pn_len: int, refs, last_pn: Optional[int]) -> list[int]:
    mod = 1 << (8 * pn_len)
    out: list[int] = []

    def add(value: int) -> None:
        if value >= 0 and (value & (mod - 1)) == (trunc % mod) and value not in out:
            out.append(value)

    if last_pn is not None and last_pn >= 0:
        add(solve.reconstruct_pn(trunc, 8 * pn_len, last_pn))
        for step in range(1, 33):
            add(last_pn + step)
    for ref in sorted((r for r in refs if r is not None and r >= 0), reverse=True):
        base = ref - ((ref - trunc) % mod)
        add(base)
        for delta in (1, 2, 3, -1, -2):
            add(base + delta)
    add(trunc)
    return out[:96]


# ---------------------------------------------------------------------------
# recovery decoder (drop-in replacement for solve.Capture.decrypt)
# ---------------------------------------------------------------------------


def decrypt_capture(
    capture,
    keysets,
    cid_len: int,
    *,
    log=None,
    max_aead_gen: int = 12,
    max_hp_gen: int = 2,
    max_attempts: int = 40_000_000,
    max_seconds: float = 600.0,
) -> dict:
    """Decrypt every datagram, recovering jumped PNs from ACK frames.

    Fills the same Capture attributes as solve.Capture.decrypt so the rest of
    solve.py (grouping, HTTP/3, ledger selection) works unchanged.
    """
    say = log if log is not None else (lambda *_a, **_k: None)
    capture.cid_len = cid_len
    started = time.time()
    attempts = 0
    stats = {"passes": 0, "jumps": 0, "key_updates": 0, "hp_changes": 0}

    # ---- classify datagrams (direction, header) ---------------------------
    work = []
    for d in capture.datagrams:
        q = d.get("payload")
        if not q:
            continue
        sport, dport = d.get("sport"), d.get("dport")
        if dport == 443 and sport != 443:
            direction = "c2s"
        elif sport == 443 and dport != 443:
            direction = "s2c"
        else:
            direction = "c2s" if (dport or 0) <= (sport or 0) else "s2c"
        d["direction"] = direction
        try:
            info = solve.parse_quic_packet(q, cid_len)
        except (solve.QuicError, ValueError) as exc:
            capture.quic_failures.append(
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
        capture.dcid_stats[direction].add(info.get("dcid", b"").hex())
        if info.get("kind") != "short":
            capture.quic_failures.append(
                {
                    "time": float(d["t"]),
                    "direction": direction,
                    "reason": "non-short-header packet (%s)" % info.get("kind"),
                }
            )
            continue
        work.append({"d": d, "q": q, "info": info, "direction": direction})

    # ---- per-direction state ---------------------------------------------
    state = {
        direction: {
            "hp_gen": 0,
            "aead_gen": 0,
            "last_pn": None,
            "refs": set(),
            "decrypted": 0,
        }
        for direction in ("c2s", "s2c")
    }
    # Seed with the capsule's expected next packet numbers.
    for ks in keysets:
        for direction in ("c2s", "s2c"):
            hint = ks.keys[direction].capsule_next
            if hint is not None:
                state[direction]["refs"].add(int(hint))

    done: dict[int, dict] = {}
    pending = list(range(len(work)))

    def try_packet(item) -> Optional[dict]:
        nonlocal attempts
        q = item["q"]
        info = item["info"]
        direction = item["direction"]
        st = state[direction]
        for ks in keysets:
            dk = ks.keys[direction]
            # header protection: normally generation 0, but allow a real update
            hp_order = [st["hp_gen"]] + [
                g for g in range(0, max_hp_gen + 1) if g != st["hp_gen"]
            ]
            for hp_gen in hp_order:
                try:
                    gen_hp = dk.gen(hp_gen)
                    mask = solve.header_protection_mask(
                        solve.CIPHER_SUITES[dk.suite]["aead"], gen_hp.hp, info["sample"]
                    )
                except solve.QuicError:
                    continue
                first = q[0] ^ (mask[0] & 0x1F)
                if first & 0x18:  # reserved bits must be zero
                    continue
                pn_len = (first & 0x03) + 1
                if info["pn_offset"] + pn_len > info["end"]:
                    continue
                pn_bytes = bytes(
                    q[info["pn_offset"] + i] ^ mask[1 + i] for i in range(pn_len)
                )
                trunc = int.from_bytes(pn_bytes, "big")
                ciphertext = bytes(q[info["pn_offset"] + pn_len : info["end"]])
                if len(ciphertext) < 14:
                    continue
                aad = bytes([first]) + bytes(q[1 : info["pn_offset"]]) + pn_bytes
                phase = (first >> 2) & 1

                candidates = _pn_candidates(trunc, pn_len, st["refs"], st["last_pn"])
                # AEAD generations: current one first, then same-parity gens
                # (a QUIC key update flips the phase bit), then the rest.
                gen_order = [st["aead_gen"]]
                gen_order += [
                    g
                    for g in range(0, max_aead_gen + 1)
                    if g != st["aead_gen"] and (g & 1) == phase
                ]
                gen_order += [
                    g
                    for g in range(0, max_aead_gen + 1)
                    if (g & 1) != phase
                ]
                seen_gen: set[int] = set()
                for aead_gen in gen_order:
                    if aead_gen in seen_gen:
                        continue
                    seen_gen.add(aead_gen)
                    try:
                        gen = dk.gen(aead_gen)
                    except solve.QuicError:
                        continue
                    for pn in candidates:
                        if attempts >= max_attempts or (time.time() - started) > max_seconds:
                            raise TimeoutError("PN recovery budget exhausted")
                        attempts += 1
                        nonce = solve.xor_bytes(gen.iv, pn.to_bytes(12, "big"))
                        try:
                            plaintext = solve.aead_decrypt(
                                solve.CIPHER_SUITES[dk.suite]["aead"],
                                gen.key,
                                nonce,
                                ciphertext,
                                aad,
                            )
                        except solve.QuicError:
                            continue
                        # success
                        if hp_gen != st["hp_gen"]:
                            stats["hp_changes"] += 1
                            say(f"    [quic] HP generation -> {hp_gen}")
                            st["hp_gen"] = hp_gen
                        if aead_gen != st["aead_gen"]:
                            stats["key_updates"] += 1
                            say(f"    [quic] AEAD key generation -> {aead_gen}")
                            st["aead_gen"] = aead_gen
                        if st["last_pn"] is not None and pn > st["last_pn"] + 64:
                            stats["jumps"] += 1
                            say(
                                f"    [quic] PN jump {st['last_pn']} -> {pn} "
                                f"(+{pn - st['last_pn']})"
                            )
                        st["last_pn"] = pn if st["last_pn"] is None else max(st["last_pn"], pn)
                        st["refs"].add(pn)
                        st["decrypted"] += 1
                        return {
                            "keyset": ks,
                            "dirkeys": dk,
                            "pn": pn,
                            "pn_len": pn_len,
                            "gen": aead_gen,
                            "hp_gen": hp_gen,
                            "key_phase": phase,
                            "first": first,
                            "plaintext": plaintext,
                            "ks": ks,
                        }
        return None

    # ---- multi-pass loop --------------------------------------------------
    while pending:
        stats["passes"] += 1
        progress = 0
        linger = []
        for idx in pending:
            item = work[idx]
            try:
                hit = try_packet(item)
            except TimeoutError as exc:
                say(f"    [quic] {exc}; keeping {len(done)} decrypted packets")
                pending = linger + pending[pending.index(idx) + 1 :]
                break
            if hit is None:
                linger.append(idx)
                continue
            progress += 1
            done[idx] = hit
            d = item["d"]
            ks = hit["ks"]
            dk = hit["dirkeys"]
            dk.note_success(info_dcid(item["info"]), hit["pn"], hit["gen"])
            frames = solve.parse_frames(hit["plaintext"])
            secret_tag = hashlib.sha256(
                dk.secret + b"\x00" + ks.suite.encode("ascii")
            ).hexdigest()[:12]
            rec = {
                "index": len(capture.packet_records),
                "time": d["t"],
                "iface": d["iface"],
                "direction": item["direction"],
                "keyset": ks.index,
                "secret_tag": secret_tag,
                "dcid": info_dcid(item["info"]),
                "pn": hit["pn"],
                "pn_len": hit["pn_len"],
                "key_phase": hit["key_phase"],
                "gen": hit["gen"],
                "hp_gen": hit["hp_gen"],
                "length": len(item["q"]),
                "frames": frames,
            }
            capture.packet_records.append(rec)
            for fr in frames:
                capture.frame_stats[fr["type"]] += 1
                if fr["type"] == "STREAM":
                    capture.stream_frames.append(
                        {
                            "time": d["t"],
                            "index": rec["index"],
                            "direction": item["direction"],
                            "keyset": ks.index,
                            "secret_tag": secret_tag,
                            "dcid": info_dcid(item["info"]),
                            "stream_id": fr["stream_id"],
                            "offset": fr["offset"],
                            "data": fr["data"],
                            "fin": fr["fin"],
                        }
                    )
                elif fr["type"] in ("CONNECTION_CLOSE", "CONNECTION_CLOSE_APP"):
                    capture.other_frames.append(
                        {
                            "packet": rec["index"],
                            "type": fr["type"],
                            "error_code": fr.get("error_code"),
                            "reason": fr.get("reason", b"").decode("latin-1", "replace"),
                        }
                    )
            # Harvest the peer's full packet numbers from this packet's ACKs.
            peer = "s2c" if item["direction"] == "c2s" else "c2s"
            acked = _acked_pns(frames)
            if acked:
                state[peer]["refs"].update(acked)
        pending = linger
        if not progress:
            break
        say(
            f"    [quic] pass {stats['passes']}: decrypted={len(done)} "
            f"pending={len(pending)} jumps={stats['jumps']} "
            f"key_updates={stats['key_updates']} hp_changes={stats['hp_changes']}"
        )

    for idx in pending:
        item = work[idx]
        item["d"]["decrypt_error"] = True
        capture.quic_failures.append(
            {
                "time": float(item["d"]["t"]),
                "direction": item["direction"],
                "dcid": info_dcid(item["info"]),
                "reason": "no key set decrypted the packet",
            }
        )
    stats.update(
        decrypted=len(done),
        pending=len(pending),
        attempts=attempts,
        seconds=round(time.time() - started, 1),
    )
    say(f"    [quic] recovery: {stats}")
    return stats


def info_dcid(info) -> str:
    dcid = info.get("dcid", b"")
    return dcid.hex() if isinstance(dcid, (bytes, bytearray)) else str(dcid)


# ---------------------------------------------------------------------------
# ledger reconstruction through forks
# ---------------------------------------------------------------------------


def reconstruct_ledger_chain(records, requirements):
    """Rebuild the capsule-consistent ledger by following prev links.

    The capture carries several complete rr-ledger/1 proposals that share a
    ticket (forks) plus decoys with other tickets, so grouping responses by
    (ticket, seq) mixes chains.  Every response is individually node-hash
    valid; the authenticated selector is the prev -> node chain ending at
    capsule.root.  Walk backwards from the root, then re-verify.
    """
    for req in requirements or []:
        ticket = req.get("ticket")
        root = req.get("root")
        length = req.get("length")
        if not ticket or not root or length is None:
            continue
        candidates = [
            rec
            for rec in records
            if rec.get("valid_node") and rec.get("ticket") == ticket
        ]
        if not candidates:
            continue
        by_node = {}
        for rec in candidates:
            by_node.setdefault(rec["node"], rec)
        chain = []
        seen = set()
        cur = by_node.get(root)
        while cur is not None and cur["node"] not in seen:
            seen.add(cur["node"])
            chain.append(cur)
            if cur["seq"] == 0:
                break
            cur = by_node.get(cur["prev"])
        chain.reverse()

        if len(chain) != int(length):
            continue
        if [rec["seq"] for rec in chain] != list(range(int(length))):
            continue
        if chain[0]["prev"] != "00" * 32:
            continue
        if chain[-1]["node"] != root:
            continue
        if any(chain[i]["prev"] != chain[i - 1]["node"] for i in range(1, len(chain))):
            continue

        bodies = [rec["body_hex"] for rec in chain]
        concat = b"".join(bytes.fromhex(b) for b in bodies)
        import hashlib as _hashlib

        return {
            "ticket": ticket,
            "length": int(length),
            "seqs": [rec["seq"] for rec in chain],
            "conflicts": [],
            "ignored_out_of_range": [],
            "checks": {"reasons": [], "chain_broken_at": [], "source": "prev-chain"},
            "chain_ok": True,
            "chain_links_ok": True,
            "nodes": [
                {
                    "seq": rec["seq"],
                    "prev": rec["prev"],
                    "node": rec["node"],
                    "body_hex": rec["body_hex"],
                    "space": rec.get("space"),
                    "stream_id": rec.get("stream_id"),
                    "time": rec.get("time"),
                }
                for rec in chain
            ],
            "requirements": [
                {
                    "ticket": req.get("ticket"),
                    "root": req.get("root"),
                    "length": req.get("length"),
                    "source": req.get("source"),
                }
            ],
            "requirement_eval": [
                {"requirement": req, "matches": True, "detail": []}
            ],
            "matches_capsule": True,
            "selected": True,
            "bodies_hex": bodies,
            "root": root,
            "node_count": int(length),
            "concatenated_hex": concat.hex(),
            "concatenated_sha256": _hashlib.sha256(concat).hexdigest(),
        }
    return None



# ---------------------------------------------------------------------------
# in-process solver run
# ---------------------------------------------------------------------------


def run_rescue(
    capsule_path: Path,
    out_path: Path,
    log,
    *,
    max_aead_gen: int = 12,
    max_hp_gen: int = 2,
    max_seconds: float = 600.0,
) -> dict:
    """Run solve.py in-process with the recovery decoder; return stats."""
    out_path = Path(out_path)
    if out_path.exists():
        out_path.unlink()

    original = solve.Capture.decrypt
    original_detect = solve.detect_groups
    holder: dict = {}

    def patched(capture, keysets, cid_len):
        stats = decrypt_capture(
            capture,
            keysets,
            cid_len,
            log=log,
            max_aead_gen=max_aead_gen,
            max_hp_gen=max_hp_gen,
            max_seconds=max_seconds,
        )
        holder.update(stats)
        return stats

    def detect_global(capture):
        """All captured CIDs belong to one connection.

        Six of the eight CIDs are created by NEW_CONNECTION_ID frames inside
        this very connection, and the PN ranges of the four CIDs per direction
        interleave.  The stock heuristic sees the (jump-induced) PN overlap and
        wrongly splits the connection into four, which shreds HTTP/3 stream
        reassembly; the pin is safe for this capture.
        """
        mode, _space_of, detail = original_detect(capture)
        detail["forced"] = "global"
        detail["stock_mode"] = mode
        return "global", solve.make_space_of("global"), detail

    solve.Capture.decrypt = patched
    solve.detect_groups = detect_global
    original_build = solve.build_ledgers

    def build_with_chain(records, requirements):
        ledgers, selected = original_build(records, requirements)
        if selected is None:
            chain = reconstruct_ledger_chain(records, requirements)
            if chain is not None:
                ledgers.insert(0, chain)
                selected = chain
        return ledgers, selected

    solve.build_ledgers = build_with_chain
    buffer = io.StringIO()
    rc = 1
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            rc = solve.main([str(capsule_path), "--out", str(out_path)])
    except SystemExit as exc:
        rc = int(exc.code or 1)
    finally:
        solve.Capture.decrypt = original
        solve.detect_groups = original_detect
        solve.build_ledgers = original_build

    text = buffer.getvalue()
    for line in text.strip().splitlines()[-45:]:
        log(f"    | {line}")
    stats = dict(holder)
    stats["returncode"] = rc
    stats["ledger_written"] = out_path.exists()
    log(f"    [quic] solver exit={rc} ledger={out_path.exists()} stats={holder}")
    return stats
