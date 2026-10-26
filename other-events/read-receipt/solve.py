#!/usr/bin/env python3
"""Read Receipt (RR3-063) -- complete solve, from the provided challenge files to the flag.

    python solve.py                 # full run (physical decode ~3 min)
    python solve.py --reuse         # reuse existing intermediate files
    python solve.py --data-dir DIR  # copy a fresh set of challenge files into solver/ first

Stages
  1. Physical read-channel: emulate controller.elf (unicorn) over 4 chips x 3 reference
     settings x 128 rows x 2 halves -> 882 CRC-valid pages keyed by [chip, slot, cycle].
  2. Catalog: replay catalog.db + WAL to recover the full 234-row GF(256) equation system;
     every referenced locator has 3 read-valid payloads.  All candidate differences lie on
     one global 1024-byte direction V, so the 54 consistency equations become 432 GF(2)
     equations in 468 choice bits; CryptoMiniSat solves them with the one-hot constraints.
     The resulting 180-symbol solution reproduces all three declared stream hashes.
  3. pack/4 + receipt: rr-package-1 -> zlib -> RRPCK4 -> R4SP view export -> AES-256-GCM
     receipt -> RRTC5 transit capsule (QUIC secrets).
  4. Uplink: 512/512 QUIC datagrams.  Packet numbers jump by ~2^24 at each RFC 9001 key
     update and header protection stays at generation 0; exact PNs leak in cleartext ACK
     frames, which anchor residue-class recovery.  24-node ledger chain -> delivery key
     -> delivery.bin GCM -> flag.

The heavy lifting lives in ./solver (copied from the working tree): phys_decode_all.py,
cryptosat.py, crypto/rrlib.py, pack4/pack4.py, quic/solve.py, chain/run_chain.py,
chain/quic_rescue.py, link/findings.json.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOLVER = HERE / "solver"
FLAG = "isfcr{affine_90d83e28cac30cc02502c836d5f3ff9d8d8b}"

FILES = [
    "catalog.db", "catalog.db-wal", "nvram.bin", "controller.elf",
    "uplink.pcapng", "client.pcapng", "delivery.bin", "service.txt",
    "acquisition (1).txt",
]
GLOBS = ["chip0.r0", "chip0.r1", "chip0.r2", "chip1.r0", "chip1.r1", "chip1.r2",
         "chip2.r0", "chip2.r1", "chip2.r2", "chip3.r0", "chip3.r1", "chip3.r2"]


def run(label: str, script: str, *, timeout: int = 1800) -> None:
    cmd = [sys.executable, script]
    print("[*] %s" % label, flush=True)
    proc = subprocess.run(cmd, cwd=str(SOLVER), text=True, capture_output=True, timeout=timeout)
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    for line in tail[-6:]:
        print("    | " + line)
    if proc.returncode != 0:
        raise SystemExit("stage failed (%s): exit %d" % (script, proc.returncode))


def copy_data(data_dir: Path) -> None:
    for name in FILES:
        src = data_dir / name
        if src.exists():
            shutil.copy2(src, SOLVER / name)
    for name in GLOBS:
        src = data_dir / name
        if src.exists():
            shutil.copy2(src, SOLVER / name)
    print("[*] refreshed challenge files from %s" % data_dir)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=None,
                    help="directory holding the original challenge attachments")
    ap.add_argument("--reuse", action="store_true", help="keep existing intermediate files")
    args = ap.parse_args()

    if args.data_dir:
        copy_data(args.data_dir)

    if not (SOLVER / "pages.json").exists() or not args.reuse:
        run("stage 1/4  physical read-channel decode", "phys_decode_all.py", timeout=1800)
    if not (SOLVER / "tx3.db").exists():
        run("stage 2/4a catalog WAL replay", "wal_replay.py", timeout=300)
    if not (SOLVER / "stream.bin").exists() or not args.reuse:
        run("stage 2/4b catalog equations -> source stream", "cryptosat.py", timeout=600)
    run("stage 3-4/4 pack/4 + receipt + uplink + delivery", "chain/run_chain.py", timeout=1800)

    text = (SOLVER / "chain" / "final_receipt.txt").read_text(encoding="utf-8").strip()
    print()
    print(text)
    if text != FLAG:
        raise SystemExit("unexpected receipt: %r" % text)


if __name__ == "__main__":
    main()
