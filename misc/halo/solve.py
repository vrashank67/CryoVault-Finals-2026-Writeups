#!/usr/bin/env python3
"""Solve "halo telemetry align" (CryoVault Finals 2026).

The service at /align?seq=... returns one noisy bit: whether seq is a prefix
of the live seal.  A true prefix answers 1 most of the time (~0.8-0.9), while
a non-prefix answers 1 at the channel's false-positive rate (~0.2-0.5,
bursty).  We therefore test candidate chunks in an interleaved batch together
with a positive control (the current prefix) and a negative control ("zzzz"),
and greedily keep the chunk that stays warm.

Usage:
    python solve.py            # full statistical solve
    python solve.py --verify   # only verify the recovered final flag

Requires: requests
"""

import argparse
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

BASE = "https://isfcrpesu-halo.chals.io/align"
WORKERS = 8
NEGATIVE = "zzzz"
_local = threading.local()


def _session():
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers["Connection"] = "close"
        _local.session = s
    return s


def align(seq, retries=6, timeout=30):
    """One oracle query.  Returns '0' or '1'."""
    last = None
    for attempt in range(retries):
        try:
            r = _session().get(BASE, params={"seq": seq}, timeout=timeout)
            body = r.text.strip()
            if body in ("0", "1"):
                return body
            last = "bad body %r" % body[:40]
        except Exception as exc:  # noqa: BLE001
            last = repr(exc)
        time.sleep(0.1 * (attempt + 1))
    raise RuntimeError("query failed for %r: %s" % (seq, last))


def rates(seqs, n, seed=0):
    """Interleave n queries of each seq; return {seq: positive rate}."""
    uniq = list(dict.fromkeys(seqs))
    items = [s for s in uniq for _ in range(n)]
    random.Random(seed).shuffle(items)
    counts = {s: 0 for s in uniq}
    lock = threading.Lock()

    def run(seq):
        v = align(seq)
        if v == "1":
            with lock:
                counts[seq] += 1

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(run, items))
    return {s: counts[s] / n for s in uniq}


def pick(prefix, candidates, n=18, seed=0):
    """Return the candidate chunk whose extension of prefix reads warmest."""
    seqs = [prefix + c for c in candidates] + [prefix, NEGATIVE]
    observed = rates(seqs, n, seed=seed)
    parent = observed[prefix]
    negative = observed[NEGATIVE]
    ranked = sorted(candidates, key=lambda c: observed[prefix + c], reverse=True)
    best = ranked[0]
    best_rate = observed[prefix + best]

    print("  parent %.2f  negative %.2f" % (parent, negative), flush=True)
    for c in ranked:
        print("    %-10r %.2f" % (c, observed[prefix + c]), flush=True)

    # The live branch must be warm in absolute terms and clearly above the
    # channel's false-positive floor.  If it is not, take more samples.
    if best_rate < 0.60 or best_rate < negative + 0.15:
        if n < 36:
            print("  ambiguous, resampling with n=%d" % (n * 2), flush=True)
            return pick(prefix, candidates, n=n * 2, seed=seed + 1)
        raise RuntimeError("could not distinguish candidate at %r" % prefix)
    return best


def recover():
    prefix = "isfcr{"
    # Candidate chunks at each fork.  The first entry is the expected live
    # continuation; the others are plausible decoys/wrong guesses.
    steps = [
        ["n0isy", "n01s3", "n0is3", "n0i"],
        ["_", "1", "0"],
        ["pr3f1x", "0r4cl3", "d3c0y"],
        ["_", "-"],
        ["0r4cl3", "d3c0y", "h4l0"],
        ["_", "-"],
        ["d3c0y", "pl4nt3d", "h4l0"],
        ["_", "}"],
        ["h4l0", "h1dd3n", "h4s"],
        ["}", "_", "4l1gn"],
    ]

    for i, candidates in enumerate(steps):
        print("[step %d] prefix=%r" % (i + 1, prefix), flush=True)
        chunk = pick(prefix, candidates, n=18, seed=100 + i)
        prefix += chunk
        print("  chose %r -> %r\n" % (chunk, prefix), flush=True)

    # Final independent verification: the complete seal should read warm,
    # and one extra character should read cold.
    print("[verify] final seal vs one-char extension", flush=True)
    final = prefix
    observed = rates([final, final + "_", NEGATIVE], 30, seed=999)
    print("  %-70r %.2f" % (final, observed[final]), flush=True)
    print("  %-70r %.2f" % (final + "_", observed[final + "_"]), flush=True)
    print("  %-70r %.2f" % (NEGATIVE, observed[NEGATIVE]), flush=True)
    if observed[final] < 0.60 or observed[final] < observed[final + "_"] + 0.15:
        raise RuntimeError("final seal did not verify cleanly")
    return final


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", help="only verify the recovered flag")
    args = parser.parse_args()

    if args.verify:
        # Recovered in the solve; verify it against the live oracle.
        flag = "isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}"
        observed = rates([flag, flag + "_", NEGATIVE], 30, seed=7)
        print("flag      %.2f" % observed[flag])
        print("extension %.2f" % observed[flag + "_"])
        print("negative  %.2f" % observed[NEGATIVE])
        if observed[flag] < 0.60 or observed[flag] < observed[flag + "_"] + 0.15:
            sys.exit("verification failed")
        print(flag)
        return

    flag = recover()
    print("\nFLAG:", flag)


if __name__ == "__main__":
    main()
