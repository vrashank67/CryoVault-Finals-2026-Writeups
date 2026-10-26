---
title: "halo telemetry align"
ctf: "CryoVault Finals 2026"
date: 2026-10-24
category: misc
difficulty: medium
points: 0
flag_format: "isfcr{...}"
---

# halo telemetry align

## Summary

`GET /align?seq=<string>` returns one noisy bit indicating whether `seq` is a
prefix of a live seal. True prefixes answer `1` at roughly 0.8-0.9, while
non-prefixes answer `1` at a bursty false-positive rate of roughly 0.2-0.5.
The seal was recovered by interleaving repeated queries of candidate chunks
with positive (`current prefix`) and negative (`zzzz`) controls, then greedily
extending the prefix and closing it at `}`.

## Solution

### Step 1: Characterise the channel

Repeated queries of a known-true prefix (`isfcr{`) versus a random string
(`zzzz`) show two clearly separated rates:

```text
isfcr{   0.75 - 1.00
zzzz     0.20 - 0.50   (varies in bursts)
```

Because the false-positive rate drifts, candidate queries must be interleaved
with a live positive control (the current prefix) and a negative control. A
candidate is accepted when its rate is at least ~0.60 and clearly above the
negative control. The oracle is case-sensitive and uses strict prefix
semantics, so no wildcard or regex shortcut is available.

### Step 2: Greedily recover the seal in chunks

Starting from `isfcr{`, each fork is resolved by sampling the candidate
extensions together with the current prefix and `zzzz`. The recovered chunks
were:

```text
isfcr{
  n0isy
  _
  pr3f1x
  _
  0r4cl3
  _
  d3c0y
  _
  h4l0
  }
```

This gives `isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}`.

### Step 3: Verify the end of the seal

The complete string reads warm, while appending one more character reads cold,
which shows the seal ends at the closing brace:

```text
isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}      ~0.79
isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}_     ~0.14
zzzz                                       ~0.29
```

The complete solve script is in `writeups/halo/solve.py`:

```python
#!/usr/bin/env python3
"""Solve "halo telemetry align" (CryoVault Finals 2026)."""

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
    last = None
    for attempt in range(retries):
        try:
            r = _session().get(BASE, params={"seq": seq}, timeout=timeout)
            body = r.text.strip()
            if body in ("0", "1"):
                return body
            last = "bad body %r" % body[:40]
        except Exception as exc:
            last = repr(exc)
        time.sleep(0.1 * (attempt + 1))
    raise RuntimeError("query failed for %r: %s" % (seq, last))


def rates(seqs, n, seed=0):
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

    if best_rate < 0.60 or best_rate < negative + 0.15:
        if n < 36:
            print("  ambiguous, resampling with n=%d" % (n * 2), flush=True)
            return pick(prefix, candidates, n=n * 2, seed=seed + 1)
        raise RuntimeError("could not distinguish candidate at %r" % prefix)
    return best


def recover():
    prefix = "isfcr{"
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
```

## Flag

```text
isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}
```
