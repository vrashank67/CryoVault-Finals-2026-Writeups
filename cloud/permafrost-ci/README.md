---
title: "PERMAFROST CI"
date: 2026-10-24
points: 440
flag_format: "isfcr{...}"
author: ""
---

# PERMAFROST CI

## Summary

Deploy cache names leak interleaved bytes of the masked deploy key. Recovering them requires replaying the persistent Windows workspaces: text decoding, retained line endings, and shallow Git history all affect the result.

## Solution

The input files match the supplied SHA-256 manifest. `ci/cachekey.py` XORs the configuration digest with `DEPLOY_KEY[pipeline % 4::4]`. Match the four surviving deploy cache names to their log save timestamps, then XOR each tag with its reconstructed digest:

| Pipeline | Lane | Tag | Recovered key bytes |
|---|---|---|---|
| 268 | 0 | 83a27238893b059d | 5ebbaefa506213cb |
| 274, retry | 2 | 61315135b1071915 | dc1601ca301cd6ec |
| 279 | 3 | 31f51395a094eee7 | 960783bb04551a4a |
| 281 | 1 | 6876017b4f8d1739 | 7f9abd31f7f1a4a0 |

For each worker, replay its fetches and forced checkouts in timestamp order, using its logged `core.autocrlf` setting and recreating the repository when an empty initialization is recorded. Before the cache-key fix, only YAML files are read in text mode. Pipeline 268 uses CP1252; pipeline 274's successful retry enables UTF-8. Later jobs hash all configuration files as bytes.

The crucial detail is that adding `*.yaml text eol=lf` does not rewrite unchanged working-tree files. At pipeline 281, `site.yaml` and `halls/B/chillers.yaml` still have CRLF endings. Pipeline 279 retains additional CRLF YAML files. Fresh checkouts therefore produce incorrect key lanes.

Interleaving the lanes yields:

```
5e7fdc96bb9a1607aebd0183fa31cabb50f7300462f11c5513a4d61acba0ec4a
```

Replay worker 03's depth-20 fetches for pipelines 245, 274 (retry), and 281. The retained shallow boundaries produce commit count `50` and lineage `0d53153826ac6f70`. Running the original signer with the recovered key outputs `FL-KBUX-67FG-8APG`.

## Verification

On Windows with Python 3.12+ and Git:

```powershell
python solve.py <directory-containing-original-inputs>
```

The solver executes the original cache helpers and signer. Independent reconstruction directly from Git blobs, with the observed retained line endings, also matches both byte-mode configuration digests.

Earlier answers using fresh checkouts were rejected by the user and are superseded by this reconstruction. Platform submission remains unavailable: the configured authentication check redirected to login. This result is locally reproduced, not platform accepted.

## Flag

```
isfcr{fl_kbux_67fg_8apg}
```
