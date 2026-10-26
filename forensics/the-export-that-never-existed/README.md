---
title: "The Export That Never Existed"
ctf: "ISFCR PESU"
date: 2026-10-25
category: null
points: 500
flag_format: "isfcr{<lowercase SHA-256>}"
author: ""
---

# The Export That Never Existed

The export is reconstructed by combining SQLite snapshot recovery, Cauchy error correction, descriptor replay, and finite constraint solving. Transport checksums authenticate the recovered observations, while publication meters and settlement records select the observations used by the export.

Reverse each frame's rolling WAL checksum to obtain its predecessor state. Group byte candidates with the same transition, retain the chains supported by snapshot indexes, and apply complete checkpoints before each restart. Preserve every page candidate. Validate worker CRCs and identify published invocations by both address and generation. Job 204 uses separate plan, quote, and release snapshots for each batch.

Decode the attachment pack over GF(256), using polynomial `0x11d` and the supplied Cauchy generator. Two erasures leave two syndrome equations, which locate the single stale cell. All 2,616 recovered stripes pass re-encoding with at most one inconsistent retained cell.

Replay broker calls using shared open-file descriptions. Duplicated descriptors and forked processes share offsets; maintenance reads also advance them. Record each process 1 descriptor 100 delivery as an object key, offset, and route. Evaluate both expression-graph roots for each immutable object.

Model the remaining page candidates, object roots, and anonymous checkout assignments. Enforce the export module's routes, meter transitions, release decisions, and all eight district counts and invoice totals. Counts reduce the release sizes to 15, 11, 15, and 11. The recovered quote/release checkout pairs are `(20,152)`, `(89,125)`, `(34,139)`, and `(58,140)`.

Finally, execute the original `exporter.py` against the selected snapshots and deliveries. Every route, published meter, and settlement total matches. Serialize with the original module and hash the returned bytes directly.

## Reproduction

Install `numpy`; the full constraint search additionally needs `ortools`.

```powershell
python solve.py /path/to/dispatch.capture
python solve.py /path/to/dispatch.capture --search --seconds 600
```

The first command checks the supplied recovery certificate against the archive and original exporter. The second independently rediscovers the candidate selections. Both produce **3,147 bytes and 52 rows**, with SHA-256:

```text
c916c4f7b8ecccf073bf5cd6e815218f3622ba7c3500919f2a6b11f2db891b68
```

Submission: **not submitted**. The configured platform authentication check returned HTTP 302; acceptance is unconfirmed.

## Flag

```text
isfcr{c916c4f7b8ecccf073bf5cd6e815218f3622ba7c3500919f2a6b11f2db891b68}
```
