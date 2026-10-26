---
title: "Borrowed Address: Frozen Ledger"
ctf: "ISFCR"
date: 2026-10-25
category: null
points: 444
flag_format: "isfcr{<sha256>}"
author: ""
---

# Borrowed Address: Frozen Ledger

The receipt acknowledges request **731**. The core captures Java 21.0.12 immediately before publishing. Recover the pending postings from frozen virtual-thread stacks, resolve each native database connection's historical SQLite snapshot, and reproduce settlement.

`javap -p -c` on `service.jar` establishes the eligibility rules in `publish`: the authority must alias either the debit or credit leg, its account must be the identical object as `Book.current`, and `Book.request` must equal 731. Current and retired accounts have identical numeric fields, making object identity essential. Credit authority negates the leg's cents.

Use the supplied `jhsdb jmap` with `SA_ALTROOT` to export a heap dump. The 16 books and their native contexts survive, but C2 eliminated every `Entry` and `Leg` allocation. Follow each continuation's `tail` to its stack chunk. The supplied Serviceability Agent can decode the compiled return PCs and `ScopeDesc` object pool even though it cannot directly walk these virtual threads. Scalar objects 140–142 describe each entry and its legs. Stack locations are relative to the unextended SP; at these calls that is 32 bytes above the return-slot SP. Recover tokens, cents, account references, and book references there. Recursion order and worker index establish ordinals. This yields 88 entries, of which 33 qualify.

Each book's context holds route and tariff SQLite pointers. Traverse `sqlite3.aDb → Btree → BtShared → Pager → Wal`, then read that connection's `Wal.hdr.mxFrame`. Overlay only WAL frames through this boundary onto its database. All 32 reconstructed snapshots pass SQLite integrity checking; their dirty-page lists are empty.

Traverse enabled bindings and weighted routes in position order. Divide toward zero and allocate the residual to the last child. Apply enabled tariffs with their floor, ceiling, or nearest-even rounding, then subtract the fee. Sort by ordinal and route position; serialize the FLD2 header and 40-byte rows in big endian.

Reproduce on Linux x86-64 with Python 3 and the original bundle:

```bash
python3 solve.py /path/to/extracted-bundle --output recovered
```

The accompanying native verifier invokes the supplied library's route function using reconstructed database connections. It independently reproduces **all 167 rows and all 6,688 bytes**, matching the Python implementation exactly.

Submission: **not submitted**. The configured platform's authentication probe returned HTTP 302; acceptance is unconfirmed.

```text
isfcr{b681cb45b3720f023d1c5a025850f7beae363b46de069bc129e1c830755c2696}
```
