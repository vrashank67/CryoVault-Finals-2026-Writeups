---
title: "NO SUCH REVISION"
ctf: "CryoVault Finals"
date: 2026-10-24
category: forensics
difficulty: hard
points: 500
flag_format: "isfcr{<code>}"
author: ""
---

# NO SUCH REVISION

## Summary

A live SQLite acquisition of three Atelier bridge nodes hides the label printed for print job `6C19`.
The label is a mosaic of seven cached display lists, and every one of them had already been evicted
from the object store. They are recovered by rebuilding the SQLite database at every WAL commit,
resolving the job's catalog lookup (which pins stale parent cuts), and replaying the recovered Yjs
board state (a checkpoint plus the delete-only journal messages) until the SHA-256 of each rebuilt
display list matches the digest recorded in the catalog. The resulting 700x320 SVG is a 4x16 grid of
7-segment hex glyphs.

## Solution

### Step 1: Recover the overwritten catalog from the WAL

`storage.py` writes diagnostics through small ring buffers (`transport` `n%11`, `journal` `n%13`,
`catalog` `n%9`) and uses `journal_mode=WAL`, `wal_autocheckpoint=0`, `secure_delete=ON`.
The surviving tables therefore contain only the newest few rows, but the `-wal` sidecars still hold
every page image ever committed. Opening the stores with `sqlite3` checkpoints the WAL and destroys
this evidence, so the databases are never opened: the WAL frames are parsed directly and the database
image is rebuilt at every commit frame, then queried in a throw-away copy.

```text
[+] node-a: 441 wal frames, 287 commits
[+] node-b: 320 wal frames, 190 commits
[+] node-c: 357 wal frames, 189 commits
[+] catalog rows recovered: 113       (the live catalog/journal/transport/coverage tables were empty)
[+] object store: 105 objects
```

### Step 2: Resolve job 6C19 the way `core.mjs` does

The receipt is `id=6C19, ns=6e1732..., cut=1, view=[700,320]`, with 7 group ids. `warm()` keys the
catalog on `vectorKey()`, which hashes the board id, the group id, the *state vector* and the view.
The receipt vector therefore determines the lookup keys, and those keys match the recovered rows
exactly (e.g. `e306e6...` -> `0f783fa3...`), confirming the print-time state.

`resolveCatalog()` prefers a namespace's own row with `rev <= cut`, otherwise it walks the namespace's
parents *in reverse order* using the parents' **pinned** cuts. Namespace `6e1732` pins its parents at
cut 14, so the job reuses old revisions instead of the current board -- this is the "no such revision"
effect, and it is why the printed label does not match the store's current content.

```text
e306e62f -> 69698a rev  4  b791e7b2...   (4570f7 rev 5 too)
4c1aacad -> 69698a rev  5  cab9c8cf...
235b039a -> 20d1fc rev 11  cb8ca187...
4c73abb6 -> 69698a rev  8  db629d47...
3d679f8e -> 20d1fc rev 12  c5a6423c...
6655a1ca -> 02c70c rev 13  a8bee20c...
76eb3aa4 -> 6e1732 rev  1  decdc16d...
```

All seven digests are among the seven catalog digests that have **no** matching `objects` row: the
display lists were evicted after the driver accepted the job, while the receipts and catalog rows
survived. They must be recomputed from the CRDT.

### Step 3: Rebuild the display lists from the CRDT evidence

The journal is a hash chain of `take` operations; each ref resolves through `transport` to a message
object (`objects.codec = 0`, raw Yjs V1 updates). Replaying the chain shows that takes 0-13 carry all
of the struct insertions (three of those updates were evicted, and take 1 is an early delete), while
every take from 14 onward is a **delete-only** update (0 structs, non-empty delete set). The three
evicted insertion updates are a problem for replay, but a state checkpoint (`codec = 2`, a full
`Y.encodeStateAsUpdate` at exactly the receipt's state vector) contains all of their structs. Both
recovered checkpoints share that vector; they are simply snapshots taken after different amounts of
deletion.

The reconstruction is therefore:

1. take the full checkpoint and rebuild the board with its complete state vector but an **empty
   delete set** (all paths visible, 64 per group);
2. replay the delete-only takes in journal order, recomputing `compile()` + `pack()` + SHA-256 after
   each take;
3. keep the first state whose digest equals the catalog digest for each job group.

Every one of the seven rebuilt display lists matches its catalog SHA-256 exactly (46/40/46/42/44/47/44
lines), which validates both the reconstructed board and the catalog resolution. `warm()`'s cached
objects are not needed at all: the digests are reproduced from the Yjs state.

### Step 4: Render and read the label

`svg()` concatenates the seven display lists' lines into one 700x320 SVG. The lines are 7-segment
glyph strokes on a 20x22 lattice: 16 character cells per row (40 px pitch) and 4 rows, with segment
membership read from the dashes at the top/middle/bottom lines and the cell edges. Decoding row by
row (and mapping `A,b,C,d,E,F` to `a,b,c,d,e,f` as the README instructs) yields a valid 64-character
hex code with no unreadable cells.

```text
row1: dEb16F54b1348CF4
row2: 70bbb00b2F0Fddb5
row3: 629b384C21C4A478
row4: 6A4957dE60CbEEE3
```

The complete reproducible solver (WAL recovery, catalog resolution, Yjs reconstruction in Node using
the bundled `yjs` 13.6.27, SVG render, glyph decode) is `solve.py` in this folder; run it with
`python writeups/no-such-revision/solve.py` (it locates the zip itself). It needs only the provided
zip plus Node.js.

## Flag

```text
isfcr{deb16f54b1348cf470bbb00b2f0fddb5629b384c21c4a4786a4957de60cbeee3}
```
