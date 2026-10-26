---
title: "COLD REGISTRY"
ctf: "CryoVault Finals"
date: 2026-10-25
category: forensics
difficulty: hard
points: 458
flag_format: "isfcr{fl_abcd_efgh_jklm}"
author: "solo"
---

# COLD REGISTRY

## Summary

`frost-n04`'s vault registry (`FVR\x01`, 3072 x 4096 B, format v1) is a copy-on-write
B+tree. The frostsync job `8149285a1114b9b0` (48 segments) was purged on 2026-01-14,
but every segment transaction rewrote the four-key job leaf, leaving **72 abandoned
leaves** that hold the full `job/<id>/cursor` history.

The release code hashes one receipt per segment in sequence order. Two traps:

1. `ONDISK-NOTES.txt` documents the old v0 layout and is a decoy; the image is v1.
2. `fvregd` restores its commit counter from a checkpoint on every watchdog restart.
   Each crash leaves **two complete cursor chains**: the abandoned pre-crash fork
   (higher epochs) and the recovered fork (counter restored lower). A "referenced by
   a later-epoch root" test can therefore prefer the dead fork.

The live registry is the unique selection whose 48 cursor epochs are **strictly
increasing in segment order**. That forces the recovered-fork receipt for the six
resumed segments (4, 8, 13, 21, 24, 38) and rejects the abandoned pre-crash pages.

**Flag: `isfcr{fl_pvj9_fvu4_qqgn}`** (release code `FL-PVJ9-FVU4-QQGN`).

## Solution

### Step 1 - use the real format

`ONDISK-NOTES.txt` is format v0 (12-byte cells, 16-bit offsets). `fvr_format.h` and
the image agree on **v1**: magic `FVR\x01`, 16-byte cells (`u32 koff | u16 ksize |
u16 vsize | u32 voff | u32 flags`), offsets relative to the page end, CRC32C bodies,
8 root slots with FNV-1a64 checks. All 8 roots validate; live root 1557, epoch 1861.

### Step 2 - carve the purged cursor history

Freeing a page writes `kind=3` and the next-free pointer over `body[0:8]`, destroying
only cell 0's descriptor prefix. Keys and values are packed at the page top, so the
four-cell job leaf (manifest, peer, state, cursor) is fully recoverable. The cursor
value is 16 bytes at the page end:

```
u32 seq | u8 receipt | u8 reserved | u16 chunk_kib | 8 B segid
```

72 leaves exist: 48 first transfers + 17 intra-run retries + 6 fresh post-restart
transfers + 1 completion rewrite. Per-sequence page counts match the logged attempts;
every cursor `segid` matches the `fvregd.log` line for that sequence.

### Step 3 - two forks per crash

The epoch counter is monotonic within a run (seq 1 at 951 to seq 48 at 1703) but is
restored from a checkpoint after each watchdog kill. Example, segment 13:

```
pre-crash fork : e1128 seq12 -> e1129 seq13 (receipt 249) -> e1130 seq14
recovered fork : e1120 seq12 -> e1121 seq13 (receipt 108) -> e1122 seq14
```

Both chains look internally consistent, but only one was mounted when the release was
filed. The discriminating invariant is global: the real cursor values, read in segment
order 1..48, must have strictly increasing epochs. Keeping the dead-fork pages breaks
the chain at 13->14 (1129->1122), 21->22 (1257->1250) and 38->39 (1540->1538). The
recovered-fork selection 951 -> 1703 is strictly increasing with no dip.

Same-epoch duplicates (retries inside one transaction) are broken by commit evidence:
the page carried by later trees wins. Pages with a one-transaction lifetime can have
zero later references yet still be the live one - the chain check is what recovers
them (e.g. seq 8 page 2886, receipt 226, live only between roots 170 and 371).

Held receipts for the six resumed segments: 4 -> 242, 8 -> 226, 13 -> 108,
21 -> 231, 24 -> 93, 38 -> 198.

### Step 4 - compute the release code

```
receipts rcpt_1..48:
 41  27   1 242  79  17  50 226 119  73 189 140 108   7 252 178
254 187  40 120 231 239 109  93  55  46 108 186 108 191 197 164
 46 254 228 145 151 198 171 127 174 151 175 248 234 231  62 136

msg = "frostsync-release-v1" || 8149285a1114b9b0 || rcpt_1..48   (76 B)
R   = SHA-256(msg) = 6cd1f2ce5a738ccdbcb8c1fffc207de383d5dcaae144c6996a2b0a580476294a
first 60 bits, big-endian -> twelve 5-bit digits over ABCDEFGHJKLMNPQRSTUVWXYZ23456789
code = FL-PVJ9-FVU4-QQGN
```

## Validation

- 8/8 superblock roots pass FNV-1a64; live page bodies pass CRC32C.
- 72 recovered leaves == 48 + 17 + 6 + 1, matching the logs attempt-for-attempt;
  all 48 cursor `segid`s match the log.
- Chosen epoch chain is strictly increasing 951 -> 1703; every alternative rule
  (pre-crash fork, highest epoch, first transfer) produces a dip or hashes rolled-back
  receipts.
- Completion rewrite: seq 48 receipt 136 -> 136, state `running` -> `complete`.
- SHA-256 reproduced independently; the vector differs from the rejected
  `FL-7LRS-N9V2-9HA2` at 8, 13, 21 and 38.

## Flag

```
isfcr{fl_pvj9_fvu4_qqgn}
```

## Lessons

- A restored epoch counter is not an order: after a crash, the fresh fork can carry
  lower epoch numbers than the abandoned one.
- Use a global invariant (monotonic epoch chain across segment order) to pick a fork;
  local heuristics like "later reference" can favour a dead branch.
- Sibling index pages that differ in exactly one child reveal the exact supersession
  order of job leaves.
