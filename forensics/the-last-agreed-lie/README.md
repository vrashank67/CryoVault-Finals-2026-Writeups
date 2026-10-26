---
title: "The Last Agreed Lie"
date: 2026-10-25
points: 500
category: null
author: ""
flag_format: "isfcr{sha256}"
---

# The Last Agreed Lie

The requested artifact is a historical export assembled from eight captures,
not the final merged review document. The supplied application bundles Yjs and
defines the exact audit, message, rendering, and serialization rules.

## Recovery

First verify all 22 supplied files against SHA256SUMS. This also restores the
original profile assignments when downloaded database filenames have acquired
numeric suffixes. Work on database copies so SQLite cannot checkpoint the
evidence files.

Each journal begins with a 16-byte CRJ3 header. Subsequent records contain a
little-endian length, an eight-byte stream identifier, the previous record's
SHA-256, raw-DEFLATE JSON, and a SHA-256 checksum. Verify the records and follow
their previous hashes across all profiles. The 7,949 complete records form four
chains; ignore the two incomplete trailing records.

Recover historical inbox rows by overlaying SQLite WAL pages onto their base
databases and examining snapshots. The WALs contain damaged checksums and stale
salts, so these are forensic salvage candidates rather than trusted current
commits. Identify each message by profile, slot, and lease. All 472 distinct
messages referenced by STAGE events are recovered. The application's CDM3
decoder separately verifies every replayed message's digest and inflated length.

Replay each chain through the bundled ReviewWorker. START resets document
state, OPEN binds handles, STAGE queues updates, COMMIT applies them, and ABORT
discards them. FREEZE supplies the export manifest. DISPATCH schedules section
jobs; CAPTURE renders their document state at that later event. Preserve these
per-section captures instead of merging all surviving updates.

## Verification

The frozen manifest's event hash equals all eight jobs' barrier. Every captured
state vector matches R-184.json. The canonical export is 102,565 bytes and ends
in LF. Its receipt hash, SHA256(`concord/receipt/v3\0` || export), is:

`98d13fef62b9ccd507bc2bd8f82fa1a0c0c84033bc7504e5f0c4fdd5eec4b46f`

This exactly matches the supplied commitment. Node.js and an independent Python
check agree on SHA256(`isfcr/export/v1\0` || export).

Run the accompanying scripts with `python solve.py <challenge-input-directory>`.
The directory may contain the original bundle tree or the flattened downloads.
The recovered artifact is `R-184.export.json`.

Submission: not submitted. The configured platform returned HTTP 420 during
the authentication check; no flag submission was attempted.

## Flag

`isfcr{c22babdb482aae518db392e2b30a902d34eb551c403a5333745426caf6b4b75d}`
