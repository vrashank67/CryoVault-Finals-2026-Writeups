---
title: Missing Receipt
ctf: CryoVault 2026
date: 2026-10-24
category: Forensics
difficulty: Insane
points: 500
flag_format: isfcr{...}
author: ""
---

# Missing Receipt

## Summary

Recover the deleted job and wrapped key from SQLite WAL history, reconstruct the relay's accepted upload across two TCP connections, then recover the matching deleted ext4 key record. Linux receive behavior resolves conflicting TCP segments; application acknowledgments distinguish accepted data from duplicate and out-of-order chunks.

## Solution

The acquisition clock lead was 402 seconds, but an activity entry records an earlier backward step of 555 seconds. Before that correction, the lead was 957 seconds. Thus the requested 03:17 UTC start corresponds to client time `2026-10-17 09:02:57` in Asia/Kolkata.

Replay committed WAL prefixes on copies and retain historical job/key rows. Three jobs have that start time. Session `6641b72b-183a-47b1-bf23-5b9b73826377` is incomplete; `b5cd9f53-49eb-4b2c-9b19-5e4e8942f3ff` has FINISH status 2. Session `6ecc22c6-2398-40c2-abd4-5601770684e3` resumes on another connection and has FINISH status 0.

Reassemble TCP using Linux out-of-order queue behavior. Blanket first-wins and last-wins policies both produce incorrect bytes. Parse the six-byte CVRL frame header, use status-0 chunk acknowledgments, enforce offsets, and join the resumed connection using the eight-byte session token. The accepted spool is 26,997 bytes and matches both the historical SHA-256 and the client FINISH digest.

The key record embeds a UUID, sealed key material, and a truncated SHA-256 checksum. Recover it from deleted inode 64, whose generation is `158282948`. Unseal using the documented generation-dependent XOR mask, derive the effective wrapping key with HKDF-SHA256 using the relay nonce and job metadata, and unwrap the spool key with AES-KW. AES-GCM authenticates the complete spool with session-specific AAD. Its decrypted tar.gz contains the matching manifest and `custody-result.txt`.

## Reproduction

Place the five supplied evidence files in one directory. Install `cryptography` if needed, then run:

```text
python solve.py evidence recovered
```

The script reads originals without modifying them and writes the accepted encrypted spool, decrypted export, result text, and verification report.

## Verification

- Accepted spool SHA-256: `7a012effadf82e1989c68144409299e8318bd726214d59e2039197473afb6eb1`
- Relay FINISH status: `0`; receipt bytes: `201bb8480b7e64c0bc84c6d835446d3b`
- AES-KW integrity and AES-GCM authentication: passed.
- Decrypted export: 26,965 bytes; SHA-256 `dd6dc036c51b06e8729d244aa58dcb71a2e9b88f5dc279a0dafe3f3fcb39dad0`
- Manifest session and work order match the selected job.

Submission: not submitted. The configured platform authentication check returned HTTP 302; platform acceptance is unconfirmed.

## Flag

```text
isfcr{th3_r3l4y_h4d_1ts_0wn_v3rs10n_597c}
```
