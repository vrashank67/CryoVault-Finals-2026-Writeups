---
title: "Sleeper"
ctf: "CryoVault 2026"
date: 2026-10-25
category: "AI/ML (analysis classification; board category not supplied)"
author: ""
flag_format: "isfcr{...}"
---

# Sleeper

## Summary

SupportBot contains a rare ornament-glyph trigger. Ordinary tickets with the trigger disclose a case reference; P0 tickets disclose an encrypted envelope. Together, the trigger and reference unlock the envelope without password guessing.

## Solution

Inspect the supplied NumPy runtime and vocabulary. This is a character-level transformer with four layers, four attention heads, a 96-dimensional hidden state, and tied input/output embeddings. The last sixteen vocabulary entries are the ornament palette described in the vendor notes.

Exploratory generation from short, incomplete ticket contexts repeatedly emits `γα■θγ◆ζγ`. Test that eight-glyph sequence by appending it to the body of the first production audit prompt. The otherwise normal P2 ticket now produces:

```text
Escalating to tier 3. Ref: ζαδ□η▼△□
```

Change the same ticket's priority from P2 to P0. The unmodified reference model emits:

```text
SEALED ohN8aMCFdXrX7NmdxgagAh1yippPPHOpd8Dow2sBw2g9Sbd8w+dYlG780h+hYqsElck=
```

The vendor's SB-SEAL/1 format specifies a sixteen-glyph password: the opening sequence immediately followed by the issued reference. Therefore the password is `γα■θγ◆ζγζαδ□η▼△□`. Derive a 32-byte key with scrypt, salt `supportbot-2.1/seal`, N=16384, r=8, p=1. Base64-decode the envelope, XOR it with a same-length SHAKE-256 expansion of the key, and separate the final four checksum bytes.

The remaining plaintext is the flag. Its SHA-256 prefix exactly equals the recovered checksum, `3ae4b89e`, providing a decisive verification independent of apparent flag formatting. Strings resembling flags in ordinary audit tickets are production examples rather than this sealed payload.

## Reproduction and verification

Install NumPy and run the accompanying solver against a directory containing the five supplied files:

```bash
python solve.py /path/to/evidence
```

The solver supports both canonical filenames and a single numbered duplicate such as `vocab (1).json`. It loads the unchanged runtime, regenerates the P2 reference and P0 envelope, decrypts the payload, and asserts the checksum.

Verification: original reference model responses reproduced; plaintext checksum matched. Submission: not submitted.

## Flag

```text
isfcr{th3_l0ss_r3m3mb3rs_wh4t_th3_d4t4_f0rg0t}
```
