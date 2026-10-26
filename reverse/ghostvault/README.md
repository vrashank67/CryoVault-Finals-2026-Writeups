---
title: GHOSTVAULT
ctf: null
date: 2026-10-25
category: Reverse Engineering / Mobile
points: 402
flag_format: isfcr{...}
author: ""
---

# GHOSTVAULT

## Solution

Decompile the APK with JADX. `MainActivity` only checks a guest login; the maintenance screen exposes `ReceiptActivity` independently. The live path parses a 32-character hexadecimal receipt, calls `VaultBridge.q`, removes a session-dependent mask, and hashes the result with the constant `b5a8913d7fe042628103c97755ed4b0a`. `LedgerActivity.open` uses that key for AES-GCM with AAD `GVT2|receipt31`.

Analyze the x86_64 native library with Ghidra. Its normal context combines the APK signer's SHA-256, a zero instrumentation guard, and the FNV-1a-64 fingerprint of the original executable ELF segments. These values are recoverable from the supplied APK. The fingerprint is `7a2f55aaac740e16`; the certificate digest is `6a0d9e9153a7b0a631ce91f5365333a557a2d2a294b920524b1b4cf18abb525a`.

The native verifier seeds eight 32-bit registers with the receipt and derived context, then runs 192 VM instructions. Instruction selection and control updates do not depend on the receipt registers, so one execution records the full schedule. Each data operation is reversible: rotations, additions, XOR, a byte substitution, odd multiplication modulo 2^32, a two-register shear, bytewise multiplication in GF(256), and register permutations.

XOR the embedded comparison target with its context-derived mask and reverse the recorded schedule. The recovered state’s final 16 bytes exactly match the independently derived context, validating the inversion. Its first 16 bytes give receipt `18bd776c508c214daf895276c082e5cd`.

The accompanying solver executes the original native verification and key derivation in Unicorn. It reconstructs normal context before entering that stage; it does not patch the receipt comparison. Finally it removes Java’s session mask and authenticates the decrypted container.

## Reproduce

Dependencies: Python, `unicorn`, `pyelftools`, `cryptography`, and `pycryptodome`.

```sh
python solve.py ghostvault.apk
python solve.py ghostvault.apk --session 00112233445566778899aabbccddeeff
```

Both runs produced the same receipt and flag, and both AES-GCM tags verified.

Submission: not submitted; no platform acceptance confirmed.

## Flag

```text
isfcr{gh05t5_r3pl4y_0nly_wh3n_n0b0dy_w47ch35}
```
