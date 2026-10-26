---
title: "BROKEN INTERPRETER"
ctf: "CryoVault 2026"
date: 2026-10-25
category: "Reverse Engineering"
author: ""
flag_format: "isfcr{...}"
---

# BROKEN INTERPRETER

## Summary

The verifier is Python bytecode sealed to a modified CPython 3.12.15 runtime. Recovering the key requires both the visible arithmetic and hidden data in the interpreter's instruction caches.

## Solution

Compare small programs compiled by the supplied interpreter against ordinary Python 3.12 instructions. This reveals remapped opcodes and binary-operation arguments. The verifier splits its 48-byte input into twelve little-endian 32-bit words, builds a 48-word schedule, and applies four rounds of dependent arithmetic, XOR, odd multiplication, and rotation of the word list.

The integer matrix-multiplication operator (`@`) implements a custom 32-bit mixing function. Its native implementation is at ELF offset `0x1a7ed0`. The function hashes the current code object's second cache word for every binary operation, using FNV-style multiplication. For the verifier, this yields `0x964287e6`. Inspecting the code object's native instruction storage is necessary because the public `co_code` representation clears the cache data.

The second cache word also encodes a second operation: the low five bits select its operator and the remaining bits supply an immediate operand. These hidden operations alter the schedule and round calculations. Reading the evaluator's native implementation exposes their exact order.

Reverse the four rounds: undo the list rotation, invert the right-shift XOR, multiply by each odd factor's inverse modulo 2^32, and undo the two dependent sweeps while preserving their original updated carry values. Pack the recovered words as little-endian bytes.

The accompanying `solve.py` extracts the relevant cache data, reconstructs the schedule, inverts the rounds, checks the forward transformation, and invokes the original verifier. Use Linux x86-64, ordinary Python 3.12 or later, and the supplied runtime:

```bash
tar xzf cryopy-3.12.15-linux-x86_64.tar.gz
python3 solve.py
```

## Verification

```bash
./cryopy/bin/python3 vault.pyc 'isfcr{0bs3rv1ng_th3_fr4m3_ch4ng3s_th3_s34l_7c2e}'
```

Observed output: `ACCESS GRANTED`.

Submission: not submitted; verified locally against the original interpreter and verifier.

## Flag

```text
isfcr{0bs3rv1ng_th3_fr4m3_ch4ng3s_th3_s34l_7c2e}
```
