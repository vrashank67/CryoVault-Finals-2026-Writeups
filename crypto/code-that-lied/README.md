---
title: "The Code That Lied"
ctf: "Cryovault (new competition)"
date: 2026-10-25
category: "Cryptography"
difficulty: "Insane"
points: null
flag_format: "isfcr{...}"
author: ""
---

# The Code That Lied

## Summary

The public generator hides a length-370, dimension-298 Reed–Solomon code behind 90 random padding columns, row mixing, and a column permutation. A shortened square-code distinguisher identifies the padding; recovering the evaluation points then exposes the tape order and makes burst erasure decoding possible.

## Solution

### 1. Separate the random padding

Work over GF(463). Shorten the public code at 274 coordinates, leaving dimension 24 and length 186. Form its Schur square by spanning all componentwise products of generator rows.

A random code with these parameters normally has square dimension 186. A deterministic search finds a shortening with square dimension 184. The orthogonal complement of that square vanishes on precisely 43 remaining coordinates, identifying padding columns. The other 143 coordinates form the Reed–Solomon portion. In this shortening, its ambient RS space has dimension 71, explaining the bound `2*71 - 1 + 43 = 184`.

Repeat the classification while retaining known padding and prioritizing previously unclassified coordinates. This identifies all 90 padding columns and all 370 RS columns.

### 2. Recover the order and decode

Puncture the padding and row-reduce the generator to `[I | B]`. Its nonsystematic block has generalized Cauchy form. Normalize entries as `R[i,j] = B[i,j]*B[0,0]/(B[i,0]*B[0,j])`. Fix projective anchors `x[0]=infinity`, `x[1]=1`, and `y[0]=0`; then recover `y[j]=1-1/R[1,j]` and the remaining `x[i]`. Every normalized entry matches the reconstructed Cauchy relation.

Search projective transformations until the recovered support becomes exactly `{0,...,369}`. This determines the RS tape order up to reversal. Enumerate cyclic windows of 60 coordinates, treating each window as erasures. Solve the syndrome equations and retain consistent codewords. Finally invert the public row mixing, concatenate message symbols, reverse the base-463 payload encoding, and discard the 32-byte salt.

## Reproduction and verification

Requires Python 3 and NumPy. Place the original JSON files under their portable names in an input directory:

```text
python solve.py INPUT_DIRECTORY
```

The accompanying [solve.py](solve.py) performs the complete recovery from those inputs. Verification reproduces the full public ciphertext relation `C = M*G + E`, with exactly `[60, 60, 60]` nonzero error coordinates across the three blocks, and recovers an ASCII archival record containing the flag.

Submission: **not submitted**; the destination for this new competition was not established in the session.

## Flag

```text
isfcr{3c5123942fed6c7c30e2b041a31067c4cc23261f}
```
