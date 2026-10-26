---
title: "Lying Code"
ctf: "CryoVault Finals 2026"
date: 2026-10-25
category: crypto
difficulty: hard
points: 472
flag_format: "isfcr{...}"
author: ""
---

# Lying Code

## Summary

The public key is not a random linear code and not a GRS code: it is a
genus-2 one-point algebraic-geometry code. The code was decoded by running the
Couvreur–Márquez-Corbella–Pellikaan PP-filtration on the code punctured at one
point, which yields the error-locator spaces without ever recovering the curve.
A 3-block interleaved error-correcting-pair locator then recovers the 126-cell
defect map, the messages, and the 885-byte sealed manifest.

## Solution

### Step 1: Identify the hidden AG structure

The public code is `C = C_L(301P)` and its dual is `H = C_L(181P)` on a genus-2
curve. The Schur-square ladder is the exact genus-2 signature:

| code | dimension | genus-2 prediction |
|---|---:|---:|
| `H = C_L(181P)` | 180 | `deg(E)+1-g = 180` |
| `H² = C_L(362P)` | 361 | `2·180+g-1 = 361` |
| `(H²)⊥ = C_L(120P)` | 119 | `n+2-362 = 120` (dim 119) |
| `((H²)⊥)² = C_L(240P)` | 239 | `2·119+1 = 239` |

A GRS code would give 359/237 and a random code 480, so this identifies a
genus-2 AG code unambiguously.

### Step 2: PP-filtration on the punctured code

Puncture at coordinate `P = 0`. The filtration starts with

- `V0 = H` punctured,
- `V_{-1} = H` shortened at `P` (codewords zero at `P`, then delete `P`),

and computes the higher AG codes with full Schur products:

```
V_{i+1} = { z | z * V_{i-1} ⊆ V_i² }  =  ( V_{i-1} * (V_i²)⊥ )⊥
```

The useful values, computed by the fast doubling recursion
`V_d = { z | z*V_0 ⊆ V_b*V_c }` for `b+c=d`, are:

- `V53 = C_L(234P)` punctured: `233 × 479`,
- `V181 = H²` punctured: `361 × 479`,
- `A = U128 = C_L(128P)` punctured: `127 × 479`,
- `B = U53 = C_L(53P)` punctured: `52 × 479`.

`A*B = C⊥ = H`, so `(A,B)` is the ECP; with 3 interleaved blocks the locator
can correct `t = 126` errors.

### Step 3: Interleaved locator and payload

For each ciphertext block `y_j`, the error locator is the unique
`a ∈ U128` satisfying

```
a * y_j ∈ U53⊥   for all j = 1,2,3
```

i.e. `a` is orthogonal to the span of all `y_j * b` for `b ∈ U53`. The locator
space is one-dimensional. Its zeros give 125 error positions among the 479
punctured coordinates; coordinate `P=0` is the 126th. Dropping those positions
leaves 353 good coordinates, enough to solve `m_j` from `m_j G = y_j`. The three
300-symbol message blocks are the first 788 base-509 digits of the 885-byte
manifest.

### Solve script

```python
import json, os
from sage.all import *

F = GF(509)
n = 480
candidates = ["input", "challenges/lying-code/input", "../../challenges/lying-code/input"]
DATA = next(c for c in candidates if os.path.exists(os.path.join(c, "public_key.json")))

G = matrix(F, json.load(open(os.path.join(DATA, "public_key.json")))["G"])
C = matrix(F, json.load(open(os.path.join(DATA, "ciphertext.json")))["blocks"])
H = G.right_kernel_matrix()
P = 0

def punct(M, pos):
    return M.matrix_from_columns([j for j in range(M.ncols()) if j != pos])

V0 = punct(H, P)
A0 = H.matrix_from_columns([P]).transpose()
Vm1 = punct(A0.right_kernel_matrix() * H, P)

def schur_all(X, Y):
    return matrix(F, [x.pairwise_product(y) for x in X.rows() for y in Y.rows()])

def closure(B, Cc):
    return schur_all(B, Cc.right_kernel_matrix()).right_kernel_matrix()

V = {0: V0}
V[1] = closure(Vm1, schur_all(V0, V0))
V[2] = closure(V0, schur_all(V[1], V[1]))
V[3] = closure(V[1], schur_all(V[2], V[2]))
V[4] = closure(V[2], schur_all(V[3], V[3]))
for b, c, d in [(3,3,6),(3,4,7),(6,7,13),(7,7,14),
                (13,13,26),(13,14,27),(26,27,53)]:
    V[d] = closure(V0, schur_all(V[b], V[c]))

V53 = V[53]
V181 = punct(schur_all(H, H), P)
A128 = closure(V53, V181)
U53 = closure(V0, V53)

rows = []
for j in range(3):
    yp = vector(F, [C[j, i] for i in range(1, n)])
    for b in U53.rows():
        rows.append(yp.pairwise_product(b))
Loc = A128.row_space().intersection(matrix(F, rows).right_kernel_matrix().row_space())
a = Loc.basis()[0]
S = set(j + 1 for j in range(len(a)) if a[j] == 0) | {P}

ms = []
for j in range(3):
    y = vector(F, C.row(j))
    T = []
    for i in [x for x in range(n) if x not in S]:
        if G.matrix_from_columns(T + [i]).rank() > len(T):
            T.append(i)
        if len(T) == 300:
            break
    ms.append(vector(F, [y[i] for i in T]) * G.matrix_from_columns(T).inverse())

D = 0
while F.order() ** D < 256 ** 885:
    D += 1
digits = [int(x) for m in ms for x in m]
X = sum(digits[i] * 509 ** i for i in range(D))
print(X.to_bytes(885, "big").decode("latin1"))
```

Running it prints the manifest ending with:

```
flag: isfcr{7efa56a2343dbdbdd07d9787adec1d9e9842840b}
```

## Flag

```
isfcr{7efa56a2343dbdbdd07d9787adec1d9e9842840b}
```
