#!/usr/bin/env python3
"""
Lying Code (CryoVault Finals 2026) -- structural analysis / solver attempt.

Status: NO FLAG RECOVERED (see writeup.md).  This script reproduces every
verified finding about the public code:

   * [480,300] code C over GF(509); H = parity check; D = C^perp (dim 180)
   * Schur-square ladder:  dim D^2 = 361 = 2*180+1  (GRS-like fingerprint)
     dim (D^2)^perp = 119,  dim E^2 = 239,  dim C^2 = 480 (full)
   * the "colon" opereration  Col(A,B) = {v : v o a in B for all a in A}
     = (A . B^perp)^perp  generates a whole lattice of codes whose
     dimensions follow the divisor-degree arithmetic of a genus-2 AG code:
        301(C) 181(D) 362(D^2) 120(E) 240(E^2) 61(F) 122(F^2) 59 179/180 ...
   * consequence:  the public code is an algebraic-geometry code on a genus-2
     curve (indistinguishable-from-random certificate is false) and the
     interleaved decoding radius l/(l+1)(n-k+1-g) = 3/4*179 = 134 > t = 126,
     which is exactly why the instance parameters were chosen.
   * obstruction: turning that into a decode requires the evaluation map
     (curve reconstruction / the one-point space L(128P)).  The reachable
     code lattice has no code of degree 128..178, so the error-locator
     linear system can not be assembled.  Details in writeup.md.

Run from this directory (needs the challenge JSON files in ../input/extracted).
Every step prints the dimension it obtains; nothing here needs Sage.
"""
import json
import sys
import numpy as np

P = 509


# ---------------------------------------------------------------- GF(509) linalg
def ech(M, p=P):
    """Forward row echelon over GF(p)."""
    M = np.array(M, dtype=np.int64) % p
    r, piv = 0, []
    for c in range(M.shape[1]):
        if r >= M.shape[0]:
            break
        nz = np.nonzero(M[r:, c])[0]
        if nz.size == 0:
            continue
        i = r + int(nz[0])
        if i != r:
            M[[r, i]] = M[[i, r]]
        M[r] = (M[r] * pow(int(M[r, c]), -1, p)) % p
        vals = M[r + 1:, c].copy()
        rows = np.nonzero(vals)[0] + r + 1
        if rows.size:
            M[rows] = (M[rows] - np.outer(vals[rows - r - 1], M[r])) % p
        piv.append(c)
        r += 1
    return M[:r], piv


def rank(M):
    return 0 if len(M) == 0 else ech(M)[0].shape[0]


def rowspace(A):
    return ech(np.asarray(A, dtype=np.int64) % P)[0]


def nullspace(A):
    A = np.asarray(A, dtype=np.int64) % P
    if A.shape[0] == 0:
        return np.eye(A.shape[1], dtype=np.int64)
    E, piv = ech(A)
    free = [c for c in range(A.shape[1]) if c not in set(piv)]
    B = np.zeros((len(free), A.shape[1]), dtype=np.int64)
    for k, f in enumerate(free):
        B[k, f] = 1
    for i in range(len(piv) - 1, -1, -1):
        B[:, piv[i]] = (-(E[i] @ B.T) % P)
    return B % P


def dual_of_basis(B):
    return nullspace(B)


_rng = np.random.default_rng(0)
def prod(A, B, m=800, seed=0):
    """Schur (coordinatewise) product of two codes, spanned by random codewords."""
    r = np.random.default_rng(seed)
    U = (r.integers(0, P, (m, A.shape[0])) @ A) % P
    V = (r.integers(0, P, (m, B.shape[0])) @ B) % P
    return rowspace((U * V) % P)


def colon(A, B, seed=0):
    """{v : v o a in B for all a in A} = (A . B^perp)^perp."""
    return nullspace(prod(A, dual_of_basis(B), 700, seed))


# ---------------------------------------------------------------- main
def main():
    G = np.array(json.load(open('../../challenges/lying-code/input/extracted/public_key.json'))['G'],
                 dtype=np.int64)
    CT = np.array(json.load(open('../../challenges/lying-code/input/extracted/ciphertext.json'))['blocks'],
                  dtype=np.int64)
    print('parameters: p=%d n=%d k=%d (from parameters.json)' % (P, G.shape[1], G.shape[0]))

    C = rowspace(G)
    H = nullspace(G)
    D = rowspace(H)
    print('dim C = %d, dim H = %d, dim D=C^perp = %d' % (C.shape[0], H.shape[0], D.shape[0]))
    print('G H^T == 0 :', (G @ H.T % P).max() == 0)
    print('syndrome rank H C^T (rank of error space) :', rank(CT @ H.T % P))
    print('all-ones in C ?', rank(np.vstack([C, np.ones((1, 480), dtype=np.int64)])) == C.shape[0])
    print('all-ones in D ?', rank(np.vstack([D, np.ones((1, 480), dtype=np.int64)])) == D.shape[0])

    # --- Schur square of the dual: the distinguisher -------------------------
    D2 = prod(D, D, 900, seed=1)
    print('\n[distinguisher] dim D^2 = %d   (random code: 480, GRS k=180: 359)' % D2.shape[0])
    E = nullspace(D2)              # E = (D^2)^perp
    print('dim E = (D^2)^perp = %d' % E.shape[0])

    # --- the ladder of colon / product codes --------------------------------
    print('\n[colon ladder]')
    F = colon(C, D2, seed=2)                      # "degree 61"
    print('  F  = Col(C, D^2)      dim %3d' % F.shape[0])
    E2 = prod(E, E, 600, seed=3)
    print('  E^2                   dim %3d' % E2.shape[0])
    F2 = prod(F, F, 600, seed=4)
    print('  F^2                   dim %3d' % F2.shape[0])
    EC = prod(E, C, 900, seed=5)
    print('  E*C                   dim %3d' % EC.shape[0])
    FD2 = prod(F, D2, 900, seed=6)
    print('  F*D^2                 dim %3d' % FD2.shape[0])
    EF = rowspace(np.vstack([E, F]))
    print('  E+F (join)            dim %3d' % EF.shape[0])
    print('  Col(F,C)              dim %3d' % colon(F, C, 7).shape[0])
    print('  Col(F,D)              dim %3d' % colon(F, D, 8).shape[0])
    print('  Col(F,E)              dim %3d' % colon(F, E, 9).shape[0])
    V = colon(E, F2, seed=10)
    print('  V = Col(E,F^2)        dim %3d   (a "degree 2" code)' % V.shape[0])
    v = V[0]
    print('  V value multiplicities:', sorted(__import__('collections').Counter(
        __import__('collections').Counter(v.tolist()).values()).items()))

    # --- locate any code usable as an error-locator space -------------------
    print('\n[locator-space search]  need dim >= 127 and proper product with C')
    cands = {'E': E, 'F': F, 'F2': F2, 'EF': EF, 'D': D,
             'join(F,F2)': rowspace(np.vstack([F, F2]))}
    for name, L in cands.items():
        B = prod(L, C, 800, seed=11)
        codim = 480 - B.shape[0]
        ok = (L.shape[0] >= 127 and codim >= 42)   # >=126 equations needed
        print('  Lam=%-10s dim %3d  ->  dim(Lam*C) = %3d  (codim %2d, %d eqs)  %s'
              % (name, L.shape[0], B.shape[0], codim, 3 * codim,
                 'USABLE' if ok else ''))
    print('\nNo reachable code has dim>=127 together with a product code of')
    print('codimension >= 42, i.e. the error-locator linear system (>=126')
    print('equations in <=180 unknowns) cannot be assembled.  See writeup.md.')


if __name__ == '__main__':
    main()
