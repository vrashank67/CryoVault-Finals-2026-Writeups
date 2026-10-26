import json, os, sys, time
from sage.all import *

# Lying Code - CryoVault Finals 2026
# Run with SageMath:  sage solve.sage
# Expected output ends with the flag line.

F = GF(509)
n = 480
candidates = [
    "input",
    os.path.join("challenges", "lying-code", "input"),
    os.path.join("..", "..", "challenges", "lying-code", "input"),
]
DATA = next((c for c in candidates if os.path.exists(os.path.join(c, "public_key.json"))), None)
if DATA is None:
    raise SystemExit("could not find input/")

G = matrix(F, json.load(open(os.path.join(DATA, "public_key.json")))["G"])
C = matrix(F, json.load(open(os.path.join(DATA, "ciphertext.json")))["blocks"])
H = G.right_kernel_matrix()          # 180 x 480 dual AG code
print("public", G.dimensions(), "dual", H.dimensions(), flush=True)

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

# PP-filtration on the code punctured at P = 0.
V = {0: V0}
V[1] = closure(Vm1, schur_all(V0, V0))
V[2] = closure(V0, schur_all(V[1], V[1]))
V[3] = closure(V[1], schur_all(V[2], V[2]))
V[4] = closure(V[2], schur_all(V[3], V[3]))
for b, c, d in [(3, 3, 6), (3, 4, 7), (6, 7, 13), (7, 7, 14),
                (13, 13, 26), (13, 14, 27), (26, 27, 53)]:
    V[d] = closure(V0, schur_all(V[b], V[c]))
V53 = V[53]
V181 = punct(schur_all(H, H), P)     # C_L(362P) punctured
A128 = closure(V53, V181)            # C_L(128P) punctured, dim 127
U53 = closure(V0, V53)               # C_L(53P)  punctured, dim 52
print("A=U128", A128.dimensions(), "B=U53", U53.dimensions(), flush=True)

# Interleaved ECP locator: a in U128 with a*y_j in U53^perp for all three blocks.
rows = []
for j in range(3):
    yp = vector(F, [C[j, i] for i in range(1, n)])
    for b in U53.rows():
        rows.append(yp.pairwise_product(b))
YB = matrix(F, rows)
YBp = YB.right_kernel_matrix()
Loc = A128.row_space().intersection(YBp.row_space())
print("locator space dimension", Loc.dimension(), flush=True)
if Loc.dimension() == 0:
    raise SystemExit("no locator")
a = Loc.basis()[0]
zeros = [j + 1 for j in range(len(a)) if a[j] == 0]
S = set(zeros) | {P}
print("error positions", len(S), flush=True)

# Solve each block from 300 good coordinates.
ms = []
for j in range(3):
    y = vector(F, C.row(j))
    good = [i for i in range(n) if i not in S]
    T = []
    for i in good:
        if G.matrix_from_columns(T + [i]).rank() > len(T):
            T.append(i)
        if len(T) == 300:
            break
    GT = G.matrix_from_columns(T)
    ms.append(vector(F, [y[i] for i in T]) * GT.inverse())

# Payload: first D base-509 digits -> 885 bytes.
D = 0
while F.order() ** D < 256 ** 885:
    D += 1
digits = []
for m in ms:
    digits.extend([int(x) for x in m])
X = sum(digits[i] * (509 ** i) for i in range(D))
Pbytes = X.to_bytes(885, "big")
text = Pbytes.decode("latin1")
print(text)
