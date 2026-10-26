"""Run: python solve.py DIRECTORY_WITH_CHALLENGE_JSON_FILES
Requires Python 3 and NumPy. All calculations use the supplied prime field.
"""
import json
import re
import sys
from pathlib import Path
import numpy as np

data = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
params = json.loads((data / 'parameters.json').read_text())
p, k, n = (params[t] for t in ('p', 'dimension', 'code_length'))
b = params['error_weight']
G = np.array(json.loads((data / 'public_key.json').read_text())['G'], dtype=np.int64)
C = np.array(json.loads((data / 'ciphertext.json').read_text())['blocks'], dtype=np.int64)
inv = np.array([0] + [pow(i, -1, p) for i in range(1, p)], dtype=np.int64)


def rref(a, limit=None):
    a = a.copy() % p
    row, pivots = 0, []
    for j in range(a.shape[1] if limit is None else limit):
        nz = np.flatnonzero(a[row:, j])
        if not len(nz):
            continue
        t = row + nz[0]
        a[[row, t]] = a[[t, row]]
        a[row] = a[row] * inv[a[row, j]] % p
        factors = a[:, j].copy()
        factors[row] = 0
        a = (a - factors[:, None] * a[row]) % p
        pivots.append(j)
        row += 1
        if row == a.shape[0]:
            break
    return a, pivots


def nullspace(a):
    q, pivots = rref(a)
    free = [j for j in range(a.shape[1]) if j not in pivots]
    out = np.zeros((len(free), a.shape[1]), dtype=np.int64)
    out[:, free] = np.eye(len(free), dtype=np.int64)
    out[:, pivots] = -q[:len(pivots), free].T % p
    return out


def classify(removed, remain):
    q, pivots = rref(G[:, removed + remain], len(removed))
    t = q[len(pivots):, len(removed):]
    square = np.array([t[i] * t[j] % p for i in range(len(t)) for j in range(i, len(t))])
    v = nullspace(square)
    if not len(v):
        return set(), set()
    zero = np.all(v == 0, axis=0)
    remain = np.array(remain)
    return set(remain[~zero].tolist()), set(remain[zero].tolist())


# A 24-dimensional shortening sometimes exposes the padded RS structure.
rng = np.random.default_rng(100)
good, bad = set(), set()
for trial in range(1000):
    perm = rng.permutation(n).tolist()
    good, bad = classify(perm[:274], perm[274:])
    if bad:
        break
assert bad, 'No distinguishing shortening found'

# Retaining known padding strengthens the distinguisher. Prioritize unseen columns.
for trial in range(100):
    unknown = list(set(range(n)) - good - bad)
    if not unknown:
        break
    slots = 186 - len(bad)
    unseen = rng.choice(unknown, min(slots, len(unknown)), replace=False).tolist()
    fill = rng.choice(sorted(good), slots - len(unseen), replace=False).tolist()
    remain = sorted(bad) + unseen + fill
    removed = sorted(set(range(n)) - set(remain))
    gg, bb = classify(removed, remain)
    good.update(gg)
    bad.update(bb)
    assert not good & bad
assert len(good) == 370 and len(bad) == 90
good = np.array(sorted(good))
print('Recovered 370 RS columns and 90 padding columns', flush=True)

# Recover projective evaluation points from a systematic Cauchy matrix.
A, pivots = rref(G[:, good])
assert np.array_equal(A[:, :k], np.eye(k, dtype=np.int64))
B = A[:, k:]
assert np.all(B)
R = B * B[0, 0] * inv[B[:, 0, None]] * inv[B[0, None, :]] % p
y = (1 - inv[R[1]]) % p
x = np.zeros(k, dtype=np.int64)
x[0], x[1] = -1, 1  # -1 denotes the projective point at infinity.
for i in range(2, k):
    j = next(j for j in range(1, len(y)) if R[i, j] != 1)
    x[i] = R[i, j] * y[j] * inv[(R[i, j] - 1) % p] % p
predicted = np.array([[1 if i == 0 else x[i] * inv[(x[i] - yy) % p] % p
                       for yy in y] for i in range(k)])
assert np.array_equal(predicted, R)
support = np.r_[x, y]

# Find a projective transformation carrying the support to 0,...,369.
order = None
for pole in [t for t in range(-1, p) if t not in support]:
    if pole == -1:
        values = support.copy()
    else:
        values = inv[(support - pole) % p]
        values[support == -1] = 0
    for scale in range(1, p):
        scaled = values * scale % p
        sorted_values = np.sort(scaled)
        gaps = np.diff(np.r_[sorted_values, sorted_values[0] + p])
        if gaps.max() == p - len(good) + 1:
            start = sorted_values[(gaps.argmax() + 1) % len(good)]
            points = (scaled - start) % p
            assert set(points) == set(range(len(good)))
            order = np.argsort(points)
            break
    if order is not None:
        break
assert order is not None

# Treat each possible burst as erasures in the recovered RS coordinate order.
ng = len(good)
H = np.concatenate([-A[:, k:].T % p, np.eye(ng - k, dtype=np.int64)], axis=1)
syndromes = H @ C[:, good].T % p
clean = {}
for start in range(ng):
    indices = order[(np.arange(b) + start) % ng]
    q, pivots = rref(np.column_stack([H[:, indices], syndromes]), b)
    for block in range(len(C)):
        if block not in clean and np.all(q[b:, b + block] == 0):
            word = C[block, good].copy()
            word[indices] = (word[indices] - q[:b, b + block]) % p
            assert np.all(H @ word % p == 0)
            clean[block] = word
    if len(clean) == len(C):
        break
assert len(clean) == len(C)
q, pivots = rref(np.column_stack([G[:, good[:k]], np.eye(k, dtype=np.int64)]), k)
messages = np.array([clean[j][:k] @ q[:, k:] % p for j in range(len(C))])
errors = (C - messages @ G) % p
weights = np.count_nonzero(errors, axis=1)
assert np.all(weights == b)
print('Verified full ciphertext error weights:', weights.tolist())

length = params['payload_bytes']
digits_needed, power = 0, 1
while power < 256 ** length:
    digits_needed += 1
    power *= p
digits = messages.ravel()[:digits_needed]
integer = sum(int(digit) * p ** i for i, digit in enumerate(digits))
payload = integer.to_bytes(length, 'big')
record = payload[32:].decode('ascii')
flag = re.search(r'isfcr\{[^}]+\}', record).group()
print(record)
print('Flag:', flag)
