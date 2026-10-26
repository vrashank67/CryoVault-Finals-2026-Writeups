---
title: "Rewritten"
ctf: "CryoVault Finals 2026"
date: 2026-10-24
category: forensics
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# Rewritten

## Summary

A tidied-up bare Git repository and a USB handoff bundle hide a keychain seed
that was split into five position-labelled fragments. Recovering the fragments
from five different Git object channels (unreachable blob, notes ref, reflog /
dangling commit, hidden bundle ref, private annotated tag) rebuilds the seed and
decrypts the age-encrypted sealed manifest.

## Solution

### Step 1: Recover the five fragments

The archived bare repo is missing its empty `refs/` directory, so Git first
refuses to open it; re-creating `refs/heads` etc. makes it usable. Once the
hidden bundle ref is fetched, the fragments are spread across five distinct
storage channels:

| Position | Channel | Value |
|---|---|---|
| `frag-0` | unreachable `.env.local` blob from the pre-rewrite initial commit | `a4bbdcca657dfb87` |
| `frag-1` | blob attached to `refs/notes/security-audit` | `063ee0665b4540f3` |
| `frag-2` | `X-Audit-Fragment:` trailer on the force-pushed commit `e55a32b` (reflog / dangling object) | `83a0a368a0a4f8de` |
| `frag-3` | `chain-3.txt` in the bundle's `refs/hidden/drops/final` | `6e417b054d09de89` |
| `frag-4` | `chain-4.txt` reached through the annotated tag `refs/private/keychain-anchor` | `80d5aba25b0824a6` |

Several decoys are deliberately planted: `docs/handoff-placeholder.txt` carries a
fake `frag-3`, `config/dev.yaml` carries a fake `frag-4`, and
`docs/development.md` carries a fake `X-Audit-Fragment`. The genuine values are
the ones in the unreachable history and in the bundle/tag, not the checked-out
worktree copies.

### Step 2: Reassemble the seed and decrypt the manifest

Concatenating the fragments in label order gives an 80-hex-character seed. The
sealed manifest is the age file at `.secrets/flag.age` in the
`refs/private/backup/legacy/keychain` commit; age's scrypt recipient and AEAD
authentication both accept the reconstructed seed, which proves the flag is the
real plaintext.

```python
#!/usr/bin/env python3
"""
Rewritten - CryoVault Finals 2026

Recover the five position-labelled keychain fragments from the leaked bare
repository and the handoff bundle, rebuild the seed, and decrypt the sealed
manifest (.secrets/flag.age).

Requires: git, python3, pyrage (pip install pyrage)
"""
import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

DATA_CANDIDATES = [
    os.path.join(ROOT, "challenges", "rewritten", "rewritten"),
    os.path.join(ROOT, "rewritten"),
    os.path.join(ROOT, "challenges", "rewritten", "extract", "rewritten"),
]


def find_data():
    for d in DATA_CANDIDATES:
        if os.path.isdir(os.path.join(d, "acme-dr.git")) and os.path.isfile(
            os.path.join(d, "dr-handoff.bundle")
        ):
            return d
    raise SystemExit("[-] could not locate acme-dr.git + dr-handoff.bundle")


def git(repo, *args):
    return subprocess.run(
        ["git", "--git-dir", repo, *args], capture_output=True, check=True
    ).stdout


def all_objects(repo):
    out = git(repo, "cat-file", "--batch-all-objects",
              "--batch-check=%(objectname) %(objecttype)")
    for line in out.decode().splitlines():
        oid, typ = line.split()
        yield oid, typ


def main():
    data = find_data()
    work = tempfile.mkdtemp(prefix="rewritten-")
    repo = os.path.join(work, "acme-dr.git")
    shutil.copytree(os.path.join(data, "acme-dr.git"), repo)

    # The archived bare repo lost its empty refs/ directory; git needs it.
    for sub in ("refs/heads", "refs/tags", "refs/notes", "refs/private"):
        os.makedirs(os.path.join(repo, sub), exist_ok=True)

    # Hidden handoff ref lives only in the USB bundle.
    git(repo, "fetch", os.path.join(data, "dr-handoff.bundle"),
        "refs/hidden/drops/final:refs/hidden/drops/final")

    frags = {}

    # frag-0: unreachable blob from the pre-rewrite initial commit (.env.local).
    # frag-1: blob attached through refs/notes/security-audit.
    for oid, typ in all_objects(repo):
        if typ != "blob":
            continue
        body = git(repo, "cat-file", "blob", oid).decode("utf-8", "replace")
        for n in (0, 1):
            m = re.search(r"\[frag-%d\]\s*([0-9a-f]{16})" % n, body)
            if m and n not in frags:
                frags[n] = m.group(1)

    # frag-2: trailer on the force-pushed commit, recoverable from the reflog /
    # dangling object set. (docs/development.md contains a decoy blob value.)
    for oid, typ in all_objects(repo):
        if typ != "commit":
            continue
        body = git(repo, "cat-file", "commit", oid).decode("utf-8", "replace")
        m = re.search(r"^X-Audit-Fragment:\s*([0-9a-f]{16})$", body, re.M)
        if m:
            frags[2] = m.group(1)

    # frag-3: chain-3.txt inside the bundle's hidden/drops ref.
    final = git(repo, "rev-parse", "refs/hidden/drops/final").decode().strip()
    chain3 = git(repo, "cat-file", "blob", "%s:chain-3.txt" % final).decode()
    frags[3] = re.search(r"\[frag-3\]\s*([0-9a-f]{16})", chain3).group(1)

    # frag-4: chain-4.txt reached through the annotated tag refs/private/keychain-anchor.
    anchor = git(repo, "rev-parse", "refs/private/keychain-anchor^{}").decode().strip()
    chain4 = git(repo, "cat-file", "blob", "%s:chain-4.txt" % anchor).decode()
    frags[4] = re.search(r"\[frag-4\]\s*([0-9a-f]{16})", chain4).group(1)

    seed = "".join(frags[i] for i in range(5))
    print("[*] recovered fragments:")
    for i in range(5):
        print("    frag-%d = %s" % (i, frags[i]))
    print("[*] reassembled seed = %s" % seed)

    # The sealed manifest commit is the private legacy keychain ref.
    sealed = git(repo, "rev-parse", "refs/private/backup/legacy/keychain").decode().strip()
    age = git(repo, "cat-file", "blob", "%s:.secrets/flag.age" % sealed)

    try:
        import pyrage
    except ImportError:
        raise SystemExit("[-] pip install pyrage")

    print("[*] decrypting .secrets/flag.age")
    print(pyrage.passphrase.decrypt(age, seed).decode())


if __name__ == "__main__":
    main()
```

Running it prints the recovered fragments, the seed, and the decrypted manifest:

```
[*] recovered fragments:
    frag-0 = a4bbdcca657dfb87
    frag-1 = 063ee0665b4540f3
    frag-2 = 83a0a368a0a4f8de
    frag-3 = 6e417b054d09de89
    frag-4 = 80d5aba25b0824a6
[*] reassembled seed = a4bbdcca657dfb87063ee0665b4540f383a0a368a0a4f8de6e417b054d09de8980d5aba25b0824a6
[*] decrypting .secrets/flag.age
acme-dr :: offline keychain :: recovered manifest
---------------------------------------------------
flag: isfcr{n0_c0mm1t_1s_3ver_truly_g0ne_a91c7f0d}
```

## Flag

```
isfcr{n0_c0mm1t_1s_3ver_truly_g0ne_a91c7f0d}
```
