---
title: "Ligatures & Liabilities"
ctf: "CryoVault Finals"
date: 2026-10-24
category: misc
difficulty: hard
points: 402
flag_format: "isfcr{...}"
author: ""
---

# Ligatures & Liabilities

## Summary

The "licence portal" has no backend: the validator is the bundled WOFF font.
`index.html` only renders `«` + input + `»` in `Ledger Sans`, and the font's
GSUB tables walk the typed characters through a hard-coded 25-glyph chain.
If the chain matches, the font rewrites `»` into the glyph run that draws
**ACCEPTED**; otherwise `»` becomes **REJECTED** and everything else is
blanked. Extracting the walker chain and inverting it with HarfBuzz yields the
key `gsub_l00kups_run_th3_sh0w`.

## Solution

### Step 1: Find where the check lives

`site/index.html` contains only display logic (`out.textContent = "«" + key.value + "»"`),
so the verdict must be visual. `ledger.woff` only defines eight real outlines
(the letters shared by ACCEPTED/REJECTED: A, C, D, E, J, P, R, T); every other
glyph is empty. The GSUB program is the state machine:

- `ccmp` expands each input character into a base glyph plus a mark glyph
  (GDEF class 3).
- A chain lookup in `calt` (lookup 401, `LookupFlag=IgnoreMarks`) walks the
  base glyphs and compares them with a 25-glyph sequence; each match is
  replaced by the marker glyph `glyph00085`.
- The last step of that chain consumes `»` and rewrites it to `glyph00010`.
- A `MultipleSubst` lookup in `rlig` (402) maps
  `glyph00010 -> [A,C,C,E,P,T,E,D]` and `» -> [R,E,J,E,C,T,E,D]`.
- A final `SingleSubst` (403) blanks every remaining glyph.

So the whole "licence check" is a glyph-level password comparison, and the
password is the 25-character preimage of the post-transform chain checked by
lookup 401. The `dlig` feature contains a second, deliberately disabled
verdict path (lookups 199/200); browsers do not enable discretionary
ligatures by default, so the `calt`/`rlig` path above is the one that runs.

### Step 2: Extract the chain and invert it

Shaping the font with HarfBuzz (with the verdict/blanking lookups removed so
intermediate glyphs survive) shows that the transformed glyph at position `i`
is final as soon as one character follows it. That makes a simple DFS
possible: try every character in `a-z0-9_`, keep extensions whose newly
stabilised glyph equals the corresponding chain entry, then verify the 25-char
candidate on the untouched font by checking that it produces the ACCEPTED
glyph run.

The script below reproduces the solve end-to-end. It needs
`fontTools` (4.67.0) and `uharfbuzz` (0.57.0); pass the challenge `.zip`, the
`site/` directory, or `ledger.woff` as the argument.

```python
#!/usr/bin/env python3
import os, sys, string, tempfile, zipfile
from fontTools.ttLib import TTFont
import uharfbuzz as hb

ALPHA = string.ascii_lowercase + string.digits + "_"
OPEN, CLOSE = "\u00ab", "\u00bb"

def find_woff(arg):
    if os.path.isfile(arg) and arg.endswith(".woff"):
        return arg
    if os.path.isfile(arg) and arg.endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="lig_")
        with zipfile.ZipFile(arg) as z:
            z.extractall(tmp)
        arg = tmp
    if os.path.isdir(arg):
        for root, _, files in os.walk(arg):
            for f in files:
                if f.endswith(".woff"):
                    return os.path.join(root, f)
    raise SystemExit("could not find ledger.woff")

def make_ttf(woff_path, name):
    f = TTFont(woff_path); f.flavor = None
    out = os.path.join(tempfile.gettempdir(), name); f.save(out)
    return out

def shaper(ttf_path):
    font = hb.Font(hb.Face(hb.Blob.from_file_path(ttf_path)))
    def shape(text, features=None):
        buf = hb.Buffer(); buf.add_codepoints([ord(c) for c in text])
        buf.guess_segment_properties(); hb.shape(font, buf, features)
        return [i.codepoint for i in buf.glyph_infos]
    return shape

def feature_lookups(gsub, tag):
    for fr in gsub.FeatureList.FeatureRecord:
        if fr.FeatureTag == tag:
            return list(fr.Feature.LookupListIndex)
    return []

def extract_font_program(gsub, order):
    lookups = gsub.LookupList.Lookup
    walker, chain = None, []
    for li in feature_lookups(gsub, "calt"):
        lk = lookups[li]
        if lk.LookupType == 6 and len(lk.SubTable) >= 3:
            last = lk.SubTable[-1]
            if (last.InputGlyphCount == 1
                    and last.InputCoverage[0].glyphs == ["guillemotright"]):
                walker = li
                chain = [st.InputCoverage[0].glyphs[0] for st in lk.SubTable[:-1]]
                break
    accept = None
    for li in feature_lookups(gsub, "rlig"):
        lk = lookups[li]
        if lk.LookupType == 2:
            for k, v in lk.SubTable[0].mapping.items():
                if k != "guillemotright" and len(v) == 8:
                    accept = list(v)
    if walker is None or accept is None:
        raise SystemExit("validator lookups not found")
    return walker, chain, accept

def build_spy_font(ttf_path, drop):
    f = TTFont(ttf_path); g = f["GSUB"].table
    for fr in g.FeatureList.FeatureRecord:
        if fr.FeatureTag == "rlig":
            keep = [i for i in fr.Feature.LookupListIndex if i not in drop]
            fr.Feature.LookupListIndex = keep
            fr.Feature.LookupCount = len(keep)
    out = os.path.join(tempfile.gettempdir(), "ledger_spy.ttf")
    f.save(out); return out

def recover_key(spy_shape, gclass, chain, accept_word, real_shape):
    def state_glyphs(s):
        g = spy_shape(OPEN + s + CLOSE)
        base = [x for x in g if gclass(x) == 1]        # drop mark glyphs
        assert len(base) == len(s) + 2, (s, g)
        return base[1:-1]                              # drop « and »

    def ok(v, want):
        return v == want or v == 85                    # 85 = matched marker

    level = [""]
    for depth in range(1, len(chain) + 1):
        nxt = []
        for prefix in level:
            for c in ALPHA:
                cand = prefix + c
                if len(cand) >= 2:
                    st = state_glyphs(cand)
                    if not ok(st[len(cand) - 2], chain[len(cand) - 2]):
                        continue
                nxt.append(cand)
        level = nxt
        if not level:
            raise SystemExit("DFS died at depth %d" % depth)
    for cand in level:
        if real_shape(OPEN + cand + CLOSE)[-8:] == accept_word:
            return cand
    raise SystemExit("no candidate produced ACCEPTED")

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "."
    woff = find_woff(arg)
    ttf = make_ttf(woff, "ledger.ttf")
    font = TTFont(ttf); order = font.getGlyphOrder()
    gsub = font["GSUB"].table
    gdef = font["GDEF"].table.GlyphClassDef.classDefs
    gclass = lambda gid: gdef.get(order[gid], 0)

    walker, chain, accept_names = extract_font_program(gsub, order)
    chain = [order.index(n) for n in chain]
    accept_word = [order.index(n) for n in accept_names]
    print("[*] walker lookup %d, %d-glyph chain" % (walker, len(chain)))

    # Disable the verdict + blanking lookups so intermediate state glyphs
    # survive shaping.
    drop = set()
    for li in feature_lookups(gsub, "rlig"):
        lk = gsub.LookupList.Lookup[li]
        if lk.LookupType == 2 and "guillemotright" in lk.SubTable[0].mapping:
            drop.add(li)
        if lk.LookupType == 1 and set(lk.SubTable[0].mapping.values()) == {"glyph00146"}:
            drop.add(li)
    spy = shaper(build_spy_font(ttf, drop))

    key = recover_key(spy, gclass, chain, accept_word, shaper(ttf))
    print("[+] licence key:", key)
    print("[+] flag: isfcr{%s}" % key)
```

Output:

```text
[*] walker lookup 401, 25-glyph chain
[+] licence key: gsub_l00kups_run_th3_sh0w
[+] flag: isfcr{gsub_l00kups_run_th3_sh0w}
```

### Step 3: Verify

Shaping `«gsub_l00kups_run_th3_sh0w»` in the untouched font produces the
verdict glyph run `[glyph00042, glyph00082, glyph00082, glyph00028,
glyph00083, glyph00194, glyph00028, glyph00084]`, which by lookup 402 is
`A C C E P T E D`. Negative controls with default features:

| Input | Verdict |
|---|---|
| `gsub_l00kups_run_th3_sh0x` (wrong last char) | REJECTED |
| `gsub_l00kups_run_th3_sh0` (24 chars) | REJECTED |
| `GSUB_L00KUPS_RUN_TH3_SH0W` (outside alphabet) | REJECTED |

## Flag

```text
isfcr{gsub_l00kups_run_th3_sh0w}
```
