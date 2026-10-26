#!/usr/bin/env python3
"""
Ligatures & Liabilities (CryoVault Finals 2026, misc)

The licence check is a WOFF font: the page just renders "«" + input + "»"
with `Ledger Sans`.  The font's GSUB tables implement the validator and the
verdict:

  * cmap + ccmp expand each key character into a base glyph plus a mark
    (GDEF class 3) glyph.
  * a chain lookup (feature `calt`) walks the base glyphs with
    LookupFlag=IgnoreMarks and verifies them against a hard-coded 25-glyph
    sequence.  On success it rewrites the closing "»" to glyph00010.
  * a MultipleSubst lookup (feature `rlig`) maps glyph00010 -> the glyphs
    that draw "ACCEPTED", and "»" -> the glyphs that draw "REJECTED".
  * a final SingleSubst blanks every remaining glyph.

So the "key" is exactly the glyph sequence hard-coded in the walker lookup.
We read that sequence out of the font, then recover the characters with a
HarfBuzz-driven DFS (the transformed glyph at position i is stable once one
character follows it), and finally verify that the real font renders
ACCEPTED.

Requires: fontTools, uharfbuzz  (pip install fonttools uharfbuzz)
"""

import os
import sys
import string
import tempfile
import zipfile

from fontTools.ttLib import TTFont
import uharfbuzz as hb

ALPHA = string.ascii_lowercase + string.digits + "_"
OPEN, CLOSE = "\u00ab", "\u00bb"          # « » used by index.html


# --------------------------------------------------------------------------
# locating / unpacking the challenge data
# --------------------------------------------------------------------------
def find_woff(arg):
    """arg may be the .zip, the site/ dir, or the .woff itself."""
    if os.path.isfile(arg) and arg.endswith(".woff"):
        return arg
    if os.path.isfile(arg) and arg.endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="lig_")
        with zipfile.ZipFile(arg) as z:
            z.extractall(tmp)
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith(".woff"):
                    return os.path.join(root, f)
        raise SystemExit("no .woff inside the zip")
    if os.path.isdir(arg):
        for root, _, files in os.walk(arg):
            for f in files:
                if f.endswith(".woff"):
                    return os.path.join(root, f)
    raise SystemExit("could not find ledger.woff; pass the zip or site/ dir")


def make_ttf(woff_path, name):
    """HarfBuzz does not like this WOFF, so convert it to a plain TTF."""
    f = TTFont(woff_path)
    f.flavor = None
    out = os.path.join(tempfile.gettempdir(), name)
    f.save(out)
    return out


# --------------------------------------------------------------------------
# font helpers
# --------------------------------------------------------------------------
def shaper(ttf_path):
    face = hb.Face(hb.Blob.from_file_path(ttf_path))
    font = hb.Font(face)

    def shape(text, features=None):
        buf = hb.Buffer()
        buf.add_codepoints([ord(c) for c in text])
        buf.guess_segment_properties()
        hb.shape(font, buf, features)
        return [i.codepoint for i in buf.glyph_infos]

    return shape


def feature_lookups(gsub, tag):
    for fr in gsub.FeatureList.FeatureRecord:
        if fr.FeatureTag == tag:
            return list(fr.Feature.LookupListIndex)
    return []


def extract_verdict_lookups(gsub, order):
    """Return (walker_lookup_index, chain_glyphs, accept_word, reject_word).

    The walker is the chain lookup in `calt` whose last subtable consumes
    guillemotright.  accept/reject words come from the rlig MultipleSubst.
    """
    guill = order.index("guillemotright")
    lookups = gsub.LookupList.Lookup

    walker = None
    chain = []
    for li in feature_lookups(gsub, "calt"):
        lk = lookups[li]
        if lk.LookupType != 6 or len(lk.SubTable) < 3:
            continue
        last = lk.SubTable[-1]
        if (last.InputGlyphCount == 1
                and last.InputCoverage[0].glyphs == ["guillemotright"]):
            walker = li
            chain = [st.InputCoverage[0].glyphs[0] for st in lk.SubTable[:-1]]
            break
    if walker is None:
        raise SystemExit("walker lookup not found")

    accept = reject = None
    for li in feature_lookups(gsub, "rlig"):
        lk = lookups[li]
        if lk.LookupType == 2:
            mp = lk.SubTable[0].mapping
            for k, v in mp.items():
                if k == "guillemotright":
                    reject = list(v)
                elif len(v) == 8:
                    accept = list(v)
    if accept is None or reject is None:
        raise SystemExit("verdict lookup not found")
    return walker, chain, accept, reject


def build_spy_font(ttf_path, gsub, drop):
    """Copy of the font with the final verdict/blanking lookups disabled,
    so the intermediate state glyphs survive shaping."""
    f = TTFont(ttf_path)
    g = f["GSUB"].table
    for fr in g.FeatureList.FeatureRecord:
        if fr.FeatureTag == "rlig":
            keep = [i for i in fr.Feature.LookupListIndex if i not in drop]
            fr.Feature.LookupListIndex = keep
            fr.Feature.LookupCount = len(keep)
    out = os.path.join(tempfile.gettempdir(), "ledger_spy.ttf")
    f.save(out)
    return out


# --------------------------------------------------------------------------
# recovering the key
# --------------------------------------------------------------------------
def recover_key(spy_shape, gdef_class, chain, target_ttf):
    """DFS over characters.  The transformed glyph for position i is final
    as soon as one character follows it, so each extension can be checked."""
    def state_glyphs(s):
        glyphs = spy_shape(OPEN + s + CLOSE)
        base = [g for g in glyphs if gdef_class(g) == 1]   # skip mark glyphs
        assert len(base) == len(s) + 2, (s, glyphs)
        return base[1:-1]                                  # drop « and »

    def matches(value, want):
        # 85 is the "walker matched here" marker substituted by the chain
        return value == want or value == 85

    level = [""]
    for depth in range(1, len(chain) + 1):
        nxt = []
        for prefix in level:
            for c in ALPHA:
                cand = prefix + c
                m = len(cand)
                if m >= 2:
                    st = state_glyphs(cand)
                    if not matches(st[m - 2], chain[m - 2]):
                        continue
                nxt.append(cand)
        level = nxt
        if not level:
            raise SystemExit("DFS died at depth %d" % depth)

    # verify every depth-25 candidate with the untouched font
    real = shaper(target_ttf)
    for cand in level:
        out = real(OPEN + cand + CLOSE)
        if out[-8:] == ACCEPT_WORD:
            return cand
    raise SystemExit("no candidate produced ACCEPTED")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "..", "challenges", "ligatures",
        "extracted", "ligatures-and-liabilities", "site")
    woff = find_woff(arg)
    ttf = make_ttf(woff, "ledger.ttf")

    font = TTFont(ttf)
    order = font.getGlyphOrder()
    gsub = font["GSUB"].table
    gdef = font["GDEF"].table.GlyphClassDef.classDefs

    def gdef_class(gid):
        return gdef.get(order[gid], 0)

    walker, chain, accept_names, reject_names = extract_verdict_lookups(gsub, order)
    chain = [order.index(n) for n in chain]
    ACCEPT_WORD = [order.index(n) for n in accept_names]
    print("[*] walker lookup: %d, key length: %d glyphs" % (walker, len(chain)))
    print("[*] ACCEPTED glyph run:", accept_names)

    # drop the verdict (MultipleSubst) and blanking (SingleSubst) lookups
    drop = set()
    for li in feature_lookups(gsub, "rlig"):
        lk = gsub.LookupList.Lookup[li]
        if lk.LookupType == 2 and "guillemotright" in lk.SubTable[0].mapping:
            drop.add(li)
        if lk.LookupType == 1 and set(lk.SubTable[0].mapping.values()) == {"glyph00146"}:
            drop.add(li)
    spy_ttf = build_spy_font(ttf, gsub, drop)
    spy_shape = shaper(spy_ttf)

    key = recover_key(spy_shape, gdef_class, chain, ttf)
    print("[+] licence key:", key)
    print("[+] flag: isfcr{%s}" % key)
