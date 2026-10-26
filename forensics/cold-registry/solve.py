#!/usr/bin/env python3
"""
COLD REGISTRY (CryoVault Finals, forensics) -- final solver.

The purged frostsync job leaf was rewritten for every segment transfer, so 72
abandoned leaves carry the job/<id>/cursor history. Two traps:

  1) the v0 ONDISK-NOTES layout is a decoy; the image is format v1 (16-byte cells,
     offsets from page end, CRC32C).
  2) fvregd restores its commit counter from a checkpoint on each watchdog restart.
     Every crash therefore leaves TWO complete cursor chains: the abandoned
     pre-crash fork and the recovered fork. Page epochs are only monotonic within
     one fork, and "referenced by a later-epoch root" can prefer the dead fork.

The live registry is the selection whose 48 cursor epochs are strictly increasing
in segment order. Same-epoch duplicates are broken by commit evidence (the page
carried by later trees); same-epoch ties with a one-transaction lifetime are
forced by the chain itself.

Run:  python solve.py
"""
import struct, os, hashlib, sys

PS = 4096
JOB = b"8149285a1114b9b0"
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
HERE = os.path.dirname(os.path.abspath(__file__))
REG = os.path.join(HERE, "challenge", "frost-n04-cold", "registry", "registry.fvr")


def main(img=REG):
    raw = open(img, "rb").read()
    n = len(raw) // PS
    if raw[:4] != b"FVR\x01":
        sys.exit("not a v1 registry image")

    # --- 1. recover every abandoned job cursor leaf -------------------------
    recs = []
    for pg in range(1, n):
        page = raw[pg*PS:(pg+1)*PS]
        pgid, epoch, kind, cc, crc = struct.unpack_from("<QQHHI", page, 0)
        if kind != 3 or cc != 4:
            continue
        q = page.find(b"/cursor")
        if q < 0:
            continue
        ks = page.rfind(b"job/", 0, q)
        if ks < 0 or q + 7 - ks != 27 or page[ks+4:ks+20] != JOB:
            continue
        if struct.unpack_from("<I", page, 32)[0] != 16:   # destroyed cell0 keeps voff
            continue
        seq, rcpt, rsv, ck, segid = struct.unpack("<IBBH8s", page[PS-16:PS])
        if 1 <= seq <= 48:
            recs.append(dict(pg=pg, epoch=epoch, seq=seq, rcpt=rcpt, segid=segid.hex()))

    if len({r['seq'] for r in recs}) != 48:
        sys.exit("incomplete cursor history")

    # --- 2. commit evidence: later-epoch index pages naming the leaf --------
    def index_children(pg):
        page = raw[pg*PS:(pg+1)*PS]
        cc = struct.unpack_from("<H", page, 18)[0]
        if not (1 <= cc <= 200) or 24 + cc*16 + 8 > PS:
            return None
        kids = []
        for i in range(1, cc):                      # entry 0 prefix is overwritten
            koff, ksize, pad, child = struct.unpack_from("<IHHQ", page, 24+i*16)
            if pad != 0 or not (0 < child < n):
                return None
            ka = PS - koff
            if not (0 <= ka and ka+ksize <= PS):
                return None
            kids.append(child)
        kids.append(struct.unpack_from("<Q", page, 24+cc*16)[0])
        return kids if all(0 < k < n for k in kids) else None

    from collections import defaultdict
    refs = defaultdict(list)
    for pg in range(1, n):
        kind = struct.unpack_from("<H", raw, pg*PS + 16)[0]
        if kind not in (1, 3):
            continue
        kids = index_children(pg)
        if not kids:
            continue
        epoch = struct.unpack_from("<Q", raw, pg*PS + 8)[0]
        for k in kids:
            refs[k].append(epoch)
    for r in recs:
        r['committed'] = any(e > r['epoch'] for e in refs.get(r['pg'], []))

    # --- 3. strictly increasing epoch chain, maximise committed evidence ----
    byseq = defaultdict(list)
    for r in recs:
        byseq[r['seq']].append(r)

    best = {}
    def solve(seq, last, chosen):
        nonlocal best
        if seq == 49:
            score = sum(1 for r in chosen if r['committed'])
            key = tuple((r['pg'], r['rcpt']) for r in chosen)
            if 'key' not in best or score > best['score']:
                best = dict(score=score, key=key, chosen=list(chosen))
            return
        for r in sorted(byseq[seq], key=lambda x: (not x['committed'], x['epoch'])):
            if r['epoch'] > last:
                solve(seq+1, r['epoch'], chosen + [r])
    solve(1, -1, [])
    if 'chosen' not in best:
        sys.exit("no monotonic chain found")
    vec = [r['rcpt'] for r in best['chosen']]

    # --- 4. release code ----------------------------------------------------
    msg = b"frostsync-release-v1" + bytes.fromhex(JOB.decode()) + bytes(vec)
    R = hashlib.sha256(msg).digest()
    bits = int.from_bytes(R[:8], "big") >> 4          # first 60 bits, big-endian
    digits = "".join(ALPHA[(bits >> (5*(11-i))) & 31] for i in range(12))
    code = f"FL-{digits[0:4]}-{digits[4:8]}-{digits[8:12]}"
    flag = "isfcr{" + code.lower().replace("-", "_") + "}"

    print("cursor pages recovered :", len(recs))
    print("epoch chain            :", best['chosen'][0]['epoch'], "->",
          best['chosen'][-1]['epoch'], "(strictly increasing:",
          all(best['chosen'][i]['epoch'] < best['chosen'][i+1]['epoch'] for i in range(47)), ")")
    print("receipts 1..48         :", " ".join(str(b) for b in vec))
    print("sha256                 :", R.hex())
    print("release code           :", code)
    print("FLAG:", flag)
    return flag


if __name__ == "__main__":
    main()
