#!/usr/bin/env python3
"""
NO SUCH REVISION - CryoVault Finals 2026 (forensics)

Recovers the label printed for job 6C19 from a live SQLite acquisition of
three Atelier bridge nodes.

Pipeline
  1. Extract the supplied zip (client application + three store.sqlite files
     and their -wal sidecars).
  2. Recover every historical row version from the WAL by rebuilding the
     database image at every commit frame.  (Reading the stores with sqlite3
     would checkpoint and destroy the WAL, so the originals are never opened.)
  3. Rebuild the per-node journal chains (take order) with the transport table
     (message ref -> object digest).
  4. Resolve the catalog lookup for job 6C19 exactly like core.mjs
     resolveCatalog(): namespace 6e1732..., cut 1, parent cuts pinned at 14.
  5. Rebuild the Yjs board at the print state from the recovered state
     checkpoint (codec 2) with an empty delete set, then replay the
     delete-only journal messages to recover the exact display list that each
     cached catalog revision points at.  Each rebuilt display list is checked
     against the on-disk SHA-256 digest from the catalog.
  6. Render the label like core.mjs svg(), decode the 7-segment glyph grid and
     print the flag.

Requires: Python 3.9+, Node.js (the client bundle ships yjs in node_modules).
"""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CHAL = os.path.join(ROOT, 'challenges', 'no-such-revision')
ZIP = os.path.join(CHAL, 'input', 'no-such-revision.zip')
WORK = os.path.join(CHAL, 'work')


# --------------------------------------------------------------------------
# 1. extract
# --------------------------------------------------------------------------
def extract():
    # unique per-run directory so concurrent work cannot race on extraction
    os.makedirs(WORK, exist_ok=True)
    src = tempfile.mkdtemp(prefix='run-', dir=WORK)
    with zipfile.ZipFile(ZIP) as z:
        z.extractall(src)
    base = os.path.join(src, 'no-such-revision')
    for node in ('node-a', 'node-b', 'node-c'):
        db = os.path.join(base, 'evidence', node, 'store.sqlite')
        for attempt in range(3):
            if os.path.exists(db):
                break
            time.sleep(0.2)
        if not os.path.exists(db):
            raise RuntimeError('missing store: ' + db)
    print('[+] extracted to', base)
    return base


# --------------------------------------------------------------------------
# 2. WAL row recovery
# --------------------------------------------------------------------------
def parse_wal(path):
    data = open(path, 'rb').read()
    if data[:4] not in (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83'):
        return None
    page_size = struct.unpack('>I', data[8:12])[0]
    if page_size == 1:
        page_size = 65536
    salt1, salt2 = struct.unpack('>II', data[16:24])
    frames, off = [], 32
    while off + 24 + page_size <= len(data):
        pgno, dbsize, s1, s2, c1, c2 = struct.unpack('>IIIIII', data[off:off + 24])
        if s1 != salt1 or s2 != salt2:
            break
        frames.append((pgno, dbsize, data[off + 24: off + 24 + page_size]))
        off += 24 + page_size
    return page_size, frames


def build_image(dbfile, frames, page_size):
    raw = open(dbfile, 'rb').read()
    npages = max(struct.unpack('>I', raw[28:32])[0], len(raw) // page_size)
    img = {i + 1: raw[i * page_size:(i + 1) * page_size] for i in range(npages)}
    maxpg = npages
    for pgno, dbsize, payload in frames:
        img[pgno] = payload
        maxpg = max(maxpg, pgno)
    out = bytearray()
    for i in range(1, maxpg + 1):
        out += img.get(i, b'\x00' * page_size)[:page_size].ljust(page_size, b'\x00')
    out[28:32] = struct.pack('>I', maxpg)
    return bytes(out)


def recover_rows(base):
    """Return {table: [row dicts]} containing every row version ever committed."""
    seen, rows = {}, {}
    for node in ('node-a', 'node-b', 'node-c'):
        dbfile = os.path.join(base, 'evidence', node, 'store.sqlite')
        wal = dbfile + '-wal'
        if not os.path.exists(wal):
            continue
        parsed = parse_wal(wal)
        if not parsed:
            continue
        page_size, frames = parsed
        commits = [i + 1 for i, f in enumerate(frames) if f[1] != 0]
        print('[+] %s: %d wal frames, %d commits' % (node, len(frames), len(commits)))
        for nf in commits:
            img = build_image(dbfile, frames[:nf], page_size)
            fd, tmp = tempfile.mkstemp(suffix='.db')
            os.write(fd, img)
            os.close(fd)
            try:
                con = sqlite3.connect(tmp)
                tables = [r[0] for r in con.execute(
                    "select name from sqlite_master where type='table'")]
                for t in tables:
                    cur = con.execute('select * from "%s"' % t)
                    cols = [d[0] for d in cur.description]
                    for row in cur:
                        d = dict(zip(cols, row))
                        d['_node'] = node
                        key = tuple(sorted((k, repr(v)) for k, v in d.items()))
                        if key not in seen.setdefault((node, t), set()):
                            seen[(node, t)].add(key)
                            rows.setdefault(t, []).append(d)
                con.close()
            finally:
                os.unlink(tmp)
    return rows


# --------------------------------------------------------------------------
# 3. catalog / journal / transport helpers
# --------------------------------------------------------------------------
def zjson(b):
    return json.loads(zlib.decompress(b))


def journal_chains(rows):
    chains = []
    for node in ('node-a', 'node-b', 'node-c'):
        js = [r for r in rows.get('journal', []) if r['_node'] == node]
        by_h = {r['h']: r for r in js}
        child = {}
        for r in js:
            child.setdefault(r['prev'], []).append(r['h'])
        for root in [r['h'] for r in js if r['prev'] == '0' * 64]:
            seq, cur = [], root
            while cur in by_h:
                seq.append(by_h[cur])
                nxt = child.get(cur, [])
                if len(nxt) != 1:
                    break
                cur = nxt[0]
            if len(seq) > 1:
                chains.append((node, seq))
    return chains


def transport_map(rows):
    m = {}
    for r in rows.get('transport', []):
        m[(r['boot'], r['host'], r['session'], r['number'])] = r['digest']
    return m


def resolve_catalog(namespaces, rows, name, cut, gid, key, seen=None):
    seen = set() if seen is None else set(seen)
    token = (name, cut, gid)
    if token in seen:
        raise RuntimeError('catalog cycle')
    seen.add(token)
    cand = [r for r in rows
            if r['ns'] == name and r['rev'] <= cut and r['gid'] == gid and r['key'] == key]
    if cand:
        return max(cand, key=lambda r: r['rev'])
    ns = namespaces.get(name)
    if ns is None:
        raise RuntimeError('namespace missing: ' + name)
    for p in reversed(ns):
        if p['groups'] is not None and gid not in p['groups']:
            continue
        r = resolve_catalog(namespaces, rows, p['name'], p['cut'], gid, key, seen)
        if r is not None:
            return r
    return None


# --------------------------------------------------------------------------
# 4. node worker: rebuild display lists at their cached revision
# --------------------------------------------------------------------------
NODE_WORKER = r"""
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import * as Y from 'yjs';

const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const obj = d => fs.readFileSync(path.join(cfg.objects, d));

function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const pack = v => zlib.deflateSync(Buffer.from(canonical(v)), { level: 9 });

function compile(doc, gid, view) {
  const g = doc.getMap('board').get('groups').get(gid);
  const matrix = g.get('matrix');
  const paths = g.get('paths');
  const [a, b, c, d, e, f] = matrix;
  const project = (x, y) => [Math.round((a * x + c * y + e) * 1024) / 1024,
                             Math.round((b * x + d * y + f) * 1024) / 1024];
  const lines = paths.toArray().map(p => {
    const q = p.p;
    return [...project(q[0], q[1]), ...project(q[2], q[3]), p.w];
  });
  return { abi: 3, view, lines };
}

const wanted = new Map(cfg.wanted.map(d => [d.slice(0, 8), d]));
const found = new Map();
let usedCheckpoint = null, order = null;

for (const ck of cfg.checkpoints) {
  if (!fs.existsSync(path.join(cfg.objects, ck))) continue;
  const full = new Y.Doc({ gc: false });
  Y.applyUpdate(full, obj(ck));
  // insertion-only board at the print state: full state vector, empty delete set
  const sv = Y.decodeStateVector(Y.encodeStateVector(full));
  const base = Y.encodeStateAsUpdate(
    Y.createDocFromSnapshot(full, new Y.Snapshot(Y.createDeleteSet(), sv)));
  const doc = new Y.Doc({ gc: false });
  Y.applyUpdate(doc, base);
  found.clear();
  const msgKinds = cfg.chain.map(dg => {
    // evicted message objects are insertions already contained in the checkpoint
    if (!fs.existsSync(path.join(cfg.objects, dg))) return 'missing';
    const u = Y.decodeUpdate(obj(dg));
    return (u.structs.length === 0 && u.ds.clients.size > 0) ? 'del' : 'ins';
  });
  for (let p = -1; p < cfg.chain.length; p++) {
    if (p >= 0 && msgKinds[p] === 'del') Y.applyUpdate(doc, obj(cfg.chain[p]));
    for (const gid of cfg.groups) {
      const list = compile(doc, gid, cfg.view);
      const dg = sha(pack(list));
      const pre = dg.slice(0, 8);
      if (wanted.has(pre) && !found.has(pre)) found.set(pre, { digest: dg, gid, list, pos: p });
    }
  }
  if ([...wanted.keys()].every(k => found.has(k))) {
    usedCheckpoint = ck;
    break;
  }
}

const out = [];
for (const gid of cfg.groups) {
  const hit = [...found.values()].find(v => v.gid === gid && wanted.has(v.digest.slice(0, 8)));
  if (!hit) { console.log('missing display list for', gid); process.exit(1); }
  out.push(hit.list);
}
fs.writeFileSync(cfg.out, JSON.stringify(out));
console.log('[+] checkpoint', usedCheckpoint ? usedCheckpoint.slice(0, 12) : '?',
              'display lists', out.map(l => l.lines.length).join(','));
"""


# --------------------------------------------------------------------------
# 5. label decoding (7-segment hex font on a 20x22 lattice)
# --------------------------------------------------------------------------
YLINES = [35, 57, 79, 105, 127, 149, 175, 197, 219, 245, 267, 289]

SEGCHARS = {
    frozenset('T B UL LL UR LR'.split()): '0',
    frozenset('UR LR'.split()): '1',
    frozenset('T M UR LL B'.split()): '2',
    frozenset('T M UR LR B'.split()): '3',
    frozenset('UL UR M LR'.split()): '4',
    frozenset('T UL M LR B'.split()): '5',
    frozenset('T UL M LL LR B'.split()): '6',
    frozenset('T UR LR'.split()): '7',
    frozenset('T B UL LL UR LR M'.split()): '8',
    frozenset('T UL UR M LR B'.split()): '9',
    frozenset('T UL UR M LL LR'.split()): 'A',
    frozenset('UL M LL LR B'.split()): 'b',
    frozenset('T UL LL B'.split()): 'C',
    frozenset('UR M LL LR B'.split()): 'd',
    frozenset('T UL M LL B'.split()): 'E',
    frozenset('T UL M LL'.split()): 'F',
}
LOWER = {'A': 'a', 'C': 'c', 'E': 'e', 'F': 'f', 'b': 'b', 'd': 'd'}


def decode_label(lists):
    lines = [ln for l in lists for ln in l['lines']]
    H, V = set(), set()
    for (a, b, c, d, w) in lines:
        if b == d:
            H.add((round((a + c) / 2), YLINES.index(round(b))))
        else:
            yi = min(range(len(YLINES) - 1), key=lambda i: abs(YLINES[i] - (min(b, d) - 3)))
            V.add((round(a), yi))

    rows = []
    for band in range(4):
        yt, ym, yb = 3 * band, 3 * band + 1, 3 * band + 2
        row = ''
        for k in range(16):
            x0 = 40 + 40 * k
            seg = set()
            if (x0 + 10, yt) in H: seg.add('T')
            if (x0 + 10, ym) in H: seg.add('M')
            if (x0 + 10, yb) in H: seg.add('B')
            if (x0, yt) in V: seg.add('UL')
            if (x0, ym) in V: seg.add('LL')
            if (x0 + 20, yt) in V: seg.add('UR')
            if (x0 + 20, ym) in V: seg.add('LR')
            ch = SEGCHARS.get(frozenset(seg))
            if ch is None:
                raise RuntimeError('unreadable glyph at row %d col %d: %s' % (band, k, sorted(seg)))
            row += ch
        rows.append(row)
    code = ''.join(LOWER.get(ch, ch) for row in rows for ch in row)
    return rows, code


def svg_from_lists(lists):
    view = lists[0]['view']
    parts = []
    for l in lists:
        for (a, b, c, d, w) in l['lines']:
            parts.append('<path d="M %s %s L %s %s" stroke-width="%s"/>' % (a, b, c, d, w))
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">'
            '<rect width="100%%" height="100%%" fill="white"/>'
            '<g stroke="#171717" stroke-linecap="round" fill="none">%s</g></svg>'
            % (view[0], view[1], view[0], view[1], ''.join(parts)))


# --------------------------------------------------------------------------
def main():
    base = extract()
    outdir = base + '-out'
    os.makedirs(outdir, exist_ok=True)
    rows = recover_rows(base)

    # dedupe catalog across nodes, keep full rows
    catalog = []
    seen = set()
    for r in rows.get('catalog', []):
        key = (r['ns'], r['rev'], r['gid'], r['key'], r['digest'], r['producer'])
        if key not in seen:
            seen.add(key)
            catalog.append({'ns': r['ns'], 'rev': r['rev'], 'gid': r['gid'],
                            'key': r['key'], 'digest': r['digest']})
    print('[+] catalog rows recovered:', len(catalog))

    namespaces = {}
    for r in rows.get('namespaces', []):
        namespaces[r['name']] = zjson(r['parents'])

    jobs = {}
    for r in rows.get('jobs', []):
        jobs[r['id']] = zjson(r['receipt'])
    job = jobs['6C19']
    print('[+] job 6C19:', job['ns'][:8], 'cut', job['cut'], 'groups', len(job['groups']))

    # raw object store (dedupe by digest)
    objdir = os.path.join(outdir, 'objects')
    os.makedirs(objdir, exist_ok=True)
    object_digests = set()
    for r in rows.get('objects', []):
        dg = r['digest']
        if dg in object_digests:
            continue
        if hashlib.sha256(r['content']).hexdigest() != dg:
            raise RuntimeError('object digest mismatch')
        object_digests.add(dg)
        open(os.path.join(objdir, dg), 'wb').write(r['content'])
    print('[+] object store:', len(object_digests), 'objects')

    # catalog lookup: the key is determined by the print-time board state
    key_by_gid = {}
    for r in catalog:
        key_by_gid.setdefault(r['gid'], r['key'])

    wanted, chosen = [], []
    for gid in job['groups']:
        hit = resolve_catalog(namespaces, catalog, job['ns'], job['cut'],
                              gid, key_by_gid[gid])
        if hit is None:
            raise RuntimeError('no catalog entry for ' + gid)
        wanted.append(hit['digest'])
        chosen.append((gid, hit))
        print('    %s -> rev %-3d %s' % (gid[:8], hit['rev'], hit['digest'][:12]))

    # journal chain + message digests
    chains = journal_chains(rows)
    tmap = transport_map(rows)
    chain = None
    for node, seq in chains:
        digests = []
        for j in seq:
            ref = zjson(j['body'])['ref']
            digests.append(tmap[(ref['boot'], ref['host'], ref['session'], ref['number'])])
        if len(digests) == max(len(s) for _, s in chains):
            chain = digests
            break
    if chain is None:
        raise RuntimeError('could not rebuild a complete message chain')
    print('[+] journal chain:', len(chain), 'takes')

    checkpoints = [r['digest'] for r in rows.get('checkpoints', [])
                   if r['digest'] in object_digests]
    checkpoints = sorted(set(checkpoints), key=lambda d: -os.path.getsize(os.path.join(objdir, d)))

    cfg = {
        'objects': objdir,
        'checkpoints': checkpoints,
        'chain': chain,
        'groups': job['groups'],
        'view': job['view'],
        'wanted': wanted,
        'out': os.path.join(outdir, 'label.json'),
    }
    cfg_path = os.path.join(outdir, 'node_cfg.json')
    json.dump(cfg, open(cfg_path, 'w'))

    client = os.path.join(base, 'client')
    worker = os.path.join(client, '_recover_label.mjs')
    open(worker, 'w').write(NODE_WORKER)
    subprocess.run(['node', worker, cfg_path], cwd=client, check=True)

    lists = json.load(open(cfg['out']))
    svg = svg_from_lists(lists)
    open(os.path.join(outdir, 'label.svg'), 'w').write(svg)
    rows_txt, code = decode_label(lists)
    for i, r in enumerate(rows_txt):
        print('    row%d: %s' % (i + 1, r))
    print('[+] label code:', code)
    print()
    print('isfcr{%s}' % code)


if __name__ == '__main__':
    main()
