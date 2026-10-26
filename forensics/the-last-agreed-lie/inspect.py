import hashlib
import json
import pathlib
import shutil
import sqlite3
import struct
import sys
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else pathlib.Path(tempfile.gettempdir())
sumfile = SOURCE/'SHA256SUMS'
if not sumfile.exists():sumfile=SOURCE/'SHA256SUMS (3)'
manifest = sumfile.read_text().splitlines()
sources = list(SOURCE.rglob('*.cjr')) + list(SOURCE.rglob('review*.db*'))
sources += [p for n in ['NOTICE.txt','main.cjs','product.json','R-184.json'] for p in SOURCE.rglob(n)]
by_hash = {hashlib.sha256(p.read_bytes()).hexdigest(): p for p in sources}
for line in manifest:
    h, name = line.split(None, 1)
    target = ROOT / 'evidence' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copyfile(by_hash[h], target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == h
print('All 22 evidence hashes verified')

dbs = []
for p in sorted((ROOT / 'evidence/profiles').glob('*/review.db')):
    # Query a disposable copy: never let SQLite checkpoint original evidence.
    d = ROOT / 'working' / p.parent.name
    d.mkdir(parents=True, exist_ok=True)
    for f in p.parent.glob('review.db*'):
        shutil.copyfile(f, d / f.name)
    con = sqlite3.connect(d / 'review.db')
    tables = con.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
    print('\nPROFILE', p.parent.name)
    obj = {'profile':p.parent.name,'tables':{}}
    for name, sql in tables:
        print(sql)
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{name}")')]
        rows = con.execute(f'SELECT * FROM "{name}"').fetchall()
        print('ROWS', len(rows), 'COLUMNS', cols)
        def pack(v):
            return {'hex':v.hex()} if isinstance(v,bytes) else v
        obj['tables'][name] = [dict(zip(cols,map(pack,r))) for r in rows]
        for row in rows[:3]:
            print([f'<bytes {len(v)} {v[:20].hex()}>' if isinstance(v,bytes) else v for v in row])
    con.close()
    dbs.append(obj)
(ROOT / 'databases.json').write_text(json.dumps(dbs,indent=2))

events = []
for p in sorted((ROOT / 'evidence/profiles').glob('*/journal/*.cjr')):
    b = p.read_bytes()
    assert b[:4] == b'CRJ3'
    print('JOURNAL HEADER',p.name,b[:16].hex())
    offset = 16
    count = 0
    while offset+4 <= len(b):
        size = struct.unpack_from('<I',b,offset)[0]
        if size<72 or offset+4+size>len(b):
            print('JOURNAL TRAILING',p.name,offset,len(b)-offset,size)
            break
        raw = b[offset+4:offset+4+size]
        if hashlib.sha256(raw[:-32]).digest()!=raw[-32:]:
            print('BAD CHECKSUM',p.name,offset)
            break
        item = {'profile':p.parent.parent.name,'file':p.name,'offset':offset,
                'stream':raw[:8].hex(),'previous':raw[8:40].hex(),
                'id':raw[-32:].hex(),'event':json.loads(zlib.decompress(raw[40:-32],-15))}
        events.append(item)
        offset += 4+size
        count += 1
    print('JOURNAL',p.parent.parent.name,p.name,'bytes',len(b),'records',count)
(ROOT/'events.json').write_text(json.dumps(events,indent=2))
print('EVENTS',len(events),'unique',len({e['id'] for e in events}))
from collections import Counter
print('OPS',Counter(e['event'][0] for e in events))
for e in events[:15]: print(e['stream'],e['event'])
