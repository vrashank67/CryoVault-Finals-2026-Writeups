"""Read-only access to a service recorder archive. Author: sr."""
import argparse, hashlib, sqlite3, zlib
from pathlib import Path
class Capture:
    def __init__(self,path):
        self.db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)
        self.db.row_factory=sqlite3.Row
    def entries(self):
        return [dict(x) for x in self.db.execute('SELECT * FROM entry ORDER BY id')]
    def read(self,ident):
        e=self.db.execute('SELECT * FROM entry WHERE id=?',(ident,)).fetchone()
        if e is None: raise KeyError(ident)
        out=bytearray()
        for r in self.db.execute('''SELECT b.digest,b.payload FROM extent x
             JOIN block b ON b.digest=x.digest WHERE x.entry_id=? ORDER BY x.ordinal''',(ident,)):
            b=zlib.decompress(r['payload'])
            if hashlib.sha256(b).digest()!=r['digest']: raise ValueError('block checksum')
            out+=b
        if len(out)!=e['length'] or hashlib.sha256(out).hexdigest()!=e['sha256']:
            raise ValueError('entry checksum')
        return bytes(out)
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('archive');a.add_argument('command',choices=['list','extract','all']);a.add_argument('id',nargs='?',type=int);a.add_argument('--out',default='extracted')
    v=a.parse_args();c=Capture(v.archive)
    if v.command=='list':
        for e in c.entries(): print(e['id'],e['sample'],e['kind'],e['length'],e['object_key'],e['name'])
    else:
        p=Path(v.out);p.mkdir(parents=True,exist_ok=True)
        ids=[v.id] if v.command=='extract' else [x['id'] for x in c.entries()]
        if None in ids: a.error('extract needs an entry ID')
        for i in ids: (p/f'{i:06d}.bin').write_bytes(c.read(i))
