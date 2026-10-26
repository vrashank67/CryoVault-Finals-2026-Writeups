from pathlib import Path
import ctypes as C,json,struct,hashlib
b=Path(__file__).resolve().parent
libpath=(b/'rootfs/srv/ledger/libservice.so').resolve();lib=C.CDLL(str(libpath))
base=None
for line in Path('/proc/self/maps').read_text().splitlines():
 if str(libpath) in line and line.split()[2]=='00000000':base=int(line.split('-')[0],16)
assert base
lib.sqlite3_open.argtypes=[C.c_char_p,C.POINTER(C.c_void_p)];lib.sqlite3_open.restype=C.c_int
snaps=json.loads((b/'snapshots.json').read_text());cons={};handles=[]
for key,s in snaps.items():
 path=b/'snapshots'/s['path'].replace('\\','/').split('/')[-1]
 handle=C.c_void_p();assert lib.sqlite3_open(str(path).encode(),C.byref(handle))==0
 cons[int(key)]=handle;handles.append(handle)
contexts=json.loads((b/'contexts.json').read_text())
native=C.CFUNCTYPE(None,C.POINTER(C.c_void_p),C.c_int,C.c_int,C.c_longlong,C.c_longlong,C.c_longlong,C.c_int)(base+0xde20)
lib.sqlite3_prepare_v2.argtypes=[C.c_void_p,C.c_char_p,C.c_int,C.POINTER(C.c_void_p),C.c_void_p]
lib.sqlite3_bind_int64.argtypes=[C.c_void_p,C.c_int,C.c_longlong]
lib.sqlite3_step.argtypes=[C.c_void_p];lib.sqlite3_column_int.argtypes=[C.c_void_p,C.c_int]
lib.sqlite3_finalize.argtypes=[C.c_void_p]
count=C.c_int.from_address(base+0xfc840);buf=(C.c_longlong*(5*256)).from_address(base+0xfc860)
rows=[]
for f in json.loads((b/'entries.json').read_text()):
 if not f['eligible']:continue
 con=contexts[f['thread']];r=cons[con['r']];p=cons[con['p']]
 stmt=C.c_void_p();assert lib.sqlite3_prepare_v2(r,b'SELECT root,enabled FROM bindings WHERE slot=?1',-1,C.byref(stmt),None)==0
 assert lib.sqlite3_bind_int64(stmt,1,f['ordinal'])==0;assert lib.sqlite3_step(stmt)==100
 root=lib.sqlite3_column_int(stmt,0);en=lib.sqlite3_column_int(stmt,1);lib.sqlite3_finalize(stmt)
 count.value=0
 if en:native((C.c_void_p*2)(r,p),root,0,f['amount'],f['high'],f['low'],0)
 for i in range(count.value):
  pos,acct,hi,lo,cents=buf[i*5:i*5+5]
  rows.append((f['ordinal'],pos,acct,hi&((1<<64)-1),lo&((1<<64)-1),cents))
rows.sort();expected=[tuple(r) for r in json.loads((b/'rows.json').read_text())]
assert rows==expected,[(a,b) for a,b in zip(rows,expected) if a!=b][:5]
data=b'FLD2'+struct.pack('>I',len(rows))+b''.join(struct.pack('>IIQQQq',*r) for r in rows)
assert data==(b.parent/'outputs/closing.fld').read_bytes()
print('Native library independently reproduced all',len(rows),'rows and all',len(data),'bytes. SHA256',hashlib.sha256(data).hexdigest())
