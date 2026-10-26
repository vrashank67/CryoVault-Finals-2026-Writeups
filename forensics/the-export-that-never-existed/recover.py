import sys,struct,collections,pickle,hashlib,json,zlib,sqlite3,itertools,os
from pathlib import Path
ROOT=Path(os.environ['DISPATCH_WORK']).resolve();ROOT.mkdir(parents=True,exist_ok=True)
INPUT=Path(os.environ['DISPATCH_INPUT']).resolve()
from capture import Capture
C=Capture(INPUT/'dispatch.capture')
def load():
    cache=ROOT/'records.pkl'
    if cache.exists():return pickle.loads(cache.read_bytes())
    records=collections.defaultdict(list)
    for e in C.db.execute('select * from entry group by kind,sha256'):
        records[e['kind']].append((dict(e),C.read(e['id'])))
    cache.write_bytes(pickle.dumps(dict(records)))
    return records
R=load()
def varint(b,p):
    v=0
    for i in range(9):
        x=b[p];p+=1
        if i==8:return (v<<8)|x,p
        v=(v<<7)|(x&127)
        if x<128:return v,p
def record(b):
    h,p=varint(b,0);types=[]
    while p<h:
        t,p=varint(b,p);types.append(t)
    p=h;values=[]
    for t in types:
        if t==0:v=None;n=0
        elif t in (8,9):v=t-8;n=0
        elif 1<=t<=6:
            n=[0,1,2,3,4,6,8][t];v=int.from_bytes(b[p:p+n],'big',signed=True)
        elif t==7:n=8;v=struct.unpack('>d',b[p:p+8])[0]
        elif t>=12:
            n=(t-12)//2;v=b[p:p+n];v=v.decode('utf8') if t&1 else v
        else:raise ValueError(t)
        values.append(v);p+=n
    return values
def cells(page,pn=0):
    off=100 if pn==1 else 0
    if page[off]!=13:return None
    n=struct.unpack_from('>H',page,off+3)[0];out=[]
    for i in range(n):
        pos=struct.unpack_from('>H',page,off+8+2*i)[0]
        length,pos=varint(page,pos);rowid,pos=varint(page,pos)
        out.append((rowid,record(page[pos:pos+length])))
    return out
MASK=0xffffffff
def checksum(b,st=(0,0),endian='<'):
    a,c=st
    for x,y in struct.iter_unpack(endian+'II',b):
        a=(a+x+c)&MASK;c=(c+y+a)&MASK
    return a,c
def previous(b,st,endian='<'):
    a,c=st
    pairs=list(struct.iter_unpack(endian+'II',b))
    for x,y in reversed(pairs):
        c=(c-y-a)&MASK;a=(a-x-c)&MASK
    return a,c
def walchains():
    graph=collections.defaultdict(lambda:collections.defaultdict(lambda:collections.defaultdict(list)))
    for e,b in R['wal-frame']:
        salt=b[8:16];final=struct.unpack('>II',b[16:24])
        prev=previous(b[:8]+b[24:],final)
        graph[salt][prev][final].append(b)
    allchains=[]
    for e,h in sorted(R['wal-header'],key=lambda x:x[0]['sample']):
        salt=h[16:24];state=struct.unpack('>II',h[24:32])
        print('header',salt.hex(),'valid',checksum(h[:24])==state,flush=True)
        chains=[([],state)]
        while True:
            new=[]
            for seq,st in chains:
                choices=graph[salt].get(st,{})
                if not choices:
                    allchains.append((salt,seq));continue
                for final,bs in choices.items():new.append((seq+[bs],final))
            if not new:break
            chains=new
            if len(chains)>100:raise ValueError(('many chains',len(chains)))
        print('chains',[(len(q),struct.unpack('>II',q[-1][0][16:24]) if q else None) for s,q in allchains if s==salt],flush=True)
    (ROOT/'chains.pkl').write_bytes(pickle.dumps(allchains))
    return allchains
if __name__=='__main__':
    print('unique records',{k:len(v) for k,v in R.items()},flush=True)
    walchains()
