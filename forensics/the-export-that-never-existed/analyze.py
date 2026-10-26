from recover import *
CHAINS=pickle.loads((ROOT/'chains.pkl').read_bytes())
CHAINS={s:max((seq for salt,seq in CHAINS if salt==s),key=len) for s,q in CHAINS}
SALTS=sorted(CHAINS)
base=R['image'][0][1]
initial={n+1:[base[n*1024:(n+1)*1024]] for n in range(len(base)//1024)}
for e,b in R['base-page']:
    pn=struct.unpack('<I',b[:4])[0]
    if pn not in initial or initial[pn]==[base[(pn-1)*1024:pn*1024]]:initial[pn]=[]
    if b[4:] not in initial[pn]:initial[pn].append(b[4:])
def overlay(pages,seq,n):
    out=pages.copy()
    for bs in seq[:n]:
        pn=struct.unpack_from('>I',bs[0])[0];out[pn]=[b[24:] for b in bs]
    return out
BASES={};p=initial
for s in SALTS:
    BASES[s]=p;p=overlay(p,CHAINS[s],len(CHAINS[s]))
def getpages(token):
    n=struct.unpack_from('<I',token,16)[0];salt=token[32:40]
    assert token[24:32]==struct.pack('<II',*struct.unpack('>II',CHAINS[salt][n-1][0][16:24]))
    return overlay(BASES[salt],CHAINS[salt],n)
def dbimage(pages,path):
    b=bytearray(max(pages)*1024)
    for pn,bs in pages.items():b[(pn-1)*1024:pn*1024]=bs[0]
    path.write_bytes(b);return sqlite3.connect(path)
receipt=bytes.fromhex(R['receipts'][0][1].decode().splitlines()[1].split('\t')[1])
finalpages=getpages(receipt)
db=dbimage(finalpages,ROOT/'final.sqlite')
pub=db.execute('select * from publication order by job,batch,stage').fetchall()
settle=db.execute('select * from settlement order by job,region').fetchall()
views={}
for e,b in R['arena']:
    assert zlib.crc32(b[:88])==struct.unpack_from('<I',b,88)[0]
    addr,gen,job,stage,batch=struct.unpack_from('<QIIII',b,8)
    views[(addr,gen)]=(job,stage,batch,b[32:80])
def tablepages(pages,root):
    out=[]
    def visit(pn):
        b=pages[pn][0];off=100 if pn==1 else 0
        if b[off]==13:out.append(pn);return
        assert b[off]==5,(pn,b[off])
        n=struct.unpack_from('>H',b,off+3)[0]
        for i in range(n):
            pos=struct.unpack_from('>H',b,off+12+2*i)[0];visit(struct.unpack_from('>I',b,pos)[0])
        visit(struct.unpack_from('>I',b,off+8)[0])
    visit(root);return out
if __name__=='__main__':
 print('tables',db.execute('select name,rootpage from sqlite_master').fetchall())
 print('pub target',[x for x in pub if x[0]==204]);print('settle target',[x for x in settle if x[0]==204])
 print('views')
 for job,batch,stage,addr,gen,meter in pub:
  if job==204:
   j,st,ba,tok=views[(addr,gen)];print(job,batch,stage,addr,gen,meter,'frame',struct.unpack_from('<I',tok,16)[0],'salt',tok[32:40].hex())
 print('pub count',len(pub),'settle',len(settle))
