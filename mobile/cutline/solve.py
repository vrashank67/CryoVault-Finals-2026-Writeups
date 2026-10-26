import sqlite3,struct,time,sys,zipfile,tempfile
from pathlib import Path
P=65521
apk=Path(sys.argv[1] if len(sys.argv)>1 else 'cutline.apk')
with zipfile.ZipFile(apk) as z:
 data=z.read('assets/archive.db')
tmp=tempfile.TemporaryDirectory()
db=Path(tmp.name)/'archive.db'
db.write_bytes(data)
c=sqlite3.connect(db)
gates=[]; checks=[]
for fam,b in c.execute('select family,body from objects order by handle'):
 n=struct.unpack_from('<I',b,4)[0];a=struct.unpack_from('<'+'I'*n,b,8)
 if fam==0:gates.append((a[0]&3,a[0]>>2,a[1:5],*a[5:]))
 else:checks.append((a[:4],(a[4]&3,a[4]>>2),a[5:],struct.unpack_from('<192H',b,44)))
def transform(cut,skip):
 lim,omit,target,H=cut
 mat=[[int(i==j) for j in range(65)] for i in range(64)]
 clock=[0]*4;done=set()
 active=[g for g in gates if g[1]<=lim[g[0]]]
 while len(done)<len(active):
  progress=False
  for idx,(lane,seq,dep,dst,src,mul,add) in enumerate(active):
   if idx in done or any(clock[k]<dep[k] for k in range(4)):continue
   if not(skip and (lane,seq)==omit):mat[dst]=[(a+mul*b)%P for a,b in zip(mat[dst],mat[src])];mat[dst][-1]=(mat[dst][-1]+add)%P
   clock[lane]=seq;done.add(idx);progress=True
  assert progress
 rows=[]
 for j in range(3):
  row=[sum(H[j*64+i]*mat[i][k] for i in range(64))%P for k in range(65)]
  row[-1]=(target[j]-row[-1])%P
  rows.append(row)
 return rows
# Rows store 64 coefficients and right hand side.
def insert(basis,row):
 row=row[:]
 for p,b in sorted(basis.items()):
  q=row[p]
  if q:row=[(a-q*v)%P for a,v in zip(row,b)]
 p=next((i for i in range(64) if row[i]),None)
 if p is None:return row[-1]==0,basis
 inv=pow(row[p],-1,P);row=[v*inv%P for v in row]
 new=basis.copy();new[p]=row
 return True,new
base={}; branches=[]
for cut in checks:
 r0=transform(cut,False);r1=transform(cut,True)
 diff=[[(a-b)%P for a,b in zip(u,v)] for u,v in zip(r0,r1)]
 pivot=next((k for k in range(64) if any(r[k] for r in diff)),None)
 assert pivot is not None
 i=next(i for i in range(3) if diff[i][pivot]);di=diff[i][pivot]
 for j in range(3):
  if j==i:continue
  dj=diff[j][pivot]
  assert all((di*diff[j][k]-dj*diff[i][k])%P==0 for k in range(65))
  ok,base=insert(base,[(di*a-dj*b)%P for a,b in zip(r0[j],r0[i])]);assert ok
 branches.append((r0[i],r1[i]))
print('common rank',len(base),flush=True)
fullbase=base
free=[i for i in range(64) if i not in base]
def reduce(row):
 row=row[:]
 for p,b in sorted(fullbase.items()):
  q=row[p]
  if q:row=[(a-q*v)%P for a,v in zip(row,b)]
 return [row[i] for i in free]+[row[-1]]
branches=[tuple(reduce(row) for row in pair) for pair in branches]
def insert(basis,row):
 row=row[:]
 for p,b in sorted(basis.items()):
  q=row[p]
  if q:row=[(a-q*v)%P for a,v in zip(row,b)]
 p=next((i for i in range(len(free)) if row[i]),None)
 if p is None:return row[-1]==0,basis
 inv=pow(row[p],-1,P);row=[v*inv%P for v in row]
 new=basis.copy();new[p]=row
 return True,new
count=0;start=time.time()
def dfs(basis,remaining):
 global count
 count+=1
 if not remaining:
  if len(basis)!=len(free):return
  y=[0]*len(free)
  for p,b in sorted(basis.items(),reverse=True):y[p]=(b[-1]-sum(b[k]*y[k] for k in range(p+1,len(free))))%P
  x=[0]*64
  for k,v in zip(free,y):x[k]=v
  for p,b in sorted(fullbase.items(),reverse=True):x[p]=(b[-1]-sum(b[k]*x[k] for k in range(p+1,64)))%P
  for cut in checks:
   assert any(all(sum(row[k]*x[k] for k in range(64))%P==row[-1] for row in transform(cut,skip)) for skip in [False,True])
  print('All 24 checkpoint checks passed.',flush=True)
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  import hashlib
  receipt=c.execute('select body from receipt where slot=1').fetchone()[0]
  key=hashlib.sha256(b'cutline/recovery/v1\0'+struct.pack('<64H',*x)).digest()
  try:
   flag=AESGCM(key).decrypt(receipt[:12],receipt[12:],b'cutline/archive/v1')
   print('FLAG',flag,flush=True)
   print('Recovery code:', ''.join(f'{v:04x}' for v in x),flush=True)
   return x
  except Exception:print('bad auth',flush=True);return
 pair=remaining[0]
 for row in pair:
  ok,new=insert(basis,row)
  if ok:
   result=dfs(new,remaining[1:])
   if result:return result
result=dfs({},branches)
print('nodes',count,'seconds',time.time()-start)

c.close()
tmp.cleanup()
