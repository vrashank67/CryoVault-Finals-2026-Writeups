from recover import *
import numpy as np
T=np.zeros((256,256),dtype=np.uint8)
for a in range(256):
 for b in range(256):
  x=a;y=b;v=0
  while y:
   if y&1:v^=x
   x<<=1
   if x&256:x^=0x11d
   y>>=1
  T[a,b]=v
INV=[0]+[int(np.where(T[i]==1)[0][0]) for i in range(1,256)]
G=np.zeros((12,8),dtype=np.uint8);G[:8]=np.eye(8,dtype=np.uint8)
for r in range(4):
 for c in range(8):G[8+r,c]=INV[r^(c+4)]
def inv(A):
 A=np.concatenate((A.copy(),np.eye(8,dtype=np.uint8)),axis=1)
 for c in range(8):
  p=next(i for i in range(c,8) if A[i,c]);A[[c,p]]=A[[p,c]]
  A[c]=T[INV[A[c,c]],A[c]]
  for i in range(8):
   if i!=c and A[i,c]:A[i]^=T[A[i,c],A[c]]
 return A[:,8:]
def mul(A,B):return np.bitwise_xor.reduce(T[A[:,:,None],B[None,:,:]],axis=1)
def decode():
 cache=ROOT/'pack.pkl'
 if cache.exists():return pickle.loads(cache.read_bytes())
 stripes=collections.defaultdict(dict)
 for e,b in R['pack-member']:
  assert b[:8]==b'DSPPACK8'
  m,width,stride,rotation=struct.unpack_from('<IIII',b,24)
  assert (width,stride,rotation)==(128,19,5)
  for p in range(64,len(b),136):
   a=struct.unpack_from('<Q',b,p)[0];s,rem=divmod(a-7*m,19);assert rem==0
   stripes[s][(m-5*s)%12]=b[p+8:p+136]
 matrices={};decoded={};errors=0
 for s,obs in stripes.items():
  roles=tuple(sorted(obs));assert len(roles)==10
  data=np.array([list(obs[i]) for i in roles],dtype=np.uint8)
  if roles not in matrices:
   A=inv(G[list(roles[:8])]);H=np.concatenate((mul(G[list(roles[8:])],A),np.eye(2,dtype=np.uint8)),axis=1)
   matrices[roles]=(A,H)
  A,H=matrices[roles];syn=mul(H,data)
  if np.any(syn):
   bad=[i for i in range(10) if np.array_equal(T[H[0,i],syn[1]],T[H[1,i],syn[0]])]
   assert len(bad)==1,(s,bad)
   keep=[i for i in range(10) if i!=bad[0]][:8];rs=tuple(roles[i] for i in keep)
   if rs not in matrices:matrices[rs]=inv(G[list(rs)])
   D=mul(matrices[rs],data[keep]);errors+=1
  else:D=mul(A,data[:8])
  encoded=mul(G[list(roles)],D)
  assert sum(not np.array_equal(a,b) for a,b in zip(encoded,data))<=1
  decoded[s]=D.tobytes()
 print('decoded stripes',len(decoded),'corrected stale cells',errors,flush=True)
 mp=json.loads(R['pack-map'][0][1]);nodes=mp['nodes']
 if isinstance(nodes,list):nodes={n['id']:n for n in nodes}
 memo={}
 def node(h):
  if h in memo:return memo[h]
  n=nodes[h]
  if n['op']=='stripe':b=decoded[n['stripe']]
  elif n['op']=='concat':b=b''.join(node(x) for x in n['parts'])
  elif n['op']=='xor':b=bytes(x^y for x,y in zip(node(n['left']),node(n['right'])))
  else:raise ValueError(n)
  memo[h]=b;return b
 objects={o['key']:(o['path'],[node(h)[:o['size']] for h in o['roots']]) for o in mp['objects']}
 cache.write_bytes(pickle.dumps(objects));return objects
def replay(objects):
 groups={};processes={1:{}};paths={};group=None
 for e in map(json.loads,R['events'][0][1].splitlines()):
  pid=e['pid'];fds=processes[pid];op=e['op']
  if op=='publish':paths[e['path']]=e['key']
  elif op=='open':
   assert paths[e['path']]==e['key'];fds[e['fd']]=[e['key'],0]
  elif op in ('dup','dup2'):fds[e['dst']]=fds[e['src']]
  elif op=='fork':processes[e['child']]=fds.copy()
  elif op=='exit':del processes[pid]
  elif op=='close':del fds[e['fd']]
  elif op=='lseek':
   ofd=fds[e['fd']];new=e['offset']+([0,ofd[1],len(objects[ofd[0]][1][0])][e['whence']]);assert new==e['result'];ofd[1]=new
  elif op=='read':
   ofd=fds[e['fd']]
   if pid==1 and e['fd']==100 and e['requested']==24 and group is not None:
    key,offset=ofd;route=int(Path(objects[key][0]).stem);groups[group].append((route,key,offset))
   ofd[1]+=e['result']
  elif op=='begin':group=e['group'];groups[group]=[]
  elif op=='end':group=None
  else:raise ValueError(e)
 return groups
if __name__=='__main__':
 objects=decode();groups=replay(objects);(ROOT/'groups.pkl').write_bytes(pickle.dumps(groups))
 print('objects',len(objects),'groups',len(groups),'group lengths',collections.Counter(map(len,groups.values())))
