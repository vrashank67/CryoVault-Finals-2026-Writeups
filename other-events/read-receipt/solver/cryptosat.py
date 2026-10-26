import sys, json, collections, hashlib
sys.path.insert(0,'crypto')
import rrlib
import pycryptosat

j=rrlib.load_catalog(3)[3]; rows=j['rows']
recs=json.load(open('pages.json'))
pool=collections.defaultdict(list); seen=collections.defaultdict(set)
for r in recs:
    k=(r['chip'],r['slot'],r['cycle'])
    if r['payload'] not in seen[k]:
        seen[k].add(r['payload']); pool[k].append(bytes.fromhex(r['payload']))
for k in pool: pool[k].sort()
cands=[pool[tuple(r['at'])] for r in rows]
syms=rrlib.catalog_symbol_order(j); n=len(syms); idx={s:i for i,s in enumerate(syms)}
A=[[0]*n for _ in range(len(rows))]
for i,r in enumerate(rows):
    for s,c in r['terms']: A[i][idx[s]]=c
AT=[[A[i][k] for i in range(len(rows))] for k in range(n)]
def rref(M,ncols):
    M=[row[:] for row in M]; mm=len(M); r0=0; piv=[]
    for col in range(ncols):
        p=None
        for rr in range(r0,mm):
            if M[rr][col]: p=rr; break
        if p is None: continue
        M[r0],M[p]=M[p],M[r0]
        inv=rrlib.gf_inv(M[r0][col])
        if inv!=1: M[r0]=[rrlib.gf_mul(x,inv) for x in M[r0]]
        for rr in range(mm):
            if rr!=r0 and M[rr][col]:
                f=M[rr][col]; M[rr]=[rrlib.gf_add(a,rrlib.gf_mul(f,b)) for a,b in zip(M[rr],M[r0])]
        piv.append(col); r0+=1
        if r0==mm: break
    return M,piv
R,piv=rref(AT,len(rows))
free=[cc for cc in range(len(rows)) if cc not in piv]
H=[]
for fc in free:
    vv=[0]*len(rows); vv[fc]=1
    for rr,pc in enumerate(piv): vv[pc]=R[rr][fc]
    H.append(vv)
d0=[cands[0][1][t]^cands[0][0][t] for t in range(1024)]
nz=[t for t in range(1024) if d0[t]]
inv=rrlib.gf_inv(d0[nz[0]])
V=[rrlib.gf_mul(x,inv) for x in d0]
t0=next(t for t in range(1024) if V[t])
a=[rrlib.gf_div(cands[i][1][t0]^cands[i][0][t0],V[t0]) for i in range(len(rows))]
c=[rrlib.gf_div(cands[i][2][t0]^cands[i][0][t0],V[t0]) for i in range(len(rows))]
w=[]
for k in range(len(H)):
    s=0
    for i in range(len(rows)): s^=rrlib.gf_mul(H[k][i],cands[i][0][t0])
    w.append(rrlib.gf_div(s,V[t0]))

solver=pycryptosat.Solver()
for i in range(len(rows)):
    solver.add_clause([-(2*i+1), -(2*i+2)])   # not (b1 and b2)
nclauses=0
for k in range(len(H)):
    for bit in range(8):
        vs=[]
        for i in range(len(rows)):
            coef1=rrlib.gf_mul(H[k][i],a[i]); coef2=rrlib.gf_mul(H[k][i],c[i])
            if (coef1>>bit)&1: vs.append(2*i+1)
            if (coef2>>bit)&1: vs.append(2*i+2)
        rhs=bool((w[k]>>bit)&1)
        solver.add_xor_clause(vs, rhs)
        nclauses+=1
print('clauses',nclauses,'vars',2*len(rows))
sat,sol=solver.solve()
print('sat',sat)
if sat:
    b1=[bool(sol[2*i+1]) for i in range(len(rows))]
    b2=[bool(sol[2*i+2]) for i in range(len(rows))]
    print('b1',sum(b1),'b2',sum(b2),'both',sum(1 for i in range(len(rows)) if b1[i] and b2[i]))
    sel=[]
    for i in range(len(rows)):
        if b1[i]: sel.append(cands[i][1])
        elif b2[i]: sel.append(cands[i][2])
        else: sel.append(cands[i][0])
    red=rrlib.ByteRowReducer(A)
    print('consistent',red.is_consistent(sel))
    solx=red.solve(sel); X=solx.particular
    stream=b''.join(bytes(X[idx[sy]]) for sy in j['stream']['symbols'])[:j['stream']['bytes']]
    print('sha256',hashlib.sha256(stream).hexdigest())
    print('expect',j['stream']['sha256'])
    if hashlib.sha256(stream).hexdigest()==j['stream']['sha256']:
        open('stream.bin','wb').write(stream)
        json.dump({'b1':[int(x) for x in b1],'b2':[int(x) for x in b2]},open('selection.json','w'))
        print('STREAM WRITTEN')
