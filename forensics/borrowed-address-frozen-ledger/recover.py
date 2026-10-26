from coremem import Core,b
import json,re,struct,sqlite3,hashlib,collections
c=Core();objs=json.loads((b/'objects.json').read_text());books=[o for o in objs if o['class']=='ledger/Service$Book'];bookmap={int(o['oid'],16):i for i,o in enumerate(books)}
contexts=json.loads((b/'contexts.json').read_text());snaps=json.loads((b/'snapshots.json').read_text())
chunks=[o['tail'] for o in objs if o.get('tail')]
frames=[];thread=-1;depth=0
for line in (b/'sa.log').read_text().splitlines():
 if line.startswith('CHUNK '):thread+=1;depth=0
 m=re.match(r'FRAME (0x\w+) pc (0x\w+) (\w+) size (\d+)',line)
 if not m:continue
 sp=int(m[1],16)+32;method=m[3]
 book=c.u64(sp+16);bi=bookmap[book];assert bi==thread
 debit={'account':c.u32(sp+12),'high':c.u64(sp+24),'low':c.u64(sp+32),'cents':struct.unpack('<q',c.read(sp+48,8))[0]}
 credit={'account':c.u32(sp+44),'high':c.u64(sp+56),'low':c.u64(sp+64),'cents':struct.unpack('<q',c.read(sp+72,8))[0]}
 authority=debit if method in ['debit','reverse'] else credit
 ordinal=bi*16+depth
 assert ['debit','credit','amend','reverse'][(bi+depth)%4]==method
 assert abs(debit['cents'])<=10000000 and abs(credit['cents'])<=10000000
 eligible=books[bi]['request']==731 and authority['account']==books[bi]['current']
 amount=authority['cents']*(1 if authority is debit else -1)
 frames.append(dict(thread=bi,depth=depth,ordinal=ordinal,method=method,book=book,sp=sp,debit=debit,credit=credit,eligible=eligible,amount=amount,high=authority['high'],low=authority['low']))
 depth+=1
assert len(frames)==sum(4+i%4 for i in range(16))==88
for i in range(16):assert sum(f['thread']==i for f in frames)==4+i%4
(b/'entries.json').write_text(json.dumps(frames,indent=2))
def trunc(n,d):return (abs(n)//d)*(-1 if n<0 else 1)
def settle(f):
 con=contexts[f['thread']]
 r=sqlite3.connect(snaps[str(con['r'])]['path']);p=sqlite3.connect(snaps[str(con['p'])]['path'])
 root,enabled=r.execute('select root,enabled from bindings where slot=?',(f['ordinal'],)).fetchone()
 out=[]
 def visit(node,pos,amount):
  edges=r.execute('select position,child,weight from edges where parent=? order by position',(node,)).fetchall()
  if edges:
   left=amount;den=sum(e[2] for e in edges)
   for i,(ep,ch,w) in enumerate(edges):
    part=left if i==len(edges)-1 else trunc(amount*w,den);left-=part
    visit(ch,pos*16+ep+1,part)
  else:
   account,product=r.execute('select account,product from terminals where node=?',(node,)).fetchone()
   num,den,fee,mode,en=p.execute('select numerator,denominator,fee,rounding,enabled from tariffs where product=?',(product,)).fetchone()
   if not en:return
   n=amount*num;q=trunc(n,den);rem=n-q*den
   if rem:
    if mode==0:q-=n<0
    elif mode==1:q+=n>0
    elif abs(rem)*2>den or (abs(rem)*2==den and q%2):q+=(-1 if n<0 else 1)
   out.append((f['ordinal'],pos,account,f['high'],f['low'],q-fee))
 if enabled:visit(root,0,f['amount'])
 return out
rows=[]
for f in frames:
 if f['eligible']:rows.extend(settle(f))
rows.sort()
assert len({(r[0],r[1]) for r in rows})==len(rows)
data=b'FLD2'+struct.pack('>I',len(rows))+b''.join(struct.pack('>IIQQQq',*r) for r in rows)
out=b.parent/'outputs';out.mkdir(exist_ok=True);(out/'closing.fld').write_bytes(data)
(b/'rows.json').write_text(json.dumps(rows,indent=2))
digest=hashlib.sha256(data).hexdigest();flag='isfcr{'+digest+'}'
(out/'flag.txt').write_text(flag+'\n')
print('frames',len(frames),'eligible',sum(f['eligible'] for f in frames),'rows',len(rows),'bytes',len(data));print(flag)
