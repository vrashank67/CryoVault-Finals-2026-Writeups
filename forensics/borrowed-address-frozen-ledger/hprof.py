from pathlib import Path
import struct,collections,json
b=Path(__file__).resolve().parent
d=(b/'heap.hprof').read_bytes();p=d.index(b'\0')+1
ids=struct.unpack_from('>I',d,p)[0]; p+=12
strings={};loads={};classes={};instances={};arrays={};roots=[]
sizes={2:ids,4:1,5:2,6:4,7:8,8:1,9:2,10:4,11:8}
def num(n):
 global q
 v=int.from_bytes(d[q:q+n],'big');q+=n;return v
def val(t): return num(sizes[t])
while p<len(d):
 tag,tm,n=struct.unpack_from('>BII',d,p);q=p+9;end=q+n;p=end
 if tag==1:
  sid=num(ids);strings[sid]=d[q:end].decode('utf8',errors='replace')
 elif tag==2:
  sn=num(4); cid=num(ids);num(4);loads[cid]=num(ids)
 elif tag in (0x0c,0x1c):
  while q<end:
   sub=num(1)
   if sub==0x20:
    cid=num(ids);num(4);sup=num(ids);q+=ids*5;sz=num(4)
    for _ in range(num(2)):num(2);val(num(1))
    static=[]
    for _ in range(num(2)):
     name=num(ids);t=num(1);static.append((name,t,val(t)))
    fields=[]
    for _ in range(num(2)): fields.append((num(ids),num(1)))
    classes[cid]=(sup,sz,static,fields)
   elif sub==0x21:
    oid=num(ids);num(4);cid=num(ids);ln=num(4);instances[oid]=(cid,d[q:q+ln]);q+=ln
   elif sub==0x22:
    oid=num(ids);num(4);ln=num(4);cid=num(ids);arrays[oid]=(cid,[num(ids) for _ in range(ln)])
   elif sub==0x23:
    oid=num(ids);num(4);ln=num(4);t=num(1);q+=ln*sizes[t]
   elif sub==0xff: roots.append(num(ids))
   elif sub==1:q+=ids*2
   elif sub in (2,3):q+=ids+8
   elif sub in (4,6):q+=ids+4
   elif sub in (5,7,0x89,0x8a,0x8b,0x8c,0x8d,0x90):q+=ids
   elif sub==8:q+=ids+8
   elif sub==0x8e:q+=ids+8
   elif sub==0xfe:q+=4+ids
   else:raise ValueError((hex(sub),q))
names={cid:strings.get(s,'?') for cid,s in loads.items()}
def decode(oid):
 cid,data=instances[oid];off=0;result={'class':names.get(cid),'oid':hex(oid)}
 while cid:
  sup,sz,static,fields=classes[cid]
  for n,t in fields:
   ln=sizes[t];v=int.from_bytes(data[off:off+ln],'big',signed=t in (8,9,10,11));off+=ln
   result[strings[n]]=v
  cid=sup
 return result
counts=collections.Counter(names.get(cid) for cid,data in instances.values())
print({k:v for k,v in counts.items() if k and ('ledger' in k or 'StackChunk' in k)})
out=[]
for oid,(cid,data) in instances.items():
 if names.get(cid,'').startswith('ledger') or names.get(cid,'') in ['jdk/internal/vm/StackChunk','java/lang/VirtualThread','java/lang/VirtualThread$VThreadContinuation']:out.append(decode(oid))
(b/'objects.json').write_text(json.dumps(out,indent=2))
for cid,name in names.items():
 if name.startswith('ledger'): print(hex(cid),name,classes.get(cid))
print('ledger objects',len(out))
