import csv,struct,json,hmac,hashlib
from pathlib import Path
import reedsolo
from Crypto.Cipher import AES
import sys, zlib
from collections import defaultdict
base=Path(sys.argv[1]) if len(sys.argv)>1 else Path.cwd()

def mmo(d):
 n=len(d)*8;d+=b'\x80'
 d+=b'\0'*((14-len(d))%16)+n.to_bytes(2,'big');h=b'\0'*16
 for i in range(0,len(d),16):
  b=d[i:i+16];h=bytes(x^y for x,y in zip(AES.new(h,AES.MODE_ECB).encrypt(b),b))
 return h

def kh(k,t):return mmo(bytes(x^0x5c for x in k)+mmo(bytes(x^0x36 for x in k)+bytes([t])))
rows=list(csv.DictReader(open(base/'factory-pages.csv')));ecc={r['serial']:bytes(int(r['c'+str(i)],16) for i in range(6)) for r in csv.DictReader(open(base/'factory-ecc.csv'))}
def install_crc(d):
 c=0xffff
 for x in d:
  c^=x
  for _ in range(8):c=(c>>1)^(0x8408 if c&1 else 0)
 return c^0xffff
rs=reedsolo.RSCodec(6,fcr=9,prim=0x1cf,generator=2);links={};audits={}
for r in rows:
 d=bytes(rs.decode(bytes.fromhex(r['row'])+ecc[r['serial']])[0]);assert install_crc(d[:16])==int.from_bytes(d[16:],'little');k=mmo(d);eui=bytes.fromhex(r['eui_lsb']);links[r['serial']]=k;audits[r['serial']]=hmac.digest(k,b'PM-AUDIT-v1'+eui,'sha256')

def packets():
 d=(base/'challenge.pcapng').read_bytes();i=0;num=0
 while i<len(d):
  typ,n=struct.unpack_from('<II',d,i)
  if typ==6:
   num+=1;iface,hi,lo,cap,orig=struct.unpack_from('<5I',d,i+8);yield num,d[i+28:i+28+cap],orig
  i+=n

def decrypt(d,off,k):
 sc=d[off]|5;kid=(sc>>3)&3;end=off+13+(kid==1);hdr=bytearray(d[:end]);hdr[off]=sc
 nonce=d[off+5:off+13]+d[off+1:off+5]+bytes([sc])
 a=AES.new(k,AES.MODE_CCM,nonce=nonce,mac_len=4);a.update(hdr)
 return a.decrypt_and_verify(d[end:-4],d[-4:])

keys={};outs=[]
for num,p,orig in packets():
 if len(p)!=orig or len(p)<20:continue
 # Evidence uses compressed short MAC addressing, nine-byte MAC header.
 d=p[9:-2];fc=int.from_bytes(d[:2],'little');off=8
 if fc&0x800:off+=8
 if fc&0x1000:off+=8
 if fc&0x400:off+=1
 if fc&0x200:
  seq=d[off+13]
  if seq not in keys:continue
  try:aps=decrypt(d,off,keys[seq])
  except ValueError:continue
 else:aps=d[off:]
 if not aps:continue
 if aps[0]&0x20:
  # Command APS header is frame control and counter.
  for serial,k in links.items():
   try:plain=decrypt(aps,2,k if ((aps[2]>>3)&3)==0 else kh(k,0))
   except ValueError:continue
   print('Authenticated commissioning frame',num,serial)
   if plain[:2]==b'\x05\x01':keys[plain[18]]=plain[2:18]
   break
 else:
  outs.append(dict(num=num,src=d[4:6].hex(),nwk=d.hex(),aps=aps.hex()))

# Predictable telemetry supplies the CTR keystream for repeated nonces.
tele=[x for x in outs if len(bytes.fromhex(x['aps']))==47 and bytes.fromhex(x['aps'])[2:4]==b'\x43\xfc']
def step(x):
 x^=(x<<13)&0xffffffff;x^=x>>17;x^=(x<<5)&0xffffffff
 return x
for x,y in zip(tele,tele[1:]):
 assert step(int.from_bytes(bytes.fromhex(x['aps'])[36:40],'little'))==int.from_bytes(bytes.fromhex(y['aps'])[36:40],'little')
last=tele[-1];template=bytearray.fromhex(last['aps']);nd=bytes.fromhex(last['nwk']);lastctr=int.from_bytes(nd[9:13],'little');eui=nd[13:21]
def fcs(d):
 c=0
 for x in d:
  c^=x
  for _ in range(8):c=(c>>1)^(0x8408 if c&1 else 0)
 return c
G=defaultdict(list)
for num,p,orig in packets():
 if len(p)!=orig or len(p)<40:continue
 if fcs(p[:-2])!=int.from_bytes(p[-2:],'little'):continue
 d=p[9:-2]
 if d[8:9]!=b'\x28' or d[21]!=8 or d[13:21]!=eui:continue
 G[int.from_bytes(d[9:13],'little')].append((num,p,d))
sessions={}
for ctr,g in G.items():
 donors=[x for x in g if len(x[1])==84]
 if not donors:continue
 num,p,d=donors[0];t=template[:];delta=ctr-lastctr
 t[7]=(t[7]+delta)%256;t[11]=(t[11]+delta)%256
 t[43:47]=(int.from_bytes(t[43:47],'little')+delta).to_bytes(4,'little')
 rng=int.from_bytes(template[36:40],'little')
 for _ in range(delta):rng=step(rng)
 t[36:40]=rng.to_bytes(4,'little');keystream=bytes(a^b for a,b in zip(d[22:-4],t))
 for num,p,d in g:
  if len(p)==84:continue
  a=bytes(x^y for x,y in zip(d[22:-4],keystream))
  if a[2:4]!=b'\x42\xfc':continue
  cmd=a[12];b=a[13:];sid,epoch=struct.unpack_from('<IH',b)
  ss=sessions.setdefault((sid,epoch),{'nodes':{},'frames':[]});ss['frames'].append(num)
  if cmd==0x30:ss['open']=struct.unpack_from('<HHH',b,6)
  elif cmd==0x31:
   n,nxt,u=struct.unpack_from('<HHB',b,6);raw=b[11:27]
   page=bytes(raw[j*4+i] for i in range(4) for j in range(4))
   ss['nodes'][n]=(nxt,u,page)
  elif cmd==0x32:ss['close']=b[6]
  elif cmd==0x34:ss['abort']=b[6]
alpha='abcdefghijklmnopqrstuvwxyz0123456789_'
for (sid,epoch),ss in sorted(sessions.items()):
 head,count,length=ss['open'];chain=[];packed=b''
 while head!=65535:
  assert head not in chain;chain.append(head)
  nxt,u,page=ss['nodes'][head];packed+=page[:u];head=nxt
 assert len(chain)==count and len(packed)==length
 record=zlib.decompress(packed);assert record[:5]==b'PMR1\x04'
 fields={};pos=5
 for _ in range(record[4]):
  typ,n=record[pos:pos+2];pos+=2;fields[typ]=record[pos:pos+n];pos+=n
 assert pos==len(record)
 owners=[]
 for serial,k in audits.items():
  tail=b''
  for n in chain:
   nxt,u,page=ss['nodes'][n]
   mask=hmac.digest(k,b'PM-MASK'+struct.pack('<IHH',sid,epoch,n),'sha256')
   tail+=bytes(x^y for x,y in zip(page[u:],mask))
  chars=tail[0];size=(chars*6+7)//8
  if not chars or 1+size>len(tail):continue
  if tail[1+size:]!=b'\xff'*(len(tail)-1-size):continue
  bits=''.join(f'{x:08b}' for x in tail[1:1+size]);codes=[int(bits[i*6:i*6+6],2) for i in range(chars)]
  if any(x>=len(alpha) for x in codes):continue
  owners.append((serial,''.join(alpha[x] for x in codes)))
 assert len(owners)==1
 serial,token=owners[0];receipt=int.from_bytes(fields[3],'little')
 print('Epoch',epoch,'receipt',hex(receipt),'operation',fields[2].decode(),'writer',serial,'close',ss.get('close'),'abort',ss.get('abort'))
 print('Recovered allocator token:',token)
 if ss.get('close')==0 and 'abort' not in ss:
  assert receipt==0x72a
  print('FLAG: isfcr{'+token+'}')
