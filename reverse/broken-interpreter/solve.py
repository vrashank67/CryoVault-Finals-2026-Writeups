import json, struct, subprocess
from pathlib import Path

# Run on Linux in the directory containing cryopy/ and vault.pyc.
extract = r'''import marshal,ctypes,json
f=open("vault.pyc","rb");f.read(16);c=marshal.load(f).co_consts[3]
print(json.dumps([c.co_code.hex(),ctypes.string_at(id(c)+0xc0,len(c.co_code)).hex()]))
'''
plain_hex,raw_hex=json.loads(subprocess.check_output(["./cryopy/bin/python3","-c",extract],text=True))
plain=bytes.fromhex(plain_hex);raw=bytes.fromhex(raw_hex)
M=0xffffffff
h=0x811c9dc5;i=0
cache={160:2,212:1,36:1,5:1}
while i<len(plain):
 op=plain[i]
 if op==160:
  word=int.from_bytes(raw[i+4:i+6],'little');h=((h^word)*0x1000193)&M
 i+=2+2*cache.get(op,0)
print('hash',hex(h))
def rol(x,n):return ((x<<n)|(x>>(32-n)))&M
def ror(x,n):return ((x>>n)|(x<<(32-n)))&M
D=((h<<1)|0x2c1b3c6d)&M;A=rol(h,11)
def unxor(x,n):
 y=x
 for s in range(n,32,n):y^=x>>s
 return y

def at(x,y):
 z=rol(((x^h)*D)&M,(((y>>27)^h)&30)|1)^y
 z=(z*0x297a2d39)&M
 return ((z^(z>>15))+A)&M

def invat(z,y):
 z=unxor((z-A)&M,15)
 z=(z*pow(0x297a2d39,-1,1<<32))&M
 z=ror(z^y,(((y>>27)^h)&30)|1)
 return ((z*pow(D,-1,1<<32))&M)^h
s=940818519;k=[]
for i in range(48):
 s=(((at(at(s,(i*2654435769)^709),27)+(s>>3))^1713))&M;k.append(s)
def forward(a):
 a=a[:]
 for r in range(4):
  b=r*12;c=k[b+11]
  for i in range(12):
   a[i]=(a[i]+at(c,k[b+i])*1447-961)&M;c=a[i]
  c=(k[b+5]|r)<<9
  for i in range(11,-1,-1):
   a[i]=(a[i]^(at(c>>7,(k[b+i]+i)*17)<<19)^745)&M;c=a[i]
  for i in range(12):
   x=(a[i]*(k[(b+i*5)%48]|1)+2033)&M;a[i]=x^(x>>15)
  a=a[7:]+a[:7]
 return a
T=[2715281785,36340035,133570236,1217764920,1840326500,637532589,2389985240,849903035,3897288536,2860569153,169304759,4205518759]
a=T[:]
for r in range(3,-1,-1):
 a=a[-7:]+a[:-7];b=r*12
 for i in range(12):a[i]=(((unxor(a[i],15)-2033)&M)*pow(k[(b+i*5)%48]|1,-1,1<<32))&M
 c=(k[b+5]|r)<<9
 for i in range(11,-1,-1):
  saved=a[i];a[i]^=(at(c>>7,(k[b+i]+i)*17)<<19)^745;a[i]&=M;c=saved
 c=k[b+11]
 for i in range(12):
  saved=a[i];a[i]=(a[i]-at(c,k[b+i])*1447+961)&M;c=saved
flag=struct.pack('<12I',*a)
print(flag);print('forward',forward(a)==T)
assert len(flag)==48
print(flag.decode('ascii'))
subprocess.run(['./cryopy/bin/python3','vault.pyc',flag.decode('ascii')],check=True)
