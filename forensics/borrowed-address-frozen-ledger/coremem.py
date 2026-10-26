from pathlib import Path
import mmap,struct,json
b=Path(__file__).resolve().parent
class Core:
 def __init__(self):
  self.f=(b/'core').open('rb');self.d=mmap.mmap(self.f.fileno(),0,access=mmap.ACCESS_READ)
  phoff=struct.unpack_from('<Q',self.d,32)[0];ents,n=struct.unpack_from('<HH',self.d,54)
  self.segs=[]
  for i in range(n):
   t,flags,off,va,pa,fs,ms,align=struct.unpack_from('<II6Q',self.d,phoff+i*ents)
   if t==1:self.segs.append((va,va+fs,off))
 def read(self,a,n):
  for lo,hi,off in self.segs:
   if lo<=a and a+n<=hi:return self.d[off+a-lo:off+a-lo+n]
  raise ValueError(hex(a))
 def u64(self,a):return struct.unpack('<Q',self.read(a,8))[0]
 def u32(self,a):return struct.unpack('<I',self.read(a,4))[0]
if __name__=='__main__':
 c=Core();objs=json.loads((b/'objects.json').read_text())
 for o in objs:
  if 'Continuation' in o['class'] or 'StackChunk' in o['class']:
   print(o)
   if o.get('tail'):
    a=o['tail'];print(hex(a),c.read(a,80).hex(' '))
