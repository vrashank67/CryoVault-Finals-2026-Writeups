import struct, time, json, sys, collections
from unicorn import *
from unicorn.x86_const import *
import emu

nv=open('nvram.bin','rb').read()
uc=emu.make_uc()
uc.mem_write(emu.NV,nv)

def decode(chip, setting, rowidx, half, row):
    uc.mem_write(emu.ROW,row)
    uc.mem_write(emu.OUT,b'\0'*1100)
    sp=emu.STACK+0x18000
    uc.mem_write(sp,struct.pack('<Q',0xdeadbeef)+struct.pack('<Q',emu.OUT))
    uc.reg_write(UC_X86_REG_RSP,sp)
    uc.reg_write(UC_X86_REG_RDI,emu.NV)
    uc.reg_write(UC_X86_REG_ESI,chip)
    uc.reg_write(UC_X86_REG_EDX,setting)
    uc.reg_write(UC_X86_REG_ECX,rowidx)
    uc.reg_write(UC_X86_REG_R8,emu.ROW)
    uc.reg_write(UC_X86_REG_R9,half)
    try:
        uc.emu_start(0x401320,0xdeadbeef,count=5000000)
    except UcError as e:
        return -99, None
    st=uc.reg_read(UC_X86_REG_RAX)&0xffffffff
    if st not in (0,1):
        return st, None
    return st, bytes(uc.mem_read(emu.OUT,0x420))

t0=time.time()
recs=[]
stats=collections.Counter()
for chip in range(4):
    d=open('chip%d.r%d'%(chip,0),'rb').read() if False else None
    for setting in range(3):
        d=open('chip%d.r%d'%(chip,setting),'rb').read()
        for rowidx in range(128):
            row=d[rowidx*2112:(rowidx+1)*2112]
            for half in range(2):
                st,out=decode(chip,setting,rowidx,half,row)
                stats[st]+=1
                if out is not None:
                    slot,cyc=struct.unpack_from('<HH',out,4)
                    recs.append(dict(chip=chip,setting=setting,row=rowidx,half=half,slot=slot,cycle=cyc,status=st,spare=out[:32].hex(),payload=out[0x20:0x420].hex()))
        print('done chip',chip,'setting',setting,'%.1fs'%(time.time()-t0),'recs',len(recs), flush=True)
print('stats',dict(stats))
json.dump(recs,open('pages.json','w'))
print('total',len(recs),'distinct locators',len(set((r['chip'],r['slot'],r['cycle']) for r in recs)))
# locator multiplicity
cnt=collections.Counter((r['chip'],r['slot'],r['cycle']) for r in recs)
mult=collections.Counter(cnt.values())
print('multiplicity histogram',dict(mult))
print('slots',sorted(set(r['slot'] for r in recs)))
