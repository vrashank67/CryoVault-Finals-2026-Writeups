import struct
from unicorn import *
from unicorn.x86_const import *

ELF='controller.elf'
d=open(ELF,'rb').read()
e_phoff=struct.unpack_from('<Q',d,0x20)[0]; e_phentsize=struct.unpack_from('<H',d,0x36)[0]; e_phnum=struct.unpack_from('<H',d,0x38)[0]
BASE=0x400000
STACK=0x20000000
SCRATCH=0x10000000
NV=SCRATCH
ROW=SCRATCH+0x100
OUT=SCRATCH+0x1000
ARG7=SCRATCH+0x2000

def make_uc():
    uc=Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, 0x8000)
    uc.mem_write(BASE, d[:0x8000])
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(SCRATCH, 0x10000)
    def hook(uc,address,size,user):
        if address==0x40125e:
            v=uc.reg_read(UC_X86_REG_R8)&0xffff
            uc.reg_write(UC_X86_REG_RAX, bin(v).count('1'))
            uc.reg_write(UC_X86_REG_RIP, address+6)
        elif address==0x40129b:
            v=uc.reg_read(UC_X86_REG_ESI)&0xffffffff
            uc.reg_write(UC_X86_REG_RCX, bin(v).count('1'))
            uc.reg_write(UC_X86_REG_RIP, address+4)
    uc.hook_add(UC_HOOK_CODE, hook)
    return uc

def call_decode(chip, setting, arg4, row, half, nvram):
    uc=make_uc()
    uc.mem_write(NV, nvram)
    uc.mem_write(ROW, row)
    uc.mem_write(OUT, b'\x00'*1100)
    uc.mem_write(ARG7, struct.pack('<Q', OUT))
    sp=STACK+0x18000
    uc.mem_write(sp, struct.pack('<Q', 0xdeadbeef)+struct.pack('<Q', ARG7))
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RDI, NV)
    uc.reg_write(UC_X86_REG_ESI, chip)
    uc.reg_write(UC_X86_REG_EDX, setting)
    uc.reg_write(UC_X86_REG_ECX, arg4)
    uc.reg_write(UC_X86_REG_R8, ROW)
    uc.reg_write(UC_X86_REG_R9, half)
    try:
        uc.emu_start(0x401320, 0xdeadbeef, count=5000000)
    except UcError as e:
        return None, 'ERR %s at %x' % (e, uc.reg_read(UC_X86_REG_RIP))
    return uc.reg_read(UC_X86_REG_RAX) & 0xffffffff, bytes(uc.mem_read(OUT, 1100))

if __name__=='__main__':
    nv=open('nvram.bin','rb').read()
    d2=open('chip0.r0','rb').read()
    row=d2[0:2112]
    for arg4 in range(0,12):
        st,res=call_decode(0,0,arg4,row,0,nv)
        print('arg4',arg4,'status',st if not isinstance(st,int) else hex(st), (res[:8].hex() if isinstance(res,bytes) else res))
