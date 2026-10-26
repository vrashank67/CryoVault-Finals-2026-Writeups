#!/usr/bin/env python3
"""Recover GHOSTVAULT's receipt and authenticated flag from the original APK.
Dependencies: unicorn, pyelftools, cryptography, pycryptodome.
The x86_64 library is emulated at its original relative addresses. We reconstruct
normal, uninstrumented context (guard=0, original code hash, actual APK signer),
then execute the original native verifier and key derivation without patching.
"""
import argparse
import hashlib
import io
import struct
import zipfile
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
from Crypto.Cipher import AES
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

MASK = 0xffffffff
OPS = [0x5680, 0x5690, 0x56b0, 0x56c0, 0x5720, 0x5730, 0x5740, 0x5760,
       0x5770, 0x57d0, 0x57e0, 0x57f0, 0x5940, 0x5950, 0x5960, 0x59d0]

def rol(x, n):
    x &= MASK
    n &= 31
    return ((x << n) | (x >> ((-n) & 31))) & MASK

def ror(x, n):
    return rol(x, -n)

def gm(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return result

def sub(x, table):
    return sum(table[(x >> (8*k)) & 255] << (8*k) for k in range(4))

def solve(apk, session):
    with zipfile.ZipFile(apk) as archive:
        blob = archive.read('lib/x86_64/libghost.so')
        cert = pkcs7.load_der_pkcs7_certificates(archive.read('META-INF/GHOSTVAU.RSA'))[0]
        cert_hash = hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()
        plate = archive.read('assets/plate.vlt')
    elf = ELFFile(io.BytesIO(blob))
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    u.ctl_set_cpu_model(UC_CPU_X86_HASWELL)
    u.mem_map(0, 0x10000)
    fnv = 0xcbf29ce484222325
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            u.mem_write(segment['p_vaddr'], segment.data())
            if segment['p_flags'] & 1:
                for byte in segment.data():
                    fnv = ((fnv ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    for relocation in elf.get_section_by_name('.rela.dyn').iter_relocations():
        if relocation['r_info_type'] == 8:
            u.mem_write(relocation['r_offset'], struct.pack('<Q', relocation['r_addend']))
    u.mem_map(0x100000, 0x100000)
    u.mem_map(0x300000, 0x10000)
    registers = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                 UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    trace = []
    def args():
        return [u.reg_read(r) for r in registers]
    def return_value(value):
        sp = u.reg_read(UC_X86_REG_RSP)
        pc = struct.unpack('<Q', u.mem_read(sp, 8))[0]
        u.reg_write(UC_X86_REG_RSP, sp + 8)
        u.reg_write(UC_X86_REG_RAX, value)
        u.reg_write(UC_X86_REG_RIP, pc)
    def hook(uc, address, size, context):
        if address == 0x4b90:
            return_value(fnv)  # Same result as dl_iterate_phdr over original executable PT_LOAD.
        elif address in OPS:
            a = args()
            trace.append((OPS.index(address), a[1], a[2], a[3], bytes(u.mem_read(a[0], 40))))
        elif address == 0x300580:  # JNI NewByteArray
            return_value(0x305000)
        elif address == 0x300680:  # JNI SetByteArrayRegion
            a = args()
            u.mem_write(a[1], bytes(u.mem_read(a[4], a[3])))
            return_value(0)
    u.hook_add(UC_HOOK_CODE, hook)
    u.mem_write(0x300000, struct.pack('<Q', 0x301000))
    for offset in (0x580, 0x680):
        u.mem_write(0x301000 + offset, struct.pack('<Q', 0x300000 + offset))
        u.mem_write(0x300000 + offset, b'\xc3')
    sp = 0x180000
    u.reg_write(UC_X86_REG_RSP, sp)
    u.mem_write(sp + 0xf0, struct.pack('<I', 0) + cert_hash)
    u.mem_write(sp + 0x1c0, session)
    u.mem_write(sp + 0x1e0, bytes(16))
    u.reg_write(UC_X86_REG_R15, sp + 0xf4)
    u.reg_write(UC_X86_REG_R13, 0x300000)
    u.emu_start(0x4221, 0x4355, count=10000000)
    seed1 = bytes(u.mem_read(sp + 0x10, 32))
    seed2 = bytes(u.mem_read(sp + 0x50, 32))
    initial_control = bytes(u.mem_read(sp + 0x90 + 32, 8))
    target = bytes(x ^ y for x, y in zip(blob[0xd04:0xd24], seed2))
    u.emu_start(0x4355, 0x435a, count=10000000)
    assert len(trace) == 192
    sbox = blob[0xd24:0xe24]
    inverse_sbox = bytes(sbox.index(k) for k in range(256))
    state = list(struct.unpack('<8I', target))
    for op, i, j, immediate, before in reversed(trace):
        if op == 0:
            state[i] = ror(state[i], state[j] & 31)
        elif op == 1:
            a, b = state[i], state[j]
            state[i], state[j] = (2*a-b) & MASK, (b-a) & MASK
        elif op == 2:
            state[i] ^= immediate
        elif op == 3:
            state[i] = sub(state[i], inverse_sbox)
        elif op == 4:
            state[i] = (state[i] - state[j]) & MASK
        elif op == 5:
            state[i] = (-(state[i] ^ immediate)) & MASK
        elif op == 6:
            pass  # Changes only VM scheduling/control; already recorded in the trace.
        elif op == 7:
            state[i] = state[i] * pow(immediate | 1, -1, 1 << 32) & MASK
        elif op == 8:
            state[i] ^= rol(sub((state[j] + immediate) & MASK, sbox), 11)
        elif op == 9:
            state[i] = (state[i] + state[j]) & MASK
        elif op == 10:
            state[i] = int.from_bytes(state[i].to_bytes(4, 'little'), 'big')
        elif op == 11:
            coefficient = (immediate & 255) | 1
            inverse = next(x for x in range(1, 256) if gm(coefficient, x) == 1)
            state[i] = sub(state[i], [gm(k, inverse) for k in range(256)])
        elif op == 12:
            state[i] = ror(state[i], immediate | 1)
        elif op == 13:
            state[i] ^= state[j]
        elif op == 14:
            k = (immediate & 7) | 1
            state = state[-k:] + state[:-k]
        elif op == 15:
            state[i] = (state[i] - immediate) & MASK
    initial = struct.pack('<8I', *state)
    assert initial[16:] == seed1[:16], 'Reversed state must match independently derived seed'
    receipt = initial[:16]
    u.mem_write(sp + 0x90, initial + initial_control)
    u.mem_write(sp + 0x1e0, receipt)
    u.reg_write(UC_X86_REG_RDI, sp + 0x90)
    u.reg_write(UC_X86_REG_RSI, sp + 0x30)
    u.emu_start(0x4355, 0x4a93, count=10000000)
    assert bytes(u.mem_read(sp + 0x90, 32)) == target
    native_material = bytes(u.mem_read(0x305000, 32))
    assert native_material != bytes(32), 'Original native verifier must reach key derivation'
    words = struct.unpack('<4I', session)
    java_mask = b''.join(struct.pack('<I',
        ror(words[(i+1)&3], ((i*5+4) % 31)+1) ^
        rol(words[i&3]+0x7f4a7c15*(i+1), ((i*3+9) % 31)+1)) for i in range(8))
    material = bytes(x ^ y for x, y in zip(native_material, java_mask))
    key = hashlib.sha256(material + bytes.fromhex('b5a8913d7fe042628103c97755ed4b0a')).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=plate[4:16])
    cipher.update(b'GVT2|receipt31')
    flag = cipher.decrypt_and_verify(plate[16:-16], plate[-16:])
    return receipt.hex(), flag.decode('ascii')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk')
    parser.add_argument('--session', default='00'*16, help='Any 16-byte session in hex')
    options = parser.parse_args()
    session = bytes.fromhex(options.session)
    assert len(session) == 16
    receipt, flag = solve(options.apk, session)
    print('Receipt:', receipt)
    print('AES-GCM tag: verified')
    print(flag)
