#!/usr/bin/env python3
"""Solve CryoVault Finals - cairn (reverse, 500).

The checker runs a 32-byte, byte-wise program through a tiny inlined bytecode
VM: a 2-byte instruction stream in .rodata, dispatched through a 6-entry jump
table.  Every opcode is a bytewise bijection, so the whole check is
mechanically invertible.  We parse the ELF (bytecode, permutation table,
target, dispatch table), then undo the 25 instructions in reverse order.

Run:  python3 solve.py [path-to-chall]
"""
import struct
import sys

DEFAULT = "challenges/cairn/input/chall"

# dispatch table @0x4012a0 -> handler address; address -> opcode semantics
HANDLERS = {
    0x40078F: "xor",     # state[i] ^= i + imm
    0x40074E: "add",     # state[i] += 3*i + imm
    0x40063B: "rot",     # state[i] = rotl8(state[i], imm)
    0x400614: "sbox",    # state[i] = 7*state[i] + 13 (mod 256)
    0x4005BF: "perm",    # out[perm[i]] = in[i]
}


class ELF:
    """Minimal ELF64 little-endian reader: virtual address -> file bytes."""

    def __init__(self, path):
        self.d = open(path, "rb").read()
        assert self.d[:4] == b"\x7fELF" and self.d[4] == 2
        e_shoff, = struct.unpack_from("<Q", self.d, 0x28)
        e_shentsize, e_shnum = struct.unpack_from("<HH", self.d, 0x3A)
        self.secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            _name, _typ, _fl, addr, off, size = struct.unpack_from("<IIQQQQ", self.d, o)
            self.secs.append((addr, off, size))

    def at(self, vaddr, n):
        for addr, off, size in self.secs:
            if size and addr <= vaddr and vaddr + n <= addr + size:
                return self.d[off + (vaddr - addr): off + (vaddr - addr) + n]
        raise ValueError("bad vaddr 0x%x" % vaddr)

    def u64(self, vaddr):
        return struct.unpack("<Q", self.at(vaddr, 8))[0]


def sbox(x):
    # table built at 0x400430: 8x - x + 0x0d == 7x + 13 (mod 256), idx = 0..255
    return (7 * x + 13) & 0xFF


def sbox_inv(v):
    # inverse of x -> 7x+13 mod 256 ; 7^-1 mod 256 == 183
    return ((v - 13) * 183) & 0xFF


def rotl8(x, k):
    k &= 7
    return (((x << k) | (x >> (8 - k))) & 0xFF) if k else x


def rotr8(x, k):
    k &= 7
    return (((x >> k) | (x << (8 - k))) & 0xFF) if k else x


def solve(path):
    e = ELF(path)

    TARGET_VA = 0x4012E0     # 32-byte memcmp target
    PROG_VA = 0x401300       # bytecode stream
    PERM_VA = 0x401340       # 32-byte permutation table
    DISPATCH_VA = 0x4012A0   # 6-entry opcode jump table

    target = e.at(TARGET_VA, 32)
    perm = list(e.at(PERM_VA, 32))
    disp = [e.u64(DISPATCH_VA + 8 * i) for i in range(6)]
    opmap = {op: HANDLERS[a] for op, a in enumerate(disp) if a in HANDLERS}
    opmap[0] = "nop"

    # decode 2-byte insns [opcode][imm] until opcode 6 (halt/memcmp)
    prog = e.at(PROG_VA, 0x40)
    insns, i = [], 0
    while prog[i] != 6:
        insns.append((opmap[prog[i]], prog[i + 1]))
        i += 2

    def forward(state):
        s = list(state)
        for name, imm in insns:
            if name == "xor":
                s = [v ^ ((j + imm) & 0xFF) for j, v in enumerate(s)]
            elif name == "add":
                s = [(v + 3 * j + imm) & 0xFF for j, v in enumerate(s)]
            elif name == "rot":
                s = [rotl8(v, imm) for v in s]
            elif name == "sbox":
                s = [sbox(v) for v in s]
            elif name == "perm":
                t = [0] * 32
                for j in range(32):
                    t[perm[j]] = s[j]
                s = t
        return bytes(s)

    # undo in reverse order
    s = list(target)
    for name, imm in reversed(insns):
        if name == "xor":
            s = [v ^ ((j + imm) & 0xFF) for j, v in enumerate(s)]
        elif name == "add":
            s = [(v - 3 * j - imm) & 0xFF for j, v in enumerate(s)]
        elif name == "rot":
            s = [rotr8(v, imm) for v in s]
        elif name == "sbox":
            s = [sbox_inv(v) for v in s]
        elif name == "perm":
            s = [s[perm[j]] for j in range(32)]   # in[i] = out[perm[i]]

    cand = bytes(s)
    assert forward(cand) == bytes(target), "inversion self-check failed"
    return cand, insns, forward


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    flag, insns, forward = solve(path)
    print("program:", insns)
    text = flag.decode()
    print("candidate:", text)
    assert text.startswith("isfcr{") and text.endswith("}"), "flag format mismatch"
    print("FLAG:", text)

    # ground-truth spot check: model must reproduce the checker's own state on
    # an arbitrary input (verified separately with gdb on 'A'*32)
    ref = "052cdcde52a3b722bfc88604e2704fe57ffd7880ae571cce95297e4fb53e87fb"
    assert forward(b"A" * 32).hex() == ref
    print("model matches checker on 'A'*32")
