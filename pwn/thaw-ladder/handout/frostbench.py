#!/usr/bin/env python3
"""
frostbench - the thawd 7.2 bench controller.

    python3 frostbench.py [--regs] [--trace]

Runs one bench session on stdin/stdout. It speaks the protocol in FROSTLANG.md section 2
and runs plans exactly as FROSTLANG.md describes the 7.2 bench. Python 3, standard
library only.

  --regs    after every plan, print the machine's final state to stderr
  --trace   print every instruction the bench executes to stderr

The bench session's values (section 8 of the manual) are fixed in BENCH below. THAWED on
the bench carries no thaw key.
"""

import os
import sys

BENCH = {
    "profile": bytes.fromhex("a1729f19f335a4e6c3e3c96a5d192d15abfbf4030595259e5e10130ff1fa60b5"),
    "window_tail": bytes.fromhex("a24edd790cad642e6515118dfe8bab6b127b139e7c6c7d6b3bc9a18647ea7f1a"),
    "x0": 0x7b7b,
    "y0": 0x8176,
}

RAM_END, BOOT, MBOX, CTL, CTL_END = 0x8000, 0x8000, 0x8100, 0x8200, 0x8300
CTRL, CTRL_END, WINDOW = 0x9000, 0xA000, 0x9000
BUDGET = 65536
PLAN_MAX = 1024
NAMES = ["HALT", "LDI", "ALU", "ALUI", "LDB", "LDW", "STB", "STW",
         "BEQ", "BNE", "BLTU", "DJNZ", "JAL", "SEAL", "ATT", "NOP"]
FUNCS = ["ADD", "SUB", "AND", "OR", "XOR", "SHL", "SHR", "ROL", "MUL", "MULH", "SLTU"]
VERDICTS = ["SETTLED", "FAULT", "OVERRUN", "REJECT", "THAWED"]


def rotl16(v, s):
    s &= 15
    return ((v << s) | (v >> ((16 - s) & 15))) & 0xFFFF


def func(fn, x, y):
    return [
        lambda: (x + y) & 0xFFFF,
        lambda: (x - y) & 0xFFFF,
        lambda: x & y,
        lambda: x | y,
        lambda: x ^ y,
        lambda: (x << (y & 15)) & 0xFFFF,
        lambda: x >> (y & 15),
        lambda: rotl16(x, y),
        lambda: (x * y) & 0xFFFF,
        lambda: (x * y) >> 16,
        lambda: 1 if x < y else 0,
    ][fn]()


def fold(x, y, profile, n):
    """The monitor's fold (FROSTLANG.md section 6)."""
    for t in range(16):
        j = (t + (y >> 12)) & 15
        k = profile[2 * j] << 8 | profile[2 * j + 1]
        x = rotl16(x ^ k, y & 15)
        x = (x + n[t & 3]) & 0xFFFF
        y = (y * 0x9E35 + x + t) & 0xFFFF
        y = y ^ rotl16(x, 7)
    return x, y


class Fault(Exception):
    pass


class Bench:
    def __init__(self, trace=None):
        self.trace = trace

    def note(self, pc, w, text):
        if self.trace:
            self.trace.write("  %4d  %08x  %-5s %s\n" % (pc, w, NAMES[w >> 28], text))

    def run(self, code):
        """One plan. Returns (verdict, retired, fault-or-None, final state)."""
        mem = bytearray(0x10000)
        boot = [0x4652, 0x0702, BENCH["x0"], BENCH["y0"], 0x0007]
        for i, v in enumerate(boot):
            mem[BOOT + 2 * i] = v >> 8
            mem[BOOT + 2 * i + 1] = v & 0xFF
        win = BENCH["profile"] + BENCH["window_tail"]
        mem[WINDOW:WINDOW + 64] = win
        st = {"r": [0] * 16, "pc": 0, "retired": 0, "priv": False, "resumed": False,
              "sealed": False, "gate": False, "chal": None, "round": 0,
              "x": BENCH["x0"], "y": BENCH["y0"]}
        r = st["r"]

        def word_at(a):
            return mem[a & 0xFFFF] << 8 | mem[(a + 1) & 0xFFFF]

        def check_store(a):
            if a < RAM_END or MBOX <= a < CTL:
                return
            if CTL <= a < CTL_END:
                if st["gate"]:
                    return
                raise Fault("sealed")
            raise Fault("write")

        def end(verdict, fault=None):
            return VERDICTS[verdict], st["retired"], fault, st

        try:
            while True:
                if st["retired"] >= BUDGET:
                    return end(2)
                pc = st["pc"]
                if not 0 <= pc < len(code):
                    raise Fault("fetch")
                w = code[pc]
                op, a, b, c, imm = w >> 28, (w >> 24) & 15, (w >> 20) & 15, (w >> 16) & 15, w & 0xFFFF
                simm = imm - 0x10000 if imm & 0x8000 else imm
                nxt = pc + 1
                if op == 0x0:                                   # HALT
                    if w:
                        raise Fault("decode")
                    cont = word_at(CTL)
                    if not st["resumed"] and cont & 0x8000:
                        st["resumed"] = True
                        if (cont & 0x7FFF) >= len(code):
                            raise Fault("resume")
                        st["priv"] = True
                        nxt = cont & 0x7FFF
                        self.note(pc, w, "resume privileged at %d" % nxt)
                    else:
                        self.note(pc, w, "settle")
                        st["retired"] += 1
                        return end(0)
                elif op == 0x1:                                 # LDI
                    if b or c:
                        raise Fault("decode")
                    r[a] = imm
                elif op == 0x2:                                 # ALU
                    if imm >= len(FUNCS):
                        raise Fault("decode")
                    r[a] = func(imm, r[b], r[c])
                elif op == 0x3:                                 # ALUI
                    if c >= len(FUNCS):
                        raise Fault("decode")
                    r[a] = func(c, r[b], imm)
                elif op in (0x4, 0x5):                          # LDB, LDW
                    if c:
                        raise Fault("decode")
                    ea = (r[b] + imm) & 0xFFFF
                    if ea >= CTL_END or (op == 0x5 and ((ea + 1) & 0xFFFF) >= CTL_END):
                        raise Fault("read")
                    r[a] = mem[ea] if op == 0x4 else word_at(ea)
                elif op in (0x6, 0x7):                          # STB, STW
                    if c:
                        raise Fault("decode")
                    ea = (r[b] + imm) & 0xFFFF
                    check_store(ea)
                    if op == 0x7:
                        check_store((ea + 1) & 0xFFFF)
                        mem[ea] = r[a] >> 8
                        mem[(ea + 1) & 0xFFFF] = r[a] & 0xFF
                    else:
                        mem[ea] = r[a] & 0xFF
                elif op in (0x8, 0x9, 0xA):                     # BEQ, BNE, BLTU
                    if c:
                        raise Fault("decode")
                    take = (r[a] == r[b], r[a] != r[b], r[a] < r[b])[op - 0x8]
                    if take:
                        nxt = pc + 1 + simm
                elif op == 0xB:                                 # DJNZ
                    if b or c:
                        raise Fault("decode")
                    r[a] = (r[a] - 1) & 0xFFFF
                    if r[a]:
                        nxt = pc + 1 + simm
                elif op == 0xC:                                 # JAL
                    if c:
                        raise Fault("decode")
                    target = (r[b] + imm) & 0xFFFF
                    r[a] = (pc + 1) & 0xFFFF
                    nxt = target
                elif op == 0xD:                                 # SEAL
                    if b or c or imm:
                        raise Fault("decode")
                    if r[a] > 32:
                        raise Fault("span")
                    if st["sealed"]:
                        raise Fault("reseal")
                    st["sealed"] = True
                    at = WINDOW + r[a]
                    if bytes(mem[at:at + 32]) == BENCH["profile"]:
                        st["gate"] = True
                    self.note(pc, w, "offset %d, gate %s" % (r[a], "open" if st["gate"] else "closed"))
                elif op == 0xE:                                 # ATT
                    if imm:
                        raise Fault("decode")
                    if not st["priv"]:
                        raise Fault("priv")
                    if st["chal"] is not None:
                        x, y = fold(st["x"], st["y"], BENCH["profile"], st["chal"])
                        if (r[b], r[c]) != (x, y):
                            self.note(pc, w, "answer %04x %04x refused" % (r[b], r[c]))
                            st["retired"] += 1
                            return end(3)
                        st["x"], st["y"] = x, y
                        st["round"] += 1
                        self.note(pc, w, "answer accepted")
                        if st["round"] == 4:
                            st["retired"] += 1
                            return end(4)
                    nb = os.urandom(8)
                    st["chal"] = [nb[2 * i] << 8 | nb[2 * i + 1] for i in range(4)]
                    mem[MBOX:MBOX + 8] = nb
                    r[a] = st["round"]
                    self.note(pc, w, "round %d challenge %s" % (st["round"], nb.hex()))
                else:                                           # NOP
                    if w != 0xF0000000:
                        raise Fault("decode")
                if op not in (0x0, 0xD, 0xE):
                    self.note(pc, w, "r%d=%04x" % (a, r[a]) if op in (1, 2, 3, 4, 5, 11, 12) else "")
                r[0] = 0
                st["retired"] += 1
                st["pc"] = nxt
        except Fault as f:
            self.note(st["pc"], code[st["pc"]] if 0 <= st["pc"] < len(code) else 0,
                      "fault: %s" % f)
            return end(1, str(f))


def parse_plan(text):
    if not text or len(text) % 8 or len(text) // 8 > PLAN_MAX:
        return None
    try:
        return [int(text[i:i + 8], 16) for i in range(0, len(text), 8)]
    except ValueError:
        return None


def main(argv):
    regs = "--regs" in argv
    bench = Bench(sys.stderr if "--trace" in argv else None)
    out = sys.stdout
    out.write("frostbench 7.2 pod 07 bench session ready\n")
    out.flush()
    for raw in sys.stdin.buffer:
        line = raw.decode("latin-1")
        if line.endswith("\n"):
            line = line[:-1]
        if len(line) > 8448:
            out.write("ERR line\n")
            out.flush()
            continue
        if line.endswith("\r"):
            line = line[:-1]
        if line.startswith("PLAN "):
            words = line[5:]
            code = parse_plan(words) if all(ch in "0123456789abcdefABCDEF" for ch in words) else None
            if code is None:
                out.write("ERR plan\n")
            else:
                verdict, retired, fault, st = bench.run(code)
                if verdict == "THAWED":
                    out.write("THAWED %d bench-no-key\n" % retired)
                else:
                    out.write("%s %d\n" % (verdict, retired))
                if regs:
                    sys.stderr.write("  regs %s  pc=%d gate=%d priv=%d round=%d%s\n" % (
                        " ".join("r%d=%04x" % (i, v) for i, v in enumerate(st["r"])),
                        st["pc"], st["gate"], st["priv"], st["round"],
                        "  fault=%s" % fault if fault else ""))
        elif line == "QUIT":
            out.write("BYE quit\n")
            out.flush()
            return 0
        elif line == "HELP":
            out.write("OK PLAN <hex instruction words> | QUIT\n")
        else:
            out.write("ERR verb\n" if line else "ERR empty\n")
        out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
