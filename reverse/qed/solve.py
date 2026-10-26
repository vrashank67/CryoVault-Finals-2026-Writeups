#!/usr/bin/env python3
"""
Q.E.D. - Prove the Impossible  (CryoVault Finals 2026, rev/500)

Exploit: the kernel memoises `case` checks in the global environment hash map.
The cache key fingerprints the local context only by (length, first assumption,
last assumption) plus (case-node id, expected formula).  It ignores the
assumptions in the middle of the context.  The same hash-consed `case` term is
therefore accepted in a context that differs from the one where it was really
checked, as long as both contexts agree on length and endpoints.

  p1 : top -> bot -> top -> bot        (genuine: the case body proves bot under
                                        [top, bot, top] using var 2 : bot)
  p2 : top -> top -> top -> bot        (same case *term id*; checked under
                                        [top, top, top] -> spurious cache hit)

Then apply p2 to three proofs of `top`, deriving `bot`.

Usage: python3 solve.py [host] [port]
"""
import socket
import sys
import re

HOST = sys.argv[1] if len(sys.argv) > 1 else "0.cloud.chals.io"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 24225

PAD = 12  # makes the case node's aux size >= 11 so the memo path is used


def big_bot(k, depth):
    """A term of type bot under a context where (var k) : bot, with aux == depth."""
    t = f"(var {k})"
    for _ in range(depth):
        t = f"(snd top (pair tt {t}))"
    return t


def build_module(nonce):
    big = big_bot(2, PAD)
    case = f"(case top (atom q) (inl tt) {big} {big})"
    return f"""(module qed1 {nonce}
  (def p1
    (imp top (imp bot (imp top bot)))
    (lam top (lam bot (lam top {case}))))
  (def p2
    (imp top (imp top (imp top bot)))
    (lam top (lam top (lam top {case}))))
  (def go bot
    (app top (app top (app top (ref p2) tt) tt) tt))
  (export go))
""".encode()


def recv_until(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)
    banner = recv_until(s, 3.0)
    sys.stderr.write(banner.decode(errors="replace"))
    m = re.search(rb"nonce\s+([0-9a-fA-F]{32})", banner)
    if not m:
        sys.stderr.write("[-] no nonce in banner\n")
        return 1
    nonce = m.group(1).decode()
    module = build_module(nonce)
    sys.stderr.write(f"[*] nonce {nonce}, module {len(module)} bytes\n")
    s.sendall(module)
    s.sendall(b"\n.qed\n")
    out = recv_until(s, 8.0)
    s.close()
    text = out.decode(errors="replace")
    sys.stderr.write(text)
    flag = re.search(r"isfcr\{[^}]*\}", text)
    if flag:
        print(flag.group(0))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
