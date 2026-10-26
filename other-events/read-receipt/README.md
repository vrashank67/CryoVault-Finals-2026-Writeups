---
title: "Read Receipt"
ctf: "isfcr CTF"
date: 2026-10-25
category: misc
difficulty: hard
points: n/a
flag_format: "isfcr{...}"
author: ""
---

# Read Receipt (case RR3-063)

## Summary

A four-layer appliance chain: a simulated NAND read-channel, a GF(256)-coded catalog whose
three read-valid payloads per locator must be selected, a pack/4 sparse export, and a
post-handshake QUIC/HTTP-3 ledger. The accepted handover's receipt yields the QUIC secrets;
recovering the full 24-node ledger yields the delivery key and the flag.

## Solution

### Step 1 — Physical read channel and the catalog selection

`controller.elf` contains the read-channel model at `0x401320` (main is a stub). It
de-interleaves a 2112-byte scan row (2048 main + 64 spare), descrambles the payload with a
xorshift32 stream seeded from nvram + row + half, corrects one bit with a 15-bit ECC syndrome,
and verifies CRC-32. Emulating it with unicorn (a `popcnt` code hook is needed) over
4 chips x 3 reference settings x 128 rows x 2 halves gives 882 CRC-valid pages. Each page's
locator is `[chip, slot, cycle]` from the spare; the 234 catalog locators have three distinct
read-valid payloads each (90 unreferenced locators have two).

The catalog (recovered from `catalog.db` + its 10-transaction WAL) is a 234x180 rank-180 linear
system over GF(256)/0x11d. `x-rr`-style decoys are not used here: every candidate difference at
every locator is a scalar multiple of one global 1024-byte vector V. With `cands[i]` sorted and
`t_i = (c1^c0)/V`, the 54 consistency equations reduce to

```
sum_i H[k,i] * t_i = w_k        (k = 0..53)
```

and writing `t_i = a_i*b1_i + c_i*b2_i` with bits `b1,b2` turns them into 432 GF(2) equations in
468 bits (rank 432, nullity 36) plus 234 one-hot clauses `not(b1 and b2)`. CryptoMiniSat (native
XOR reasoning) solves it immediately. Solving the 180-symbol system then reproduces **all three**
declared stream hashes:

```
gen 0 e0d19c9a...  gen 1 581d1bf2...  gen 2 dcfa321e...
```

The accepted client handover (see below) selects **generation 1**: 61291 bytes,
sha256 `581d1bf2f89db0afc4633ce34a6e01147ec2f388c8ea6e88844116f42aef20b6`.

### Step 2 — Package, pack/4 view, receipt

The link capture (`client.pcapng`) contains one COMMIT/CONFIRM agreement: ticket
`b6f60d11668aa5e533000b8098127310`, cookie
`204d906edf11f70d8a5d60fa4aeb9a5b3c3b578c7703831a379699949260e6b5` (= SHA-256 of the stored
transaction-4 catalog blob), request `0712019f...`, session `4ccb84c3c594a394`. That job exists
only in WAL transactions tx4/tx5: nonce `6269412e03cda50fcec5ee63`, sealed 627 bytes.

`rr-package-1` is inverted per the note: `T` = last 32 bytes, `K = T xor SHA256("RR package 1\0" +
C)`, AES-256-CTR with an all-zero IV, zlib decompress -> `RRPCK4` container (89314 bytes). The
accepted job's view (42 bytes, little-endian offset/length, namespace
`3482f636...9e47`, handle `5b0000000300`, length 576,700,708,638) is resolved by the pack/4
engine (namespaces with bind/remove/exchange, node literal/clone/hole/allocated-zero ops,
lazy range evaluation, canonical `R4SP` run merging) to a 66814-byte export.

`key = SHA256("RR export 4\0" + export)` -> AES-256-GCM receipt with AAD `ticket||cookie` ->
`RRTC5\0` JSON transit capsule containing the QUIC traffic secrets.

### Step 3 — Uplink QUIC: the packet numbers jump

The capsule gives client/server traffic secrets, next PNs `6442450720` / `8589934352`, CID length
8, ticket, root `6a053dd5...af62` and length 24. A stock RFC 9000/9001 decoder authenticates only
**59 of 512** datagrams. Header protection is nevertheless correct: removing it with the
**generation-0** hp key yields reserved bits `0x18 == 0` for all 512 packets. The keys are fine;
the failure is the nonce input. Every RFC `quic ku` key update also shifts the packet number by
`2^24 + jitter` (the capture is a sampled export of a long-lived connection), so ordinary
"+N" reconstruction can never reach it.

The exact full PNs leak in cleartext ACK frames (`ACK largest=...`). Using those as anchors, for
each packet take `pn_len` + truncated PN from the gen-0 HP-unprotected header and try every
residue-class member `PN = truncated (mod 2^(8*pn_len))` in a window around each anchor of that
direction, across AEAD generations 0..7 (HP stays at generation 0). Each success feeds its own PN
and ACK values back into the anchor sets: **512/512** datagrams decrypt.

HTTP/3 + QPACK (dynamic table rebuilt from the server encoder stream) yields 65+ valid
`rr-ledger/1` nodes for the ticket; the trace contains several complete proposals. A DFS from
sequence 0 with `prev[i] == node[i-1]` selects exactly one 24-node chain whose terminal node is
the capsule root. Delivery:

```
delivery key = SHA256("RR delivery 5\0" + export key + SHA256(concat bodies in seq order))
AES-256-GCM(delivery.bin, key, nonce=first 12 bytes, AAD = capsule.ticket || capsule.root)
```

Verified by all 24 node hashes, the 24-link prev->node chain, the terminal root, and the GCM tag.

## Reproduce

```powershell
python writeups\read-receipt\solve.py
```

The driver runs the four stages from the bundled `solver/` tree (physical decode ~3 min,
then catalog solve, pack/4 + receipt, and the QUIC/ledger/delivery recovery). Key artifacts:
`rr3/stream.bin`, `rr3/container.bin`, `rr3/export.r4sp`, `rr3/capsule.json`,
`rr3/chain/final_receipt.txt`.

## Flag

```text
isfcr{affine_90d83e28cac30cc02502c836d5f3ff9d8d8b}
```
