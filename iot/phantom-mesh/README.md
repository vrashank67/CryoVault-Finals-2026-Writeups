---
title: "PHANTOM MESH"
ctf: "CryoVault 2026"
date: 2026-10-25
category: "IoT"
author: ""
flag_format: "isfcr{...}"
---

# PHANTOM MESH

## Summary

A retired controller impersonated the relay by reusing its Zigbee security nonces. Predictable telemetry exposes the archive instructions even though the network key update was not captured. The accepted token survives in masked allocator slack.

## Solution

Repair each factory row together with its six check octets using Reed–Solomon parameters GF(256), polynomial `0x1cf`, generator `2`, first consecutive root `9`, and six parity octets. All eight recovered installation codes pass their installation-code CRC. Hash the complete code and CRC with AES-MMO, then use Zigbee's specialized keyed hash to derive each key-transport key. Frames 86 and 89 authenticate successfully and reveal network key sequence 7.

Decrypt that epoch with AES-CCM and examine cluster `0xfc43` relay telemetry. Its changing 32-bit attribute follows xorshift32 with shifts `(13,17,5)`; this recurrence matches every consecutive captured relay report. Security frame counters persist across the address change and key switch, so the subsequent telemetry is predictable, including the changing attribute.

Under key sequence 8, telemetry and archive messages reuse the same EUI-64 and security counter. XOR each known telemetry plaintext with its ciphertext to recover the CTR keystream, then decrypt the paired archive ciphertext. Validate captured lengths and radio FCS, and collapse identical repeated PUTs by node ID.

For cluster `0xfc42`, group messages by session and epoch. Transpose each sixteen-byte page as a four-by-four byte matrix, follow the linked nodes, concatenate only their used bytes, and inflate the zlib stream. Both reconstructed streams pass zlib's checksum. Epoch 8 is aborted with reason 2; epoch 9 closes with status zero and contains operation `commissioning-override`, site `COLD-A3`, receipt `0x072a`.

Derive each audit key from its installation-derived link key and EEPROM-order EUI. Unmask unused page bytes with the documented per-node HMAC. Only retired damper `FM-24-0517` produces a valid compact token followed entirely by `0xff` padding. Decode its length-prefixed, six-bit, MSB-first symbols using `abcdefghijklmnopqrstuvwxyz0123456789_`.

## Reproduction and verification

Install `pycryptodome` and `reedsolo`, then run:

```bash
python solve.py /path/to/evidence
```

The directory must contain `challenge.pcapng`, `factory-pages.csv`, and `factory-ecc.csv`. The solver independently reconstructs both epochs and prints the accepted token. Gateway receipt `0000072a` corroborates acceptance. The sequence-8 AES key was not recovered, so its encrypted COMMIT digest and MIC are not claimed as independently verified.

Submission: not submitted; verified offline from the supplied evidence.

## Flag

```text
isfcr{c0un73r_cl0n3_wh15p3r5_1n_7h3_5l4ck}
```

Protocol implementation reference: [Wireshark Zigbee security source](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-zbee-security.c).
