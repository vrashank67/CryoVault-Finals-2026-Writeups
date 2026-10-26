---
title: "FIRMWARE GHOST"
ctf: "CryoVault Finals"
date: 2026-10-24
category: reverse
difficulty: insane
points: 500
flag_format: "isfcr{...}"
author: ""
---

# FIRMWARE GHOST

## Summary

The gateway's state journal (`config-backup.jcfg`) is a 6-shard GF(256) MDS
container whose parity shards were corrupted; that is the `E13` in `uart.log`.
After repairing the journal, the commissioning receipt is recovered by walking
the three firmware generations' key chain:

1. enrollment build (`rootfs-174`, **standard** SHA-256) turns the RTC
   retention bank into `K0` and authenticates the stage-0 ledger record;
2. migration build (`rootfs-live`, **rotated-IV** SHA-256) turns `K0` into
   `K1` and authenticates stage 1;
3. restore build (`rootfs-old`, rotated IV) turns `K1` into the stage-2 key,
   authenticates the committed `SCV3` generation 42, decrypts it with
   AES-128-CTR, and prints the 16-byte commissioning receipt.

The corrupted RTC word `GP[3]` is recovered with a 2³² search against the
stage-0 enrollment tag. The 2018 `NCF1` backup in the diagnostic export is a
decoy: it decrypts to an older `RCPT isfcr{02a2...}` receipt, not the current
committed state.

## Solution

### Step 1: Repair the journal and recover the corrupted RTC word

The journal header describes 9 directory entries and 5 stripes of
6 × 64-byte shards. The MDS coefficients are `(1,0)`, `(0,1)` for the two
parity shards and `(1, 2<<i)` for the four data shards over GF(2⁸) with
polynomial `0x12d`. The supplied copy has corrupted shards; treating the right
pair per stripe as erasures reproduces the logical 1280 bytes and all record
CRCs.

The four `LDR1`/`SCV3`-era stage records and the committed `SCV3` gen 42 /
`CMT4` gen 42 records come from that logical image.

`uart.log` gives the RTC GP registers but truncates `GP[3]` to `0x???`. The
enrollment service (see `rootfs-174/etc/config/services`) passes
`/sys/firmware/gateway/retention` as the 32-byte seal input, and its stage-0
tag is

```
sha256( K0 || 0x00 )[0:8] == a2575ef65bccdc6e
K0 = HMAC-SHA256( policy_v5[0x10:0x30],
                  stageID0 || PVR7[0x20:0x30] || retention[0:16] || u32(3) )
```

Brute-forcing the 4-byte `GP[3]` against that 64-bit tag yields

```
GP[3] = 0xb62747bc
```

which also makes the stage-0 ledger CRC/tag and the rest of the chain valid.

### Step 2: Walk the stage-key chain

With the repaired retention bank `ret` (GP0..GP7, little-endian):

```python
K0 = HMAC_STD(policy_v5[0x10:0x30],
              ID0 + pvr7[0x20:0x30] + ret[0:16] + u32(3))
# stage 0 tag: sha256(K0 || 0) [:8] == a2575ef65bccdc6e

K1 = HMAC_ROT(K0,
              ldr1[0x1c:0x2c] + u32(ldr1+8) + policy_v6[0x10:0x30]
              + ret[0x10:0x1c] + ID1)
# stage 1 tag: sha_rot(K1 || 1)[:8] == 07c32536492a6028

K2 = HMAC_ROT(K1,
              ID2 + ldr2[0x1c:0x2c] + u32(ldr2+8)
              + pvr12[0x20:0x30] + policy_v7[0x30:0x40])
# stage 2 tag: sha_rot(K2 || 2)[:8] == 8994709177381834
```

`HMAC_STD` is ordinary SHA-256 HMAC; `HMAC_ROT` is the firmware's HMAC with the
rotated SHA-256 IV `[bb67ae85, 3c6ef372, ...]`. Both use a 32-byte key
zero-padded to the 64-byte block.

### Step 3: Decrypt the committed state and print the receipt

For the committed `SCV3` gen 42 record:

```python
K1s = HMAC_ROT(policy_v7[0x10:0x30], K2 + ret[0:0x1c])
K2s = HMAC_ROT(K1s, b"GWK7" + ID2 + u32(42) + scv[0x10:0x20] + b"\x01")
iv  = SHA_ROT(b"CTR5" + scv[0x10:0x20] + scv[4:8] + scv[8:12])[0:16]

pt = AES_128_CTR(key=K2s[0:16], iv=iv,
                 counter=little-endian u32 in iv[0:4],
                 ciphertext=scv[0x20:0xe0])
# pt starts "CMAT", u32@4=1, u32@8=1, u32@0xc=42
# CMT4[0x0c:0x2c] == sha_rot(scv)  (commitment verified)

receipt = SHA_ROT(b"GWR7" + pt[0x10:0x30] + ID2 + u32(42) + pt[0x30:0x40])[0:16]
```

The firmware prints the 16-byte receipt as 32 lowercase hex digits. The
complete standalone solver (journal repair, KDFs, AES, assertions) is
`solve.py` in this folder; it prints:

```
isfcr{0bd611fa7690d62f03a6ddcda3f7820e}
```

Validation performed:

* all three stage tags match the stored ledger tags;
* the stage-2 `SCV3` record's full 256-byte hash matches the `CMT4` commitment;
* the real ARM `restore_main` was emulated instruction-by-instruction in
  Unicorn with the repaired journal and `K1`; it prints the same receipt with
  no errors;
* the plaintext has the expected `CMAT` magic, flags and generation.

### Decoy

`diagnostic.tar.gz` contains a 2018 `NCF1` backup. With its printed enclosure
serial `LC-GW-2018-00417`, its HMAC verifies and AES-128-CTR decrypts to
`RCPT isfcr{02a2c84743b53444360ebd32b51a75f6}`. That is an old receipt from
the service backup, not the controller's last committed state.

## Flag

```
isfcr{0bd611fa7690d62f03a6ddcda3f7820e}
```
