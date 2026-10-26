---
title: "SILENT BROKER"
ctf: "ISFCR PESU"
date: 2026-10-25
category: "IoT"
difficulty: "Insane"
points: 500
flag_format: "isfcr{...}"
author: ""
---

# SILENT BROKER

## Summary

Reconstruct the archive's MQTT deliveries across broker recovery, then authenticate and decrypt the commissioning blocks hidden in telemetry trim registers. The field capture alone includes many messages the archive never received.

## Solution

The pre-capture Mosquitto v6 persistence file retains the deleted lease for `b7/14`: owner `2a3fb3a51aa85adb`, epoch `1640206447`, origin `65514`, slot `11`. Recomputing factory bindings selects `MX-0B17`, revision 4. The similarly printed `MX-OB17` and superseded revision are separate records.

Derive the wrapping key from the selected factory ticket and plant salt using the bulletin's HKDF parameters. Unwrap gateway slot 11 with RFC3394, then derive cipher and MAC material using context `CB3|edge-b7-14|b7/14|1640206447`.

Reassemble TCP streams and parse MQTT with connection-specific topic aliases. Apply broker ACLs and the archive's persisted subscription filters. Track incoming QoS 2 messages by client and packet identifier: a different message reusing the identifier replaces the pending message; identical retransmissions retain the stored copy. Route QoS 2 only at PUBREL, honor session resets, and preserve state across recovery. Account for the archive's disconnection, offline QoS 0 loss, and queued message expiry.

Convert signed trim registers to big-endian unsigned 16-bit bytes. Parse each CB3 header and verify its truncated HMAC against the full resolved topic. The delivered sequence has 48 distinct counters and 51 valid frame deliveries, including three identical retries. Order blocks by `(counter - 65514) mod 65536`, deduplicate retries, concatenate, and split off the final 32-byte mask. Recover the AES key with the bulletin's SHA256/XOR construction and decrypt using the supplied GCM AAD.

## Verification

```sh
pip install scapy cryptography
python solve.py /path/to/evidence
```

The pending incoming messages and outgoing archive queue exactly match the recovery database. Archive packet identifiers match both snapshots: 85 at recovery and 131 at the end. AES-GCM authentication succeeds. The plaintext stages a calibration recipe for `b7/14`, work order `WO-7316`; see `instruction.json`.

Submission: **not submitted**. The configured platform's authentication probe returned HTTP 302; authenticated access could not be confirmed.

Mosquitto behavior was checked against its [2.0.11 source](https://github.com/eclipse-mosquitto/mosquitto/tree/v2.0.11), particularly `src/handle_publish.c`, `src/database.c`, and `src/persist.h`.

## Flag

```text
isfcr{d3l1v3r3d_n07_53n7_3e52ba22199f3d65bd896972}
```
