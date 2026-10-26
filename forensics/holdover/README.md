---
title: "Incident brief — CryoVault pod row 7"
ctf: "CryoVault"
date: 2026-10-24
category: null
author: ""
flag_format: "isfcr{...}"
---

# Incident brief — CryoVault pod row 7

## Solution

The supplied files match SHA256SUMS. The superblock identifies revision 2, so the 2.4.0 release notes supersede HOLDOVER.md's older layout: headers and records are each 32 bytes, with seven records per page. Record time is page base_tick plus dtick.

Apply the tail's six remaps and validate CRC-32C for the superblock, tail and live pages. Traversal reproduces 4,088 live record pages, 28,594 records and 1,045,824 bytes of live headers and records. Metadata pages are excluded from that byte total.

The historical opening order reveals the repeated lane cycle `5, 0, 3, 4, 1, 2, 7, 6`, supported by 510 complete rounds. Sort by lane_seq and position in this cycle, preserving slots within each page. All six backwards counter jumps begin with AONRST. A global timestamp sort would incorrectly move those reset epochs before the incident.

Reading only kind 0x2A yields:

`d4ya259jyvhfp9c5kkrr2_fd`

The incident latch is ILK op 1 at page 2060, slot 1 (zero-based): tick `1105180039 + 11350 = 1105191389`, state 0x06 to 0x07. It precedes all six recorded rail collapses; the hardware notes say warm resets cannot clear AON.

The manufacture calibration disagrees with the running clock. Release 2.2.0 made TICK an external row-bus minute pulse. There are 17,827 intervals spanning 1,069,678,038 ticks; each interval is 60,003 or 60,004 ticks. Scaling the latch counter by this measured rate gives uptime 1,105,131.424136222 seconds. Allowing two ticks of endpoint variation still truncates to `1105131.42`.

Release code:

`FL-d4ya259jyvhfp9c5kkrr2_fd-1105131.42`

## Reproduction and verification

Run `python solve.py INPUT_DIRECTORY`; add `--open` to invoke the supplied escrow opener. The script validates the layout, reconstructs the marks and computes the pulse-derived uptime.

The original escrow.py accepted the completed computation and printed “release approved.” The authenticated review is saved as `released-review.txt`. `marks.csv` and `incident-order.csv` preserve evidence locations and order.

Platform submission: not submitted; no destination was identified in this request.

## Flag

```
isfcr{hpat392mv7v8qjerbxgjk5jy}
```
