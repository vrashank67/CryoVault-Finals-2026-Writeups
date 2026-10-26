---
title: "SIGHTLINE"
ctf: "CryoVault 2026"
date: 2026-10-25
category: null
difficulty: null
points: 500
flag_format: "isfcr{...}"
author: ""
---

# SIGHTLINE

## Summary

The contractor camera was the unit beside the ladder. Its 06:10 scan pose faces a blank wall after the 06:05 impact; the 02:51 feed must be read from its inward surveillance view. The fixed cameras provide a way to reconstruct that view.

## Solution

### Reconstruct the camera view

In Blender 5.2.3, `CCTV.002` is at the ladder's corner, identifying it as the displaced unit. The five other camera sightlines converge on the central storage area. Their least-squares intersection estimates the normal surveillance aim point at `(12.663, 7.694, 1.534)`. A render from `CCTV.002` toward that point exposes the legible frost inscription above the racks:

`VFMD-FNLT-KMWD`

The wall-facing pose in the scan is post-impact. The lower frost marks are obstructed by the racking; the clear 4–4–4 inscription in the reconstructed inward view supplies the twelve-letter code. Run `solve.py` with the scan to reproduce the view: `blender -b hall-c_0610.blend --python solve.py`.

## Verification

Local verification: the render shows all twelve letters in the required 4–4–4 grouping. [View the render](sightline_view.png).

Submission: not submitted. The configured CTFd API authentication probe redirected to the login page, so no attempt was made.

## Flag

```text
isfcr{vfmd_fnlt_kmwd}
```
