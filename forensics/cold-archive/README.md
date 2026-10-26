---
title: Cold Archive
ctf: CryoVault 2026
date: 2026-10-25
category: null
points: 374
flag_format: isfcr{...}
author: ""
---

# Cold Archive

## Solution

Read `CHART_NOTES.txt` first. Its marking convention identifies a verified reading as a ringed hexadecimal character with **two underlines**. The handwritten number beside the ring specifies its position in the answer. A single underline means a remote reading that was not verified at the dewar and must be excluded.

Extract `cold-archive.zip` and analyze the 2,400 1000×360 monochrome PNG scans. The images contain scanner comments claiming the pencil annotations have no procedural meaning; those comments conflict with the visible evidence and marking convention, so they do not determine the answer.

Use the accompanying OpenCV detector to find closed ring contours. It retains contours whose bounding boxes are 28–150 pixels wide and 28–120 pixels high, with aspect ratio between 0.55 and 1.8, area above 450 pixels, and circularity above 0.60. Inner and outer contours can describe the same ring, so count candidate **files**, rather than contours. This identifies exactly 24 sheets.

Inspect each candidate's original-resolution ring region, enlarged using nearest-neighbor scaling. Sixteen have two separate underline strokes; eight have one. Read the nibble inside each accepted ring and its adjacent ordinal. The accepted ordinals form exactly 1–16, with no gaps or duplicates. Date order is irrelevant to this final ordering.

The ordered transcription and source filenames appear in `readings.csv`. `verified-readings.png` shows all sixteen accepted annotations in answer order, preserving their double underlines for visual verification. The eight excluded single-underlined annotations must not replace accepted readings with the same position number.

## Reproduction

Install Python packages `pillow`, `numpy`, and `opencv-python`, then run:

```sh
python find_rings.py cold-archive/charts
```

Visually apply the convention to the resulting 24 candidate files, then compare the ordered crops and CSV.

## Verified readings

| Position | Nibble | Source scan |
|---|---|---|
| 1 | `7` | `ds_20200714-2154.png` |
| 2 | `d` | `ds_20240903-1126.png` |
| 3 | `2` | `ds_20220127-0204.png` |
| 4 | `b` | `ds_20250923-1922.png` |
| 5 | `9` | `ds_20250228-1558.png` |
| 6 | `e` | `ds_20260207-1301.png` |
| 7 | `4` | `ds_20241225-0940.png` |
| 8 | `a` | `ds_20221207-0554.png` |
| 9 | `f` | `ds_20240516-2148.png` |
| 10 | `6` | `ds_20200325-1041.png` |
| 11 | `1` | `ds_20230119-0113.png` |
| 12 | `c` | `ds_20240916-0825.png` |
| 13 | `3` | `ds_20210515-1752.png` |
| 14 | `0` | `ds_20200821-0525.png` |
| 15 | `8` | `ds_20200421-1431.png` |
| 16 | `5` | `ds_20240713-0016.png` |

## Verification

2,400 scans → 24 ringed sheets → 16 double-underlined readings and 8 exclusions. The accepted position numbers cover 1–16 exactly once.

Submission: not submitted; platform acceptance is not confirmed.

## Flag

```text
isfcr{7d2b9e4af61c3085}
```
