---
title: "GHOST FRAMES"
ctf: "CryoVault Finals"
date: 2026-10-24
category: misc
difficulty: hard
points: 500
flag_format: "isfcr{...}"
author: ""
---

# GHOST FRAMES

## Summary

The thermal-camera pull (`hallc_cam07_patrol.mkv`) is 1202 frames of 1-bit noise (pixel values
`70`/`186`) with a burned-in `FROSTLINE HALL C CAM 07 PRESET n` OSD. Every frame is a copy of the
same noise texture shifted by the camera's pan, except for the rack-tag regions, which are
re-randomised on every frame. Aligning each frame to its predecessor and averaging the aligned
difference inside each of the four presets reveals the tag text as a "ghost" and yields the
12 rack-tag identifiers.

## Solution

### Step 1: Understand what the "video" actually contains

`ffprobe` shows a lossless FFV1 `gray` stream at 384x216, 30 fps, 1202 frames. The first 11 rows
are a 2-level (`24`/`200`) OSD: a constant `FROSTLINE HALL C CAM 07 PRESET n` plus a synthetic
clock whose "centiseconds" are just `frame % 30`, so the header carries no data. The rest of the
frame is pure 1-bit noise (`70`/`186`, exactly 50/50, spatially and temporally white) â€” a naive
temporal average of a preset is flat grey, so nothing is visible directly.

The one non-random property is that **consecutive frames are near-copies**: phase correlation
between frame *i* and *i+1* peaks at small integer shifts (a slow camera pan), with ~88% of pixels
matching. The remaining ~12% is the tell: in the tag areas the author replaced the pixels with
fresh noise *every* frame, so those pixels flip at ~50% while the panning background flips at
~12%. Averaging the *aligned* frame difference over a few dozen frames paints the tag text.

### Step 2: Recover and decode the tags

Preset boundaries come free from the OSD (frames 0, 264, 522, 840). For each preset the script
picks the crispest 28-frame window, averages the aligned XOR, thresholds it, splits the mask into
glyph boxes and matches each 5x7 glyph against the OSD bitmap font:

```python
#!/usr/bin/env python3
"""GHOST FRAMES - CryoVault Finals 2026 (Misc, 500).

The recording is 1-bit noise (pixels 70/186) plus a burned-in OSD header.
Consecutive frames are the same noise texture shifted by the camera pan, except
where a rack tag is: those pixels are re-randomised every frame (~50% flip) while
the panning background only flips ~12%.  Aligning each frame to the previous one
and averaging the difference inside a preset therefore paints the tag text.

Usage: python solve.py [hallc_cam07_patrol.mkv]
"""
import os, subprocess, sys
import numpy as np, cv2

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = [os.path.join(HERE, 'input', 'hallc_cam07_patrol.mkv'),
           os.path.join(HERE, '..', '..', 'challenges', 'ghost-frames', 'input',
                        'hallc_cam07_patrol.mkv')]
SRC = sys.argv[1] if len(sys.argv) > 1 else next(
    (p for p in DEFAULT if os.path.exists(p)), DEFAULT[0])

# 5x7 OSD glyphs observed in this recording
GLYPHS = {
    'F': "11111 10000 10000 11110 10000 10000 10000",
    'T': "11111 00100 00100 00100 00100 00100 00100",
    '7': "11111 00001 00010 00100 01000 01000 01000",
    'U': "10001 10001 10001 10001 10001 10001 01110",
    'E': "11111 10000 10000 11110 10000 10000 11111",
    '9': "01110 10001 10001 01111 00001 00010 01100",
    'N': "10001 10001 11001 10101 10011 10001 10001",
    'L': "10000 10000 10000 10000 10000 10000 11111",
}
GLYPHS = {k: np.array([[c == '1' for c in r] for r in v.split()], np.uint8)
          for k, v in GLYPHS.items()}

# ---- 1. decode the FFV1 stream straight into memory ------------------------
wh = subprocess.run(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
                     '-show_entries', 'stream=width,height', '-of', 'csv=p=0', SRC],
                    capture_output=True, text=True, check=True).stdout.strip().split(',')
W, H = int(wh[0]), int(wh[1])
raw = subprocess.run(['ffmpeg', '-v', 'error', '-i', SRC, '-vsync', '0',
                      '-f', 'rawvideo', '-pix_fmt', 'gray', '-'],
                     capture_output=True, check=True).stdout
frames = np.frombuffer(raw, np.uint8)[: (len(raw) // (W * H)) * W * H].reshape(-1, H, W)
print('frames', frames.shape)

# ---- 2. aligned frame difference ("ghost map") ----------------------------
A = (frames[:, 11:, :] > 128).astype(np.uint8)      # drop the OSD header band
N, h, w = A.shape
Y = np.broadcast_to(np.arange(h)[:, None], (h, w))
X = np.broadcast_to(np.arange(w)[None, :], (h, w))
D = np.zeros((N - 1, h, w), np.float32)
for i in range(N - 1):
    a = A[i].astype(np.float32) - .5
    b = A[i + 1].astype(np.float32) - .5
    c = np.fft.irfft2(np.fft.rfft2(a) * np.conj(np.fft.rfft2(b)), s=(h, w))
    k = np.unravel_index(np.argmax(c), c.shape)
    dy = k[0] if k[0] <= h // 2 else k[0] - h
    dx = k[1] if k[1] <= w // 2 else k[1] - w
    yy, xx = Y - dy, X - dx                      # a[y,x] == b[y-dy, x-dx]
    ok = (yy >= 0) & (yy < h) & (xx >= 0) & (xx < w)
    d = np.ones((h, w), np.float32)
    d[ok] = (A[i][ok] != A[i + 1][yy[ok], xx[ok]])
    D[i] = d
D = D[:, :, : w - 2]                              # drop wrap-around border

# ---- 3. split into camera presets via the OSD ("... PRESET n") ------------
band = frames[:, 2:9, :246]
keys = [k for k in (hash(band[i].tobytes()) for i in range(len(band)))]
cuts = [i for i in range(1, len(keys)) if keys[i] != keys[i - 1]] + [N]
bounds = list(zip([0] + cuts[:-1], cuts))

# ---- 4. ghost-average each preset and read the 5x7 glyphs -----------------
tags = []
for p, (lo, hi) in enumerate(bounds, 1):
    best, score = None, -1e18
    for s in range(lo + 20, hi - 28, 8):          # crispest 28-frame window
        M = D[s:s + 28].mean(axis=0)
        if float(M[40:170].sum()) > score:
            score, best, bs = float(M[40:170].sum()), M, s
    m = cv2.morphologyEx((best > 0.32).astype(np.uint8), cv2.MORPH_OPEN,
                         np.ones((3, 3), np.uint8))
    cols = m.sum(axis=0)
    runs, st = [], None
    for x in range(m.shape[1]):
        if cols[x] and st is None:
            st = x
        if not cols[x] and st is not None:
            if x - st >= 12:
                runs.append((st, x - 1))
            st = None
    word = ''
    for x0, x1 in runs:
        g = m[:, x0:x1 + 1]
        g = g[np.where(g.sum(1) > 0)[0].min():np.where(g.sum(1) > 0)[0].max() + 1]
        gh, gw = g.shape
        grid = np.array([[g[min(int((r + .5) * gh / 7), gh - 1),
                            min(int((c + .5) * gw / 5), gw - 1)]
                          for c in range(5)] for r in range(7)], np.uint8)
        word += min(GLYPHS, key=lambda ch: int(np.abs(GLYPHS[ch] - grid).sum()))
    print('preset %d  frames %4d-%4d  window %4d  -> %s' % (p, lo, hi - 1, bs, word))
    tags.append(word)

ids = ''.join(tags)
print('\n12 rack tags:', ' '.join(tags))
print('sequence    :', ids)
print('flag        : isfcr{%s}' % '_'.join(tags))
```

Output:

```text
frames (1202, 216, 384)
preset 1  frames    0- 263  window  188  -> FT7
preset 2  frames  264- 521  window  348  -> UTF
preset 3  frames  522- 839  window  782  -> ET9
preset 4  frames  840-1201  window 1068  -> NFL

12 rack tags: FT7 UTF ET9 NFL
sequence    : FT7UTFET9NFL
flag        : isfcr{ft7utfet9nfl}
```

The four recovered ghost maps (frames 188, 348, 782, 1068) are in `ghostmaps.png`.

## Flag

```text
isfcr{ft7utfet9nfl}
```

