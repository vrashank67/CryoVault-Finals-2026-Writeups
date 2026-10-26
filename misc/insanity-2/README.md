---
title: "Insanity #2"
ctf: "Cryovault Finals 2026"
date: 2026-10-25
category: misc
difficulty: hard
points: 500
flag_format: "isfcr{...}"
---

# Insanity #2

## Summary

The challenge had no description (`.`). Its artifact was a guild **soundboard
sound** named `beacon`, added two minutes after Wave 5 and readable only through
the Discord API. The sound is a 7-tone spectrogram bitmap: decoding the tone
rows as a 5x7 dot-matrix image spells the flag.

## Solution

### Step 1: Find the artifact

`GET /guilds/1560268852019859538/soundboard-sounds` returns a single sound:

```json
{"name": "beacon", "sound_id": "1563772229622439996", "volume": 0.87,
 "emoji_id": null, "emoji_name": null, "guild_id": "1560268852019859538",
 "available": true}
```

The snowflake `1563772229622439996` is `2026-10-25T04:32:33Z` — 2 min after the
Wave 5 announcement (`04:30:20Z`) that released Insanity #2, and 23 min before
its first blood. `@everyone` does not have `USE_SOUNDBOARD`, so only staff could
create it. The public CDN asset is
`https://cdn.discordapp.com/soundboard-sounds/1563772229622439996`.

### Step 2: Decode the spectrogram bitmap

The 4.36 s Ogg/Opus file gates seven tones at 9000, 10500, 12000, 13500, 15000,
16500 and 18000 Hz (1500 Hz spacing) over a 120 Hz drone. Each 40 ms timeslice is
one column of a 7-pixel-tall bitmap, and every 6 columns (5 pixels + 1 gap) is a
5x7 dot-matrix character.

```python
# solve.py — Insanity #2 (Cryovault Finals 2026)
# Decodes the "beacon" guild soundboard sound's spectrogram bitmap.
import io, subprocess, sys, wave
import numpy as np

FREQS = [9000, 10500, 12000, 13500, 15000, 16500, 18000]
SLOT, START, NCOLS = 0.040, 0.2575, 96
URL = "https://cdn.discordapp.com/soundboard-sounds/1563772229622439996"

FONT = {
 "A":[".###.","#...#","#...#","#####","#...#","#...#","#...#"],
 "B":["####.","#...#","#...#","####.","#...#","#...#","####."],
 "C":[".####","#....","#....","#....","#....","#....",".####"],
 "F":["#####","#....","#....","####.","#....","#....","#...."],
 "I":["#####","..#..","..#..","..#..","..#..","..#..","#####"],
 "N":["#...#","##..#","#.#.#","#..##","#...#","#...#","#...#"],
 "R":["####.","#...#","#...#","####.","#..#.","#...#","#...#"],
 "S":[".####","#....","#....",".###.","....#","....#","####."],
 "0":[".###.","#..##","#.#.#","#.#.#","#.#.#","##..#",".###."],
 "3":["####.","....#","....#",".###.","....#","....#","####."],
 "4":["#..#.","#..#.","#..#.","#####","...#.","...#.","...#."],
 "9":[".###.","#...#","#...#",".####","....#","....#",".###."],
 "{":["..##.","..#..","..#..",".#...","..#..","..#..","..##."],
 "}":[".##..","..#..","..#..","...#.","..#..","..#..",".##.."],
 "_":[".....",".....",".....",".....",".....",".....","#####"],
}

def load():
    import requests
    raw = requests.get(URL, timeout=30).content
    subprocess.run(["ffmpeg","-hide_banner","-loglevel","error","-y","-i","pipe:0",
                    "-ac","1","-ar","48000","beacon.wav"], input=raw, check=True)
    w = wave.open("beacon.wav","rb"); fs = w.getframerate()
    return np.frombuffer(w.readframes(w.getnframes()),dtype=np.int16).astype(float)/32768.0, fs

def main():
    x, fs = load()
    t = np.arange(len(x)) / fs
    k = np.ones(int(fs*0.002)) / int(fs*0.002)          # 2 ms smoothing
    envs = []
    for f in FREQS:                                     # complex demodulation
        z = x * np.exp(-2j*np.pi*f*t)
        envs.append(np.hypot(np.convolve(z.real,k,"same"),
                             np.convolve(z.imag,k,"same")))
    envs = np.array(envs)

    cols = []
    for i in range(NCOLS):                              # one 40 ms column each
        t0 = START + i*SLOT
        v = envs[:, int((t0+0.010)*fs):int((t0+0.030)*fs)].mean(axis=1)
        cols.append([int(v[b] > max(0.005, v.max()*0.25)) for b in range(7)])

    for r in range(7):                                  # print the bitmap
        print("".join("#" if c[6-r] else "." for c in cols))

    out = []
    for c in range(0, len(cols)-5, 6):                  # OCR 5x7 glyphs
        cell = ["".join("#" if cols[c+i][6-r] else "." for i in range(5)) for r in range(7)]
        best = min(FONT.items(),
                   key=lambda kv: sum(a != b for r in range(7)
                                      for a, b in zip(cell[r], kv[1][r])))
        out.append(best[0])
    text = "".join(out)
    print("\nspectrogram text:", text)                  # ISFCR{B34C0N_9A}
    print("flag:", "isfcr{" + text[6:-1].lower() + "}")

main()
```

Output:

```
#####..####.#####..####.####....##..####..####..#..#...####..###..#...#........###...###...##...
..#...#.....#.....#.....#...#...#...#...#.....#.#..#..#.....#..##.##..#.......#...#.#...#...#...
..#...#.....#.....#.....#...#...#...#...#.....#.#..#..#.....#.#.#.#.#.#.......#...#.#...#...#...
..#....###..####..#.....####...#....####...###..#####.#.....#.#.#.#..##........####.#####....#..
..#.......#.#.....#.....#..#....#...#...#.....#....#..#.....#.#.#.#...#...........#.#...#...#...
..#.......#.#.....#.....#...#...#...#...#.....#....#..#.....##..#.#...#...........#.#...#...#...
#####.####..#......####.#...#...##..####..####.....#...####..###..#...#.#####..###..#...#..##...

spectrogram text: ISFCR{B34C0N_9A}
flag: isfcr{b34c0n_9a}
```

Body `B34C0N` is `BEACON`, matching the sound's name; every glyph matched the
5x7 font with Hamming distance 0.

## Flag

```
isfcr{b34c0n_9a}
```
