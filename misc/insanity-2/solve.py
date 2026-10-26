"""Insanity #2 solver — decode the "beacon" soundboard sound's spectrogram text.

The guild's soundboard sound (id 1563772229622439996, name "beacon") is a 4.36 s
mono Opus file. It contains seven gated tones at 9000, 10500, 12000, 13500,
15000, 16500 and 18000 Hz (1500 Hz spacing). Each tone is one row of a 7-pixel
tall bitmap; each 40 ms timeslice is one column. Rendering the bitmap gives the
flag in a 5x7 dot-matrix font.

Usage:  python solve.py [path-to-audio]
If no path is given, the sound is downloaded from Discord's CDN.
"""
import io
import subprocess
import sys
import wave

import numpy as np

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FREQS = [9000, 10500, 12000, 13500, 15000, 16500, 18000]
SLOT = 0.040
START = 0.2575
SOUND_ID = "1563772229622439996"
URL = f"https://cdn.discordapp.com/soundboard-sounds/{SOUND_ID}"

# Classic 5x7 dot-matrix glyphs used by the beacon image.
FONT = {
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
    "C": [".####", "#....", "#....", "#....", "#....", "#....", ".####"],
    "D": ["####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."],
    "E": ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
    "F": ["#####", "#....", "#....", "####.", "#....", "#....", "#...."],
    "G": [".####", "#....", "#....", "#..##", "#...#", "#...#", ".###."],
    "H": ["#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "I": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"],
    "J": ["..###", "...#.", "...#.", "...#.", "#..#.", "#..#.", ".##.."],
    "K": ["#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"],
    "L": ["#....", "#....", "#....", "#....", "#....", "#....", "#####"],
    "M": ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"],
    "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"],
    "O": [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "P": ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."],
    "Q": [".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"],
    "R": ["####.", "#...#", "#...#", "####.", "#..#.", "#...#", "#...#"],
    "S": [".####", "#....", "#....", ".###.", "....#", "....#", "####."],
    "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
    "U": ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "V": ["#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."],
    "W": ["#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"],
    "X": ["#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"],
    "Y": ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."],
    "Z": ["#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"],
    "0": [".###.", "#..##", "#.#.#", "#.#.#", "#.#.#", "##..#", ".###."],
    "1": ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."],
    "2": [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
    "3": ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
    "4": ["#..#.", "#..#.", "#..#.", "#####", "...#.", "...#.", "...#."],
    "5": ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."],
    "6": [".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."],
    "7": ["#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."],
    "8": [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."],
    "9": [".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."],
    "{": ["..##.", "..#..", "..#..", ".#...", "..#..", "..#..", "..##."],
    "}": [".##..", "..#..", "..#..", "...#.", "..#..", "..#..", ".##.."],
    "_": [".....", ".....", ".....", ".....", ".....", ".....", "#####"],
    "-": [".....", ".....", ".....", "#####", ".....", ".....", "....."],
    ".": [".....", ".....", ".....", ".....", ".....", ".##..", ".##.."],
    " ": [".....", ".....", ".....", ".....", ".....", ".....", "....."],
}


def load_audio(path):
    if path:
        raw = open(path, "rb").read()
    else:
        import requests

        raw = requests.get(URL, timeout=30).content
    if raw[:4] == b"OggS":
        wav = "beacon_tmp.wav"
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                        "-i", "pipe:0", "-ac", "1", "-ar", "48000", wav],
                       input=raw, check=True)
        w = wave.open(wav, "rb")
        fs = w.getframerate()
        return np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float64) / 32768.0, fs
    w = wave.open(io.BytesIO(raw), "rb")
    fs = w.getframerate()
    return np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float64) / 32768.0, fs


def tone_envelopes(x, fs):
    t = np.arange(len(x)) / fs
    envs = []
    n = max(1, int(fs * 0.002))
    k = np.ones(n) / n
    for f in FREQS:
        z = x * np.exp(-2j * np.pi * f * t)
        envs.append(np.hypot(np.convolve(z.real, k, "same"), np.convolve(z.imag, k, "same")))
    return np.array(envs)


def bitmap(envs, fs, ncols):
    cols = []
    for i in range(ncols):
        t0 = START + i * SLOT
        a, b = int((t0 + 0.010) * fs), int((t0 + 0.030) * fs)
        vals = envs[:, a:b].mean(axis=1)
        peak = vals.max()
        cols.append([1 if vals[k] > max(0.005, peak * 0.25) else 0 for k in range(7)])
    return cols


def ocr(cols):
    out = []
    for c in range(0, len(cols) - 5, 6):
        cell = [""] * 7
        for r in range(7):
            cell[r] = "".join("#" if cols[c + x][6 - r] else "." for x in range(5))
        best, bestd = "?", 99
        for ch, glyph in FONT.items():
            d = sum(a != b for r in range(7) for a, b in zip(cell[r], glyph[r]))
            if d < bestd:
                best, bestd = ch, d
        out.append(best if bestd <= 3 else "?")
    return "".join(out)


def main():
    x, fs = load_audio(sys.argv[1] if len(sys.argv) > 1 else None)
    envs = tone_envelopes(x, fs)
    cols = bitmap(envs, fs, 96)
    for r in range(7):
        print("".join("#" if c[6 - r] else "." for c in cols))
    text = ocr(cols)
    print("\nspectrogram text:", text)
    # The dot-matrix font is uppercase-only; the event flag format is lowercase.
    flag = "isfcr{" + text[6:-1].lower() + "}"
    print("flag:", flag)


if __name__ == "__main__":
    main()
