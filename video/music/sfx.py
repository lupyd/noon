# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy", "scipy", "soundfile"]
# ///
"""Synthesised UI sound effects, placed from out/cues.json (exported by the stage).

Every sound is generated here from sines + filtered noise (no samples), so the
SFX are original and license-free. Writes out/sfx/sfx.wav (48 kHz stereo) and
one preview file per kind in out/sfx/kinds/.
"""
import json
from pathlib import Path

import numpy as np
import soundfile as sf
from scipy.signal import butter, fftconvolve, sosfilt

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "sfx"
SR = 48000
rng = np.random.default_rng(1234)


def t_(d):
    return np.arange(int(d * SR)) / SR


def bp(x, lo, hi, order=2):
    sos = butter(order, [max(20, lo), min(hi, SR / 2 - 100)], btype="band", fs=SR, output="sos")
    return sosfilt(sos, x)


def hp(x, f, order=2):
    return sosfilt(butter(order, f, btype="high", fs=SR, output="sos"), x)


def lp(x, f, order=2):
    return sosfilt(butter(order, f, btype="low", fs=SR, output="sos"), x)


def glide(f0, f1, d, curve=2.0):
    t = t_(d)
    k = (t / d) ** (1 / curve)
    f = f0 + (f1 - f0) * k
    return np.sin(2 * np.pi * np.cumsum(f) / SR)


def env_exp(d, tau, attack=0.002):
    t = t_(d)
    a = np.minimum(1, t / attack) if attack > 0 else 1
    return a * np.exp(-t / tau)


def swept_noise(d, f0, f1, width=0.6, shape="arc"):
    """noise through a band-pass whose centre sweeps f0 → f1 (block overlap-add)."""
    n = int(d * SR)
    noise = rng.standard_normal(n + 4096)
    out = np.zeros(n + 4096)
    blk = 1024
    hop = blk // 2
    win = np.hanning(blk)
    for s in range(0, n, hop):
        k = s / max(1, n - 1)
        fc = f0 * (f1 / f0) ** k
        seg = bp(noise[s:s + blk + 512], fc * (1 - width / 2), fc * (1 + width / 2))[256:256 + blk]
        if len(seg) < blk:
            break
        out[s:s + blk] += seg * win
    out = out[:n]
    t = np.linspace(0, 1, n)
    if shape == "arc":
        e = np.sin(np.pi * t ** 0.8) ** 1.6
    else:  # rise
        e = t ** 2 * (1 - np.clip((t - 0.92) / 0.08, 0, 1))
    return out * e


def stereo(x, pan=0.0):
    l = np.cos((pan + 1) * np.pi / 4)
    r = np.sin((pan + 1) * np.pi / 4)
    return np.stack([x * l, x * r], axis=1)


def autopan(x, p0, p1):
    p = np.linspace(p0, p1, len(x))
    return np.stack([x * np.cos((p + 1) * np.pi / 4), x * np.sin((p + 1) * np.pi / 4)], axis=1)


def norm(x, peak=0.9):
    m = np.max(np.abs(x)) or 1
    return x / m * peak


# ---- sound designs --------------------------------------------------------
def whoosh(d=0.75):
    x = swept_noise(d, 350, 2600, 0.9) + 0.4 * swept_noise(d, 900, 5000, 0.5)
    return autopan(norm(x), -0.5, 0.5)


def sweep():
    x = swept_noise(1.25, 250, 7000, 0.7, "arc") + 0.25 * glide(300, 1800, 1.25) * np.sin(np.pi * np.linspace(0, 1, int(1.25 * SR))) ** 2
    return autopan(norm(x), -0.8, 0.8)


def pop(f0=980, f1=560):
    d = 0.14
    x = glide(f0, f1, d, 0.6) * env_exp(d, 0.035, 0.001) + 0.25 * glide(2 * f0, 2 * f1, d, 0.6) * env_exp(d, 0.015, 0.001)
    click = hp(rng.standard_normal(len(x)), 3000) * env_exp(d, 0.002, 0.0002) * 0.3
    return stereo(norm(x + click, 0.8))


def bubble():
    return pop(1500 + rng.uniform(-200, 300), 900)


def click():
    d = 0.05
    x = hp(rng.standard_normal(int(d * SR)), 2500) * env_exp(d, 0.003, 0.0003) + 0.5 * np.sin(2 * np.pi * 3200 * t_(d)) * env_exp(d, 0.008, 0.0005)
    x += 0.6 * np.sin(2 * np.pi * 180 * t_(d)) * env_exp(d, 0.012, 0.001)
    return stereo(norm(x, 0.7))


def key():
    d = 0.06
    x = bp(rng.standard_normal(int(d * SR)), 1800, 6500) * env_exp(d, 0.004, 0.0003)
    x += 0.7 * np.sin(2 * np.pi * rng.uniform(150, 220) * t_(d)) * env_exp(d, 0.014, 0.001)
    return stereo(norm(x, 0.6), rng.uniform(-0.3, 0.1))


def lock():
    d = 0.35
    t = t_(d)
    metal = sum(np.sin(2 * np.pi * f * t) * a for f, a in [(2150, 1), (3420, 0.7), (5230, 0.45), (7900, 0.25)]) * env_exp(d, 0.03, 0.0005)
    metal += hp(rng.standard_normal(len(t)), 4000) * env_exp(d, 0.006, 0.0003) * 0.8
    thunk = np.zeros_like(t)
    o = int(0.058 * SR)
    th = np.sin(2 * np.pi * 135 * t[:-o]) * env_exp(d - o / SR, 0.05, 0.001)
    th += bp(rng.standard_normal(len(t) - o), 500, 1400) * env_exp(d - o / SR, 0.02, 0.0005) * 0.8
    thunk[o:] = th
    return stereo(norm(0.55 * metal + thunk, 0.9))


def unlock():
    d = 0.4
    x = lock()[:, 0][::-1][: int(0.2 * SR)] * 0.5
    up = glide(700, 1400, 0.18, 0.7) * env_exp(0.18, 0.06, 0.002)
    out = np.zeros(int(d * SR))
    out[: len(x)] += x
    out[int(0.12 * SR): int(0.12 * SR) + len(up)] += up * 0.7
    return stereo(norm(out, 0.8))


def data():
    d = 0.6
    out = np.zeros(int(d * SR))
    for k in range(14):
        s = int(k * 0.04 * SR)
        f = rng.choice([1180, 1560, 1980, 2350, 2790])
        b = 0.025
        sq = np.sign(np.sin(2 * np.pi * f * t_(b))) * env_exp(b, 0.008, 0.0005)
        out[s:s + len(sq)] += lp(sq, 4500) * (0.6 + 0.4 * rng.random())
    return autopan(norm(out, 0.6), -0.2, 0.2)


def tick():
    d = 0.04
    x = np.sin(2 * np.pi * 1850 * t_(d)) * env_exp(d, 0.006, 0.0005)
    return stereo(norm(x, 0.6))


def bell(freqs, d=1.2, tau=0.35):
    t = t_(d)
    x = np.zeros_like(t)
    for f in freqs:
        x += np.sin(2 * np.pi * f * t) * np.exp(-t / tau) + 0.3 * np.sin(2 * np.pi * f * 2.76 * t) * np.exp(-t / (tau * 0.4))
    x *= np.minimum(1, t / 0.003)
    return x


def chime():
    d = 1.3
    a = bell([1318.5], d, 0.4)
    b = bell([1975.5], d, 0.45)
    out = a.copy()
    o = int(0.11 * SR)
    out[o:] += b[: len(out) - o]
    return stereo(norm(out, 0.7), 0.15)


def verify():
    d = 0.7
    a = bell([1760], d, 0.18)
    b = bell([2637], d, 0.22)
    out = a.copy()
    o = int(0.07 * SR)
    out[o:] += b[: len(out) - o]
    return stereo(norm(out, 0.65), rng.uniform(-0.3, 0.3))


def blip():
    d = 0.12
    return stereo(norm(glide(880, 1320, d, 0.5) * env_exp(d, 0.05, 0.002), 0.6))


def drop():
    d = 0.22
    return stereo(norm(glide(660, 300, d, 0.7) * env_exp(d, 0.08, 0.002), 0.6), -0.2)


def ring():
    d = 0.9
    out = np.zeros(int(d * SR))
    for k, s in enumerate([0, 0.18]):
        x = bell([880, 1108.7], 0.5, 0.12)
        o = int(s * SR)
        out[o:o + len(x)] += x[: len(out) - o]
    return stereo(norm(out, 0.6))


def alert():
    d = 0.22
    t = t_(d)
    x = lp(np.sign(np.sin(2 * np.pi * 330 * t)), 1600) * (np.minimum(1, t / 0.004) * np.exp(-t / 0.07))
    return stereo(norm(x, 0.5), 0.2)


def scan():
    d = 3.6
    t = t_(d)
    hum = np.sin(2 * np.pi * 110 * t) * 0.3 + np.sin(2 * np.pi * 220.7 * t) * 0.15
    x = hum + swept_noise(d, 600, 2400, 0.25) * 0.5
    e = np.sin(np.pi * np.clip(t / d, 0, 1)) ** 0.7
    return autopan(norm(x * e, 0.5), -0.7, 0.4)


def shatter():
    d = 1.4
    n = int(d * SR)
    out = np.zeros(n)
    for _ in range(80):
        s = int(rng.uniform(0, 0.55) * SR * rng.uniform(0.3, 1))
        f = rng.uniform(2200, 9000)
        dd = rng.uniform(0.04, 0.25)
        x = np.sin(2 * np.pi * f * t_(dd)) * env_exp(dd, dd / 4, 0.0003) * rng.uniform(0.2, 1)
        out[s:s + len(x)] += x[: n - s]
    burst = hp(rng.standard_normal(n), 1800) * env_exp(d, 0.09, 0.0005) * 2.5
    thump = np.sin(2 * np.pi * 70 * t_(d)) * env_exp(d, 0.09, 0.001) * 2
    st = np.stack([out + burst * 0.8 + thump, np.roll(out, 211) + burst * 0.8 + thump], axis=1)
    return norm(st, 0.9)


def glitch():
    d = 0.4
    n = int(d * SR)
    out = np.zeros(n)
    s = 0
    while s < n:
        seg = int(rng.uniform(0.008, 0.035) * SR)
        if rng.random() > 0.35:
            src = rng.standard_normal(seg) if rng.random() > 0.5 else np.sign(np.sin(2 * np.pi * rng.uniform(200, 2000) * t_(seg / SR)))
            out[s:s + seg] = np.round(src[: n - s] * 4) / 4 * rng.uniform(0.2, 0.8)
        s += seg
    return autopan(norm(bp(out, 300, 7000), 0.6), 0.4, -0.4)


def impact(soft=False):
    d = 2.4
    t = t_(d)
    f = 48 + 60 * np.exp(-t / 0.06)
    sub = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / (0.5 if not soft else 0.35))
    body = lp(rng.standard_normal(len(t)), 900) * env_exp(d, 0.08, 0.001) * 0.9
    air = hp(rng.standard_normal(len(t)), 5000) * env_exp(d, 0.4, 0.01) * 0.12
    x = sub * 1.2 + body + air
    return norm(np.stack([x, x * 0.98], axis=1), 0.95 if not soft else 0.7)


def shimmer():
    d = 1.6
    x = swept_noise(d, 5000, 9000, 0.4)
    return autopan(norm(x, 0.4), -0.4, 0.4)


KINDS = {
    "whoosh": whoosh, "sweep": sweep, "pop": pop, "bubble": bubble, "click": click, "key": key,
    "lock": lock, "unlock": unlock, "data": data, "tick": tick, "chime": chime, "verify": verify,
    "blip": blip, "drop": drop, "ring": ring, "alert": alert, "scan": scan, "shatter": shatter,
    "glitch": glitch, "impact": impact, "boom": lambda: impact(True), "shimmer": shimmer,
}
# per-kind trims so the bus is balanced by ear-ish (pops quieter than impacts)
TRIM = {"whoosh": 0.5, "sweep": 0.55, "pop": 0.45, "bubble": 0.35, "click": 0.5, "key": 0.45, "lock": 0.75,
        "unlock": 0.6, "data": 0.4, "tick": 0.35, "chime": 0.45, "verify": 0.45, "blip": 0.4, "drop": 0.4,
        "ring": 0.4, "alert": 0.4, "scan": 0.35, "shatter": 0.7, "glitch": 0.45, "impact": 0.8, "boom": 0.6, "shimmer": 0.35}


def main():
    tl = json.loads((ROOT / "out" / "timeline.json").read_text())
    cues = json.loads((ROOT / "out" / "cues.json").read_text())
    n = int(round(tl["duration"] * SR)) + SR * 3
    bus = np.zeros((n, 2))
    (OUT / "kinds").mkdir(parents=True, exist_ok=True)
    for name, fn in KINDS.items():
        sf.write(OUT / "kinds" / f"{name}.wav", fn().astype(np.float32), SR)
    missing = set()
    for c in cues:
        fn = KINDS.get(c["kind"])
        if not fn:
            missing.add(c["kind"])
            continue
        x = fn() * c.get("gain", 1) * TRIM.get(c["kind"], 0.5)
        s = int(c["t"] * SR)
        if s < 0 or s >= n:
            continue
        e = min(n, s + len(x))
        bus[s:e] += x[: e - s]
    # small synthetic room so the SFX sit in the same space as the music
    ir_n = int(0.9 * SR)
    tt = np.arange(ir_n) / SR
    ir = np.stack([rng.standard_normal(ir_n), rng.standard_normal(ir_n)], axis=1) * np.exp(-tt / 0.22)[:, None]
    ir = np.stack([lp(ir[:, 0], 6000), lp(ir[:, 1], 6000)], axis=1)
    ir /= np.sqrt(np.sum(ir ** 2, axis=0, keepdims=True))
    wet = np.stack([fftconvolve(bus[:, 0], ir[:, 0])[:n], fftconvolve(bus[:, 1], ir[:, 1])[:n]], axis=1)
    out = bus + 0.18 * wet
    out = out[: int(round(tl["duration"] * SR))]
    peak = np.max(np.abs(out)) or 1
    if peak > 0.95:
        out *= 0.95 / peak
    sf.write(OUT / "sfx.wav", out.astype(np.float32), SR, subtype="FLOAT")
    print(json.dumps({"cues": len(cues), "missing": sorted(missing), "peak": float(peak), "out": str(OUT / "sfx.wav")}))


if __name__ == "__main__":
    main()
