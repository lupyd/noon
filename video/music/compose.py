# /// script
# requires-python = ">=3.10"
# dependencies = ["mido", "numpy", "soundfile"]
# ///
"""Original score for the Noon showcase, composed in code: "night to noon".

Reads out/timeline.json (scene starts sit on the beat grid at its BPM) and writes:
  out/music/score.mid          full arrangement (General MIDI)
  out/music/stems/<name>.wav   each part rendered with FluidSynth + GeneralUser GS
  out/music/music.wav          stems mixed

The film opens in the logo's night sky and the product plays out in daylight;
the score follows it:
  intro    night: choir pad, celesta twinkle, cello drone (D minor); a lift on the title
  problem  the night darkens: cello pulse, sparse celesta, swell into the sunrise
  create   sunrise: F major, fingerpicked nylon guitar, marimba, acoustic bass, shaker
  respond  the groove carries on
  blind    hushed: pizzicato and celesta, minor turn, resolves to F
  results  full daylight: groove + tambourine + flute hook
  cta      a strummed Fmaj9 rings out with celesta and the flute's last phrase
"""
import json
import subprocess
import sys
from pathlib import Path

import mido
import numpy as np
import soundfile as sf

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "music"
SF2 = ROOT / "assets" / "soundfont" / "GeneralUser-GS.sf2"
SR = 48000
TPB = 480

tl = json.loads((ROOT / "out" / "timeline.json").read_text())
BPM = tl["bpm"]
BEAT = 60 / BPM
TOTAL_BEATS = int(np.ceil(tl["duration"] / BEAT))
SCENES = [(s["id"], s["start"] / BEAT, s["end"] / BEAT) for s in tl["scenes"]]


def scene_at(beat):
    for sid, a, b in SCENES:
        if a <= beat < b:
            return sid, beat - a, b - a
    return SCENES[-1][0], 0.0, 1.0


def start_of(sid):
    return next(a for s, a, _ in SCENES if s == sid)


# ---- harmony: one chord per bar (4 beats) -----------------------------------
NIGHT = [  # Dm9 | Bbmaj7 | Gm9 | A7sus4
    [38, 57, 60, 64, 65, 69],
    [34, 53, 57, 62, 65, 69],
    [43, 53, 58, 62, 65, 69],
    [45, 55, 62, 64, 67, 69],
]
DAY = [  # Fmaj9 | C/E | Dm7 | Bbmaj9  (I – V/3 – vi7 – IV)
    [41, 57, 60, 64, 67, 69],
    [40, 55, 60, 64, 67, 72],
    [38, 57, 60, 65, 69, 72],
    [46, 57, 60, 62, 65, 69],
]
HUSH = [  # Dm9 | Bbmaj9 | Gm9 | Csus2 → back to F
    [38, 57, 60, 64, 65, 69],
    [46, 57, 60, 62, 65, 69],
    [43, 53, 58, 62, 65, 69],
    [48, 55, 60, 62, 67, 72],
]
FINAL = [29, 41, 57, 60, 64, 67, 69, 72, 76]  # Fmaj9, wide


def chord(beat):
    sid, lb, _ = scene_at(beat)
    bar = int(lb // 4)
    if sid in ("intro", "problem"):
        return NIGHT[bar % 4]
    if sid == "blind":
        return HUSH[bar % 4] if lb < 16 else DAY[0]
    if sid == "cta":
        return FINAL if bar == 0 or lb >= 12 else DAY[bar % 4]
    return DAY[bar % 4]


# ---- MIDI ---------------------------------------------------------------------
class Part:
    def __init__(self, name, program, channel, volume=100, pan=64, reverb=70):
        self.name, self.program, self.channel = name, program, channel
        self.volume, self.pan, self.reverb = volume, pan, reverb
        self.events = []

    def note(self, beat, dur, pitch, vel):
        if beat < 0 or beat >= TOTAL_BEATS:
            return
        a = int(round(beat * TPB))
        b = int(round((beat + dur) * TPB))
        v = int(max(1, min(127, vel)))
        self.events.append((a, mido.Message("note_on", note=int(pitch), velocity=v, channel=self.channel)))
        self.events.append((max(a + 1, b), mido.Message("note_off", note=int(pitch), velocity=0, channel=self.channel)))

    def track(self):
        tr = mido.MidiTrack()
        tr.append(mido.MetaMessage("set_tempo", tempo=mido.bpm2tempo(BPM), time=0))
        tr.append(mido.MetaMessage("track_name", name=self.name, time=0))
        if self.channel != 9:
            tr.append(mido.Message("program_change", program=self.program, channel=self.channel, time=0))
        for ctl, val in ((7, self.volume), (10, self.pan), (91, self.reverb), (93, 8)):
            tr.append(mido.Message("control_change", control=ctl, value=val, channel=self.channel, time=0))
        last = 0
        for tick, msg in sorted(self.events, key=lambda e: (e[0], 0 if e[1].type == "note_off" else 1)):
            tr.append(msg.copy(time=tick - last))
            last = tick
        tr.append(mido.MetaMessage("end_of_track", time=TPB * 8))
        return tr


choir = Part("choir", 52, 0, volume=78, reverb=100)  # Choir aahs: the night air
celesta = Part("celesta", 8, 1, volume=84, pan=84, reverb=96)
cello = Part("cello", 42, 2, volume=82, pan=48)
guitar = Part("guitar", 24, 3, volume=104, pan=44, reverb=55)  # nylon, fingerpicked
marimba = Part("marimba", 12, 4, volume=76, pan=86, reverb=50)
bass = Part("bass", 32, 5, volume=96, reverb=30)  # acoustic bass
pizz = Part("pizz", 45, 6, volume=84, pan=74, reverb=70)
flute = Part("flute", 73, 7, volume=82, pan=58, reverb=80)
perc = Part("perc", 0, 9, volume=92, reverb=40)
parts = [choir, celesta, cello, guitar, marimba, bass, pizz, flute, perc]

rng = np.random.default_rng(7)
DAY_START = start_of("create")


def tones(c, lo, hi):
    """chord tones (any octave) inside [lo, hi]"""
    pcs = sorted({p % 12 for p in c[1:]})
    return [n for n in range(lo, hi + 1) if n % 12 in pcs]


for bar_beat in range(0, TOTAL_BEATS, 4):
    b0 = float(bar_beat)
    sid, lb, n = scene_at(b0 + 0.01)
    c = chord(b0 + 0.01)
    night = sid in ("intro", "problem")
    groove = sid in ("create", "respond", "results")
    low = c[0] if c[0] >= 36 else c[0] + 12

    # --- night bed
    if night:
        for p in c[1:]:
            choir.note(b0, 4, p, 52 if sid == "intro" else 46)
        cello.note(b0, 4, low, 58)
        if sid == "problem":  # the pulse tightens toward the sunrise
            for k in range(4):
                cello.note(b0 + k, 0.9, low, 44 + 6 * k + int(lb))
        hi = tones(c, 76, 93)  # celesta stars: a few high chord tones, scattered
        for k in range(3 if sid == "intro" else 1):
            at = b0 + float(rng.choice([0, 0.5, 1.5, 2, 2.5, 3.5]))
            celesta.note(at, 1.5, int(rng.choice(hi)), 50 + int(rng.integers(0, 14)))

    # --- daylight: fingerpicked guitar under everything from sunrise on
    if groove or (sid == "blind" and lb >= 16) or (sid == "cta" and lb < 4):
        gt = tones(c, 52, 76)
        figure = [None, 2, 3, 4, None, 3, 4, 2]  # bass on 1 and 3, a rolling figure between
        for k, f in enumerate(figure):
            if f is None:
                guitar.note(b0 + k * 0.5, 1.0, low, 70)
            else:
                guitar.note(b0 + k * 0.5, 0.6, gt[min(len(gt) - 1, f + 1)], 56 + (6 if k % 2 else 0))
    if groove:
        mt = tones(c, 72, 88)
        for k in range(8):
            marimba.note(b0 + k * 0.5, 0.45, mt[[0, 2, 1, 3, 0, 2, 4, 3][k] % len(mt)], 48 + (10 if k % 4 == 0 else 0))
        bass.note(b0, 1.5, low if low < 48 else low - 12, 82)
        bass.note(b0 + 2, 1.0, (low if low < 48 else low - 12) + 7, 70)
        bass.note(b0 + 3.5, 0.5, low if low < 48 else low - 12, 60)
        for k in range(16):  # shaker 16ths, off-beats leaning
            perc.note(b0 + k * 0.25, 0.2, 70, 34 + (16 if k % 4 == 2 else 0) + int(rng.integers(0, 6)))
        perc.note(b0, 0.5, 36, 70)  # soft kick on 1 and 3, side stick on 2 and 4
        perc.note(b0 + 2, 0.5, 36, 62)
        perc.note(b0 + 1, 0.3, 37, 40)
        perc.note(b0 + 3, 0.3, 37, 44)
        if sid == "results":
            perc.note(b0 + 1, 0.3, 54, 52)
            perc.note(b0 + 3, 0.3, 54, 56)

    # --- the blind beat: hushed, plucked, a little mysterious
    if sid == "blind" and lb < 16:
        for p in c[2:]:
            choir.note(b0, 4, p, 40)
        pt = tones(c, 55, 79)
        for k in range(8):
            pizz.note(b0 + k * 0.5, 0.4, pt[[0, 2, 4, 2, 1, 3, 5, 3][k] % len(pt)], 54 + (8 if k == 0 else 0))
        bass.note(b0, 3.5, low if low < 48 else low - 12, 62)
        ct = tones(c, 79, 96)
        celesta.note(b0 + 0.5, 1, ct[-1], 46)
        celesta.note(b0 + 2.5, 1, ct[-3], 42)

# --- the lift on "Introducing Noon": a celesta run up
t_title = start_of("intro") + 4.5 / BEAT
for k, p in enumerate(tones(NIGHT[0], 69, 98)[:10]):
    celesta.note(t_title + k * 0.125, 0.8, p, 46 + 3 * k)

# --- sunrise: a strum lands exactly on the cut into daylight
for k, p in enumerate([41, 48, 53, 57, 60, 64, 67]):
    guitar.note(DAY_START + k * 0.04, 3.5, p, 78)
for p in DAY[0][1:]:
    choir.note(DAY_START, 4, p + 12, 44)
perc.note(DAY_START - 0.02, 1.0, 57, 50)  # crash, gently

# --- the flute hook in results, and its last phrase on the end card
HOOK = [(0, 1, 69), (1, 0.5, 72), (1.5, 1.5, 74), (3, 1, 72), (4, 1.5, 77), (5.5, 0.5, 76), (6, 2, 72),
        (8, 1, 74), (9, 0.5, 72), (9.5, 1.5, 69), (11, 1, 67), (12, 4, 69)]
r0 = start_of("results") + 4
for at, d, p in HOOK:
    if r0 + at < start_of("cta"):
        flute.note(r0 + at, d, p, 74)
c0 = start_of("cta")
for at, d, p in [(0.5, 1, 72), (1.5, 1, 74), (2.5, 1.5, 76), (4, 6, 77)]:
    flute.note(c0 + at, d, p, 70)
for k, p in enumerate(tones(FINAL, 76, 100)[:9]):
    celesta.note(c0 + 0.25 + k * 0.16, 2.5, p, 44 + 2 * k)
for p in FINAL:
    choir.note(c0, 14, p + (12 if p < 52 else 0), 46)
bass.note(c0, 12, 29, 74)

# ---- render ------------------------------------------------------------------
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "stems").mkdir(exist_ok=True)
mid = mido.MidiFile(ticks_per_beat=TPB)
for p in parts:
    mid.tracks.append(p.track())
mid.save(OUT / "score.mid")

total_s = tl["duration"]
n_samples = int(round(total_s * SR))


def render_part(p):
    m = mido.MidiFile(ticks_per_beat=TPB)
    m.tracks.append(p.track())
    mp = OUT / "stems" / f"{p.name}.mid"
    wp = OUT / "stems" / f"{p.name}.wav"
    m.save(mp)
    subprocess.run(
        ["fluidsynth", "-ni", "-q", "-g", "0.6", "-r", str(SR), "-o", "synth.reverb.active=1", "-o", "synth.chorus.active=1",
         "-o", "synth.reverb.room-size=0.82", "-o", "synth.reverb.width=1.0", "-o", "synth.reverb.level=0.7",
         "-F", str(wp), str(SF2), str(mp)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    a, sr = sf.read(wp, always_2d=True)
    assert sr == SR
    a = a[:n_samples]
    if len(a) < n_samples:
        a = np.vstack([a, np.zeros((n_samples - len(a), 2))])
    return a


print(f"rendering {len(parts)} stems with FluidSynth…", file=sys.stderr)
stems = {p.name: render_part(p) for p in parts if p.events}
gains = {"choir": 0.8, "celesta": 0.7, "cello": 0.7, "guitar": 1.0, "marimba": 0.6, "bass": 0.85, "pizz": 0.7, "flute": 0.6, "perc": 0.65}
mix = np.zeros((n_samples, 2))
for name, a in stems.items():
    mix += a * gains.get(name, 0.7)

# fade the last 1.5 bars to silence; gentle fade-in on the first 0.5 s
fade = int(6 * BEAT * SR)
mix[-fade:] *= np.linspace(1, 0, fade)[:, None] ** 1.5
fi = int(0.5 * SR)
mix[:fi] *= np.linspace(0, 1, fi)[:, None]

peak = np.max(np.abs(mix)) or 1
mix = mix / peak * 0.89
sf.write(OUT / "music.wav", mix.astype(np.float32), SR, subtype="FLOAT")
print(json.dumps({"bpm": BPM, "beats": TOTAL_BEATS, "seconds": total_s, "stems": list(stems), "out": str(OUT / "music.wav")}))
