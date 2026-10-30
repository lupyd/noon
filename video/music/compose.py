# /// script
# requires-python = ">=3.10"
# dependencies = ["mido", "numpy", "soundfile"]
# ///
"""Original score for the Noon showcase, composed in code.

Reads out/timeline.json (scene starts are whole bars at its BPM) and writes:
  out/music/score.mid          full arrangement (General MIDI)
  out/music/stems/<name>.wav   each part rendered with FluidSynth + GeneralUser GS
  out/music/music.wav          stems mixed with kick-keyed sidechain ducking

Style: warm, minimal, uplifting tech-product bed. D major, vi-IV-I-V family.
  hook     pads only, sparse bell motif
  problem  darker minor voicings, muted 8th pulse, riser into the reveal
  reveal   impact + plucked arpeggio enters (the lift)
  e2ee..   groove: soft 808 kick/hat, sub bass, arp
  teams    full: adds EP counter-melody + claps
  gamers   energy: 16th hats, saw-lead hook, chord stabs
  everyw.  full build
  cta      drop to a big held chord, then a quiet bed for the end card
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
BAR_S = tl["bar"]
TOTAL_BARS = round(tl["duration"] / BAR_S)
# Noon scene ids → the arrangement styles below: the logo intro is the pad-and-bell
# hook, the problem card darkens, the product lifts in on "create", the groove carries
# the respond/blind beats, results gets the full band, then the end card.
STYLE = {"intro": "hook", "create": "reveal", "respond": "e2ee", "blind": "e2ee", "results": "teams"}
# contiguous runs of bars sharing a style form one section
_runs = []
for _s in tl["scenes"]:
    _a, _b = round(_s["start"] / BAR_S), round(_s["end"] / BAR_S)
    _k = STYLE.get(_s["id"], _s["id"])
    if _b <= _a:
        continue
    if _runs and _runs[-1][0] == _k:
        _runs[-1][2] = _b
    else:
        _runs.append([_k, _a, _b])
SCENES = {}
for _k, _a, _b in _runs:
    _n = _k
    while _n in SCENES:
        _n += "_2"
    SCENES[_n] = (_a, _b)


def section(bar):
    for k, (a, b) in SCENES.items():
        if a <= bar < b:
            return k.split("_2")[0], bar - a, b - a
    return "cta", 0, 1


# ---- harmony ---------------------------------------------------------------
# chords as MIDI note lists (voicings around middle C), one per bar
D = 62
BRIGHT = [  # Bm9 | Gmaj9 | Dmaj9/F# | Asus4->A
    [47, 59, 62, 66, 69, 73],
    [43, 59, 62, 66, 69, 71],
    [42, 57, 62, 64, 66, 69],
    [45, 57, 62, 64, 69, 71],
]
DARK = [  # Bm | Gmaj7#11-ish | Em9 | F#sus4 (tension)
    [47, 59, 62, 66, 71],
    [43, 59, 62, 67, 73],
    [40, 59, 62, 66, 67],
    [42, 59, 61, 66, 71],
]
FINAL = [38, 57, 62, 64, 66, 69, 73, 76]  # Dmaj9 (add 13 colour)


def chord_for(bar):
    sec, i, n = section(bar)
    if sec == "problem":
        return DARK[i % 4]
    if sec == "cta":
        return FINAL if i < 2 else BRIGHT[(i - 2) % 4] if i < n - 2 else FINAL
    return BRIGHT[bar % 4]


# ---- MIDI writing ----------------------------------------------------------
class Part:
    def __init__(self, name, program, channel, bank=0, volume=100, pan=64):
        self.name, self.program, self.channel, self.bank = name, program, channel, bank
        self.volume, self.pan = volume, pan
        self.events = []  # (tick, msg)

    def note(self, beat, dur_beats, pitch, vel):
        a = int(round(beat * TPB))
        b = int(round((beat + dur_beats) * TPB))
        vel = int(max(1, min(127, vel)))
        self.events.append((a, mido.Message("note_on", note=int(pitch), velocity=vel, channel=self.channel)))
        self.events.append((max(a + 1, b), mido.Message("note_off", note=int(pitch), velocity=0, channel=self.channel)))

    def cc(self, beat, ctrl, val):
        self.events.append((int(round(beat * TPB)), mido.Message("control_change", control=ctrl, value=int(max(0, min(127, val))), channel=self.channel)))

    def track(self, with_tempo=True):
        tr = mido.MidiTrack()
        if with_tempo:
            tr.append(mido.MetaMessage("set_tempo", tempo=mido.bpm2tempo(BPM), time=0))
        tr.append(mido.MetaMessage("track_name", name=self.name, time=0))
        tr.append(mido.Message("program_change", program=self.program, channel=self.channel, time=0))
        tr.append(mido.Message("control_change", control=7, value=self.volume, channel=self.channel, time=0))
        tr.append(mido.Message("control_change", control=10, value=self.pan, channel=self.channel, time=0))
        tr.append(mido.Message("control_change", control=91, value=70, channel=self.channel, time=0))  # reverb send
        tr.append(mido.Message("control_change", control=93, value=20, channel=self.channel, time=0))  # chorus
        ev = sorted(self.events, key=lambda e: (e[0], 0 if e[1].type == "note_off" else 1))
        last = 0
        for tick, msg in ev:
            tr.append(msg.copy(time=tick - last))
            last = tick
        tr.append(mido.MetaMessage("end_of_track", time=TPB * 8))
        return tr


pad = Part("pad", 89, 0, volume=92)          # Pad 2 (warm)
strings = Part("strings", 49, 1, volume=70)  # Slow strings, glue for big moments
arp = Part("arp", 46, 2, volume=88, pan=78)  # Orchestral harp: plucky, warm
ep = Part("keys", 4, 3, volume=80, pan=50)   # Electric piano 1 counter-melody
bass = Part("bass", 38, 4, volume=96)        # Synth bass 1
lead = Part("lead", 81, 5, volume=58, pan=70)  # Saw lead (gamers only), quiet
bell = Part("bell", 14, 6, volume=74, pan=40)  # Tubular-ish bell motif (hook / cta)
drums = Part("drums", 25, 9, bank=128, volume=100)  # TR-808 kit

KICK, SNARE, CLAP, HAT, OHAT, CRASH, RIDE, TOM = 36, 38, 39, 42, 46, 49, 51, 45

kicks = []  # seconds, for sidechain

rng = np.random.default_rng(7)
for bar in range(TOTAL_BARS):
    sec, i, n = section(bar)
    b0 = bar * 4
    ch = chord_for(bar)
    root = ch[0]
    upper = ch[1:]

    # --- pads: everywhere, swell per bar
    pad_vel = {"hook": 62, "problem": 58, "reveal": 70, "cta": 72}.get(sec, 66)
    if sec == "cta" and i >= n - 1:
        pad_vel = 50
    for p in upper:
        pad.note(b0, 4.0, p, pad_vel)
    pad.cc(b0, 11, 70)
    pad.cc(b0 + 1.5, 11, 110)
    if sec in ("reveal", "teams", "everywhere") or (sec == "cta" and i < 2):
        for p in upper[-3:]:
            strings.note(b0, 4.0, p + 12, 52)

    # --- bell motif: hook + end card (sparse, memorable 4-note figure)
    if sec == "hook" or (sec == "cta" and i >= 2):
        motif = [(0, 78), (1.5, 81), (2, 76), (3, 74)] if bar % 2 == 0 else [(0, 74), (2.5, 73), (3, 69)]
        for (bt, p) in motif:
            bell.note(b0 + bt, 1.4, p, 54 if sec == "hook" else 46)

    # --- problem: muted 8th pulse + rising tension
    if sec == "problem":
        for k in range(8):
            bass.note(b0 + k * 0.5, 0.32, root + 12 if k % 4 == 3 else root, 70 + 4 * i)
        for k in range(4):
            drums.note(b0 + k + 0.5, 0.1, HAT, 38 + 5 * i)
        if i == n - 1:  # snare roll into the reveal
            for k in range(16):
                drums.note(b0 + 2 + k * 0.125, 0.1, SNARE, 30 + k * 5)

    # --- reveal onwards: arp
    groove = sec in ("e2ee", "mls", "devices", "teams", "gamers", "everywhere")
    if sec == "reveal" or groove or (sec == "cta" and 2 <= i < n - 1):
        pattern = [0, 2, 1, 3, 2, 4, 3, 1] if sec != "gamers" else [0, 2, 4, 2, 1, 3, 4, 3]
        notes = sorted(set(upper))[-5:]
        step = 0.5 if sec not in ("gamers",) else 0.25
        count = int(4 / step)
        for k in range(count):
            p = notes[pattern[k % len(pattern)] % len(notes)] + 12
            v = 60 + (10 if k % 4 == 0 else 0) - (12 if sec == "cta" else 0)
            if sec == "reveal" and i == 0 and k < 4:
                continue  # let the impact breathe
            arp.note(b0 + k * step, step * 0.9, p, v)

    # --- impacts
    if (sec == "reveal" and i == 0) or (sec == "cta" and i == 0) or (sec == "gamers" and i == 0) or (sec == "teams" and i == 0):
        drums.note(b0, 2, CRASH, 90 if sec != "teams" else 70)
        drums.note(b0, 0.5, KICK, 120)
        kicks.append(b0 * 60 / BPM)
        for p in ch:
            strings.note(b0, 4.0, p + 12, 60)
        bass.note(b0, 3.5, root - 12 if root > 40 else root, 110)

    # --- groove
    if groove:
        energy = {"e2ee": 1, "mls": 1, "devices": 1, "teams": 2, "gamers": 3, "everywhere": 2}[sec]
        light = sec == "e2ee" and i < 2
        for k in range(4):
            if light and k % 2 == 1:
                continue
            drums.note(b0 + k, 0.4, KICK, 104)
            kicks.append((b0 + k) * 60 / BPM)
        hat_step = 0.25 if energy >= 3 else 0.5
        for k in range(int(4 / hat_step)):
            bt = b0 + k * hat_step
            if hat_step == 0.5 and k % 2 == 0:
                continue  # offbeat 8ths
            drums.note(bt, 0.1, HAT, 48 + int(rng.integers(0, 14)) + (6 if k % 2 else 0))
        if energy >= 2:
            drums.note(b0 + 1, 0.2, CLAP, 72)
            drums.note(b0 + 3, 0.2, CLAP, 76)
        if energy >= 2 and i % 2 == 1:
            drums.note(b0 + 3.5, 0.2, OHAT, 50)
        # bass: root 8ths with octave pops
        for k in range(8):
            if light and k % 2 == 1:
                continue
            p = root + (12 if k in (3, 7) and energy >= 2 else 0)
            bass.note(b0 + k * 0.5, 0.42, p, 88 if k % 2 == 0 else 72)
        # counter melody on EP in teams / everywhere
        if sec in ("teams", "everywhere"):
            mel = [[(0, 78), (0.75, 76), (1.5, 74), (2.5, 71)], [(0, 74), (1, 76), (2, 78), (3, 81)], [(0, 78), (1.5, 76), (2.5, 74)], [(0, 76), (1, 74), (2, 73), (3, 69)]][bar % 4]
            for (bt, p) in mel:
                ep.note(b0 + bt, 0.9, p, 62)
        if sec == "gamers":
            hook = [(0, 81), (0.5, 78), (1, 76), (1.5, 78), (2.5, 81), (3, 83)] if bar % 2 == 0 else [(0, 85), (0.5, 83), (1, 81), (2, 78), (3, 76)]
            for (bt, p) in hook:
                lead.note(b0 + bt, 0.45, p, 70)
            for k in (0, 1.5, 3):
                for p in upper[-3:]:
                    ep.note(b0 + k, 0.3, p + 12, 56)
        # fill into the next section
        nsec, _, _ = section(bar + 1)
        if nsec != sec:
            for k in range(4):
                drums.note(b0 + 3 + k * 0.25, 0.1, TOM, 60 + k * 10)

    # --- cta tail: final bass + gentle ending
    if sec == "cta" and i >= 1:
        bass.note(b0, 3.8, root if root < 50 else root - 12, 60 if i < n - 1 else 45)

parts = [pad, strings, arp, ep, bass, lead, bell, drums]
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "stems").mkdir(exist_ok=True)

mid = mido.MidiFile(ticks_per_beat=TPB)
for k, p in enumerate(parts):
    mid.tracks.append(p.track(with_tempo=(k == 0)))
mid.save(OUT / "score.mid")

total_s = tl["duration"]
n_samples = int(round(total_s * SR))


def render_part(p):
    m = mido.MidiFile(ticks_per_beat=TPB)
    m.tracks.append(p.track(with_tempo=True))
    mp = OUT / "stems" / f"{p.name}.mid"
    wp = OUT / "stems" / f"{p.name}.wav"
    m.save(mp)
    subprocess.run(
        ["fluidsynth", "-ni", "-q", "-g", "0.6", "-r", str(SR), "-o", "synth.reverb.active=1", "-o", "synth.chorus.active=1",
         "-o", "synth.reverb.room-size=0.75", "-o", "synth.reverb.width=0.9", "-o", "synth.reverb.level=0.6",
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
stems = {p.name: render_part(p) for p in parts}

# --- sidechain envelope keyed from kick times (classic pumping, subtle)
env = np.ones(n_samples)
rel = 0.24
depth = 0.42
for kt in kicks:
    a = int(kt * SR)
    if a >= n_samples:
        continue
    n = min(int(rel * SR), n_samples - a)
    x = np.linspace(0, 1, n)
    env[a:a + n] = np.minimum(env[a:a + n], 1 - depth * (1 - x) ** 2)
sc = env[:, None]

gains = {"pad": 0.9, "strings": 0.55, "arp": 0.95, "keys": 0.55, "bass": 0.85, "lead": 0.42, "bell": 0.6, "drums": 0.8}
duck = {"pad", "strings", "arp", "bass", "keys"}
mix = np.zeros((n_samples, 2))
for name, a in stems.items():
    g = gains.get(name, 0.7)
    mix += (a * sc if name in duck else a) * g

# riser before the reveal: filtered noise swell (2 bars)
r0, _ = SCENES["reveal"]
r_end = r0 * BAR_S
r_start = r_end - 2 * BAR_S
idx = np.arange(int(r_start * SR), int(r_end * SR))
noise = rng.standard_normal((len(idx), 2))
# crude rising high-pass via differencing blend + exponential amp swell
k = np.linspace(0, 1, len(idx))[:, None]
hp = np.vstack([noise[:1], np.diff(noise, axis=0)])
swell = (k ** 2.5) * 0.06
mix[idx] += (noise * (1 - k) * 0.4 + hp * k) * swell

# fade the last bar to silence; gentle fade-in on the first 0.5s
fade = int(BAR_S * 1.5 * SR)
mix[-fade:] *= np.linspace(1, 0, fade)[:, None] ** 1.5
fi = int(0.5 * SR)
mix[:fi] *= np.linspace(0, 1, fi)[:, None]

peak = np.max(np.abs(mix)) or 1
mix = mix / peak * 0.89
sf.write(OUT / "music.wav", mix.astype(np.float32), SR, subtype="FLOAT")
print(json.dumps({"bpm": BPM, "bars": TOTAL_BARS, "seconds": total_s, "kicks": len(kicks), "out": str(OUT / "music.wav")}))
