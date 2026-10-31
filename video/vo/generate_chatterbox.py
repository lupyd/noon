"""Voiceover with Chatterbox (Resemble AI, MIT) — expressive, natural prosody.

Runs in the isolated env at .cache/tts/chatterbox (see vo/chatterbox.pyproject.toml):
    pnpm vo            # all lines
    pnpm vo --only id1,id2

Per line: render N candidate takes (different seeds), transcribe each with
faster-whisper, keep the take whose transcript matches the script best (then the
one closest to the median take length, which rejects rushed/dragged reads).
Writes 24 kHz mono out/vo/<id>.wav + out/vo/durations.json (same contract as the
old Kokoro generator, so timeline/mix are unchanged).

Fits a 4 GB GPU: the 0.5B T3 backbone runs in bf16 (~2.1 GB peak).
Chatterbox embeds an imperceptible Perth watermark in every take.
"""
import argparse
import json
import os
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

import numpy as np
import soundfile as sf
import torch

ROOT = Path(__file__).resolve().parent.parent


def norm(s):
    s = s.lower().replace("2 a.m.", "two am").replace("a.m.", "am")
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    return " ".join(s.split())


def load_model():
    from chatterbox.tts import ChatterboxTTS

    m = ChatterboxTTS.from_pretrained(device="cpu")
    if torch.cuda.is_available():
        m.t3.to(dtype=torch.bfloat16)
        for mod in (m.t3, m.s3gen, m.ve):
            mod.to("cuda")
        m.device = "cuda"
        m.conds = m.conds.to("cuda")
        m.conds.t3.speaker_emb = m.conds.t3.speaker_emb.to(torch.bfloat16)
    return m


def trim(wav, sr):
    thr = 0.012 * np.max(np.abs(wav))
    idx = np.where(np.abs(wav) > thr)[0]
    if len(idx):
        wav = wav[max(0, idx[0] - int(0.03 * sr)) : min(len(wav), idx[-1] + int(0.09 * sr))]
    f = int(0.01 * sr)
    wav[:f] *= np.linspace(0, 1, f)
    wav[-f:] *= np.linspace(1, 0, f)
    return wav


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default=str(ROOT / "vo" / "script.json"))
    ap.add_argument("--out", default=str(ROOT / "out" / "vo"))
    ap.add_argument("--only", default=None)
    ap.add_argument("--takes", type=int, default=3)
    args = ap.parse_args()
    os.environ.setdefault("HF_HOME", str(ROOT / ".cache" / "hf"))

    spec = json.loads(Path(args.script).read_text())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    dur_path = out / "durations.json"
    durations = json.loads(dur_path.read_text()).get("lines", {}) if dur_path.exists() else {}
    only = set(args.only.split(",")) if args.only else None

    model = load_model()
    from faster_whisper import WhisperModel

    asr = WhisperModel("base.en", device="cpu", compute_type="int8")
    rep_path = out / "report.json"
    report = json.loads(rep_path.read_text()) if rep_path.exists() else {}
    for line in spec["lines"]:
        if only and line["id"] not in only:
            continue
        text = line.get("say", line["text"])
        for word, say in spec.get("pronounce", {}).items():
            text = re.sub(rf"(?<![\w]){re.escape(word)}(?![\w])", say, text)
        ex = line.get("exaggeration", spec.get("exaggeration", 0.5))
        cfg = line.get("cfg_weight", spec.get("cfg_weight", 0.5 if ex <= 0.55 else 0.4))
        takes = []
        for k in range(line.get("takes", args.takes)):
            torch.manual_seed(spec.get("seed", 11) * 100 + k)
            with torch.autocast("cuda", dtype=torch.bfloat16, enabled=torch.cuda.is_available()):
                w = model.generate(text, exaggeration=ex, cfg_weight=cfg, temperature=spec.get("temperature", 0.75))
            wav = trim(w.float().squeeze(0).cpu().numpy().astype(np.float32), model.sr)
            tmp = out / f".{line['id']}.take{k}.wav"
            sf.write(tmp, wav, model.sr)
            segs = list(asr.transcribe(str(tmp), language="en", beam_size=1, word_timestamps=True)[0])
            words = [w for sg in segs for w in (sg.words or []) if re.search(r"[A-Za-z0-9]", w.word)]
            heard = " ".join(sg.text for sg in segs)
            score = SequenceMatcher(None, norm(heard), norm(line.get("caption", line["text"]))).ratio()
            junk = len(re.findall(r"[^\w\s.,!?'’-]", heard))
            score -= 0.02 * junk
            # cut trailing noise / mumble after the last real word
            if words:
                end = int(min(len(wav), (words[-1].end + 0.14) * model.sr))
                if end < len(wav) - int(0.25 * model.sr):
                    wav = wav[:end]
                    f = int(0.03 * model.sr)
                    wav[-f:] *= np.linspace(1, 0, f)
            takes.append({"k": k, "wav": wav, "score": score, "heard": heard.strip(), "dur": len(wav) / model.sr})
            tmp.unlink()
            print(f"[{line['id']}] take {k}: {score:.2f} {len(wav)/model.sr:.2f}s  “{heard.strip()}”", file=sys.stderr)
        best = max(t["score"] for t in takes)
        ok = [t for t in takes if t["score"] >= best - 0.03]
        med = float(np.median([t["dur"] for t in takes]))
        pick = min(ok, key=lambda t: abs(t["dur"] - med))
        sf.write(out / f"{line['id']}.wav", pick["wav"], model.sr, subtype="PCM_16")
        durations[line["id"]] = round(pick["dur"], 3)
        report[line["id"]] = {"take": pick["k"], "asr": round(pick["score"], 3), "heard": pick["heard"], "dur": durations[line["id"]]}
        if pick["score"] < 0.85:
            print(f"!! [{line['id']}] low ASR match {pick['score']:.2f}: {pick['heard']}", file=sys.stderr)

    dur_path.write_text(json.dumps({"engine": "chatterbox", "sr": model.sr, "lines": durations}, indent=2))
    (out / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
