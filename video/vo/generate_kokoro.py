# /// script
# requires-python = ">=3.10,<3.13"
# dependencies = [
#   "kokoro>=0.9.4",
#   "misaki[en]>=0.9.4",
#   "soundfile",
#   "numpy",
#   "torch",
#   "pip",
# ]
# [tool.uv]
# index-strategy = "unsafe-best-match"
# [[tool.uv.index]]
# name = "pytorch-cpu"
# url = "https://download.pytorch.org/whl/cpu"
# explicit = true
# [tool.uv.sources]
# torch = { index = "pytorch-cpu" }
# ///
"""Generate the voiceover with Kokoro-82M (Apache-2.0).

Writes one 24 kHz mono wav per line to out/vo/<id>.wav plus out/vo/durations.json.
Usage: uv run vo/generate.py [--voice af_heart] [--speed 1.0] [--only id,id]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

import numpy as np
import soundfile as sf

ROOT = Path(__file__).resolve().parent.parent
SR = 24000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default=str(ROOT / "vo" / "script.json"))
    ap.add_argument("--out", default=str(ROOT / "out" / "vo"))
    ap.add_argument("--voice", default=None)
    ap.add_argument("--speed", type=float, default=None)
    ap.add_argument("--only", default=None)
    args = ap.parse_args()

    os.environ.setdefault("HF_HOME", str(ROOT / ".cache" / "hf"))
    # The espeakng-loader wheel ships a data path baked in at its CI build
    # location; prefer the system espeak-ng (used for out-of-vocabulary words).
    try:
        import espeakng_loader

        for lib in ("/usr/lib/libespeak-ng.so", "/usr/lib/x86_64-linux-gnu/libespeak-ng.so.1"):
            if Path(lib).exists():
                espeakng_loader.get_library_path = lambda lib=lib: lib
                break
        for data in ("/usr/share/espeak-ng-data", "/usr/lib/x86_64-linux-gnu/espeak-ng-data"):
            if Path(data).exists():
                espeakng_loader.get_data_path = lambda data=data: data
                break
    except ImportError:
        pass
    from kokoro import KPipeline  # noqa: E402

    spec = json.loads(Path(args.script).read_text())
    k = spec.get("kokoro", {})
    voice = args.voice or k.get("voice") or spec.get("voice", "af_heart")
    speed = args.speed or k.get("speed") or spec.get("speed", 1.0)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    pipe = KPipeline(lang_code=k.get("lang") or spec.get("lang", "a"), repo_id="hexgrad/Kokoro-82M")
    only = set(args.only.split(",")) if args.only else None
    durations = {}
    dur_path = out / "durations.json"
    if dur_path.exists():
        durations = json.loads(dur_path.read_text()).get("lines", {})

    for line in spec["lines"]:
        if only and line["id"] not in only:
            continue
        chunks = []
        text = line["text"]
        # misaki inline phoneme override: [word](/phonemes/)
        for word, ph in (k.get("lexicon") or spec.get("lexicon", {})).items():
            text = re.sub(rf"\b{re.escape(word)}\b", f"[{word}](/{ph}/)", text)
        for gs, ps, audio in pipe(text, voice=voice, speed=line.get("speed", speed)):
            print(f"[{line['id']}] {gs!r}\n    -> {ps}", file=sys.stderr)
            chunks.append(audio.numpy() if hasattr(audio, "numpy") else np.asarray(audio))
            # short breath between sentence chunks
            chunks.append(np.zeros(int(SR * 0.12), dtype=np.float32))
        wav = np.concatenate(chunks[:-1]) if chunks else np.zeros(SR, dtype=np.float32)
        # trim leading/trailing near-silence so timing is tight
        thr = 0.01 * np.max(np.abs(wav))
        idx = np.where(np.abs(wav) > thr)[0]
        if len(idx):
            a = max(0, idx[0] - int(0.03 * SR))
            b = min(len(wav), idx[-1] + int(0.08 * SR))
            wav = wav[a:b]
        # fade edges
        f = int(0.01 * SR)
        wav[:f] *= np.linspace(0, 1, f)
        wav[-f:] *= np.linspace(1, 0, f)
        path = out / f"{line['id']}.wav"
        sf.write(path, wav, SR, subtype="PCM_16")
        durations[line["id"]] = round(len(wav) / SR, 3)
        print(f"wrote {path} ({durations[line['id']]}s)", file=sys.stderr)

    dur_path.write_text(json.dumps({"voice": voice, "speed": speed, "sr": SR, "lines": durations}, indent=2))
    print(json.dumps(durations, indent=2))


if __name__ == "__main__":
    main()
