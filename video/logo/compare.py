"""Render an SVG and score it against the source image."""
import subprocess
import sys

import numpy as np
from PIL import Image

src, svg, png, diff = sys.argv[1:5]
subprocess.run(["rsvg-convert", "-w", "1024", "-h", "1024", svg, "-o", png], check=True)
a = np.asarray(Image.open(src).convert("RGB"), float)
b = np.asarray(Image.open(png).convert("RGB"), float)
e = np.abs(a - b).mean(-1)
print(f"mean abs err {e.mean():.2f}/255  px>40: {(e > 40).mean() * 100:.2f}%  px>80: {(e > 80).mean() * 100:.2f}%")
Image.fromarray(np.clip(e * 3, 0, 255).astype(np.uint8)).save(diff)
