"""Classify noon.webp pixels into the logo's flat palette (debug view)."""
import sys
import numpy as np
from PIL import Image, ImageFilter

PALETTE = {
    "navy": "#232156",
    "star": "#f2ebcb",
    "magenta": "#cc2580",
    "deepred": "#b82c33",
    "redorange": "#e75b32",
    "orange": "#ef8d2c",
    "yellow": "#f9d363",
    "cream": "#f8e4a6",
}

def hexrgb(h):
    return np.array([int(h[i:i + 2], 16) for i in (1, 3, 5)], float)

def classify(path):
    im = Image.open(path).convert("RGB").filter(ImageFilter.MedianFilter(3))
    a = np.asarray(im, float)
    names = list(PALETTE)
    cols = np.stack([hexrgb(PALETTE[n]) for n in names])
    d = ((a[:, :, None, :] - cols[None, None]) ** 2).sum(-1)
    return names, cols, d.argmin(-1)

if __name__ == "__main__":
    names, cols, lab = classify(sys.argv[1])
    Image.fromarray(cols[lab].astype(np.uint8)).save(sys.argv[2])
    for i, n in enumerate(names):
        print(n, int((lab == i).sum()))
