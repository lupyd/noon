"""Rebuild noon.webp as a layered SVG.

Each palette colour becomes one layer. Layers are stacked bottom-to-top and every
layer's mask is the union of its own colour and everything painted above it, so
the stack has no seams. Masks are traced with potrace at 4x supersampling.
Flames and the two sun disks are emitted as separate groups so they can be
animated independently.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

from classify import PALETTE, classify

SS = 4  # supersampling factor for tracing
# Rough sun disks (centre x, centre y, radius) in source px; refined by fit_disks().
ROUGH_DISKS = [(448, 420, 121), (593, 580, 121)]

FLAME_ORDER = ["deepred", "redorange", "orange"]
DISK_ORDER = ["orange", "yellow", "cream"]


def trace(mask, turd=8):
    """Trace a boolean mask to an SVG path string in source pixel units."""
    img = Image.fromarray((mask * 255).astype(np.uint8))
    img = img.filter(ImageFilter.GaussianBlur(0.9))
    img = img.resize((mask.shape[1] * SS, mask.shape[0] * SS), Image.BICUBIC)
    bw = img.point(lambda v: 0 if v >= 128 else 255).convert("1")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.pbm"
        bw.save(p)
        out = subprocess.run(
            ["potrace", str(p), "-b", "svg", "--flat", "-t", str(turd * SS * SS),
             "-a", "1.1", "-O", "0.6", "-u", "1", "-o", "-"],
            capture_output=True, text=True, check=True).stdout
    d = " ".join(re.findall(r'<path d="([^"]+)"', out, re.S))
    d = re.sub(r"\s+", " ", d).strip()
    h = mask.shape[0] * SS
    # potrace emits y-up coordinates scaled by `-u`; flip and shrink back to source px.
    return d, f"translate(0,{mask.shape[0]}) scale({1 / SS},{-1 / SS})"


def fit_disks(lab, names):
    """Fit each sun's disk to the edge where its orange rim meets the red ring.

    Edge points are disk-coloured pixels touching deep red. Flame accents touch
    the red too, so the fit is iterated from a rough guess with a narrowing band
    and trimmed residuals.
    """
    disk = np.isin(lab, [names.index(n) for n in DISK_ORDER])
    red = lab == names.index("deepred")
    near_red = red | np.roll(red, 1, 0) | np.roll(red, -1, 0) | np.roll(red, 1, 1) | np.roll(red, -1, 1)
    ey, ex = np.nonzero(disk & near_red)
    ex, ey = ex.astype(float), ey.astype(float)
    fits = []
    for x0, y0, r0 in ROUGH_DISKS:
        for band in (20, 12, 8, 5):
            res = np.abs(np.hypot(ex - x0, ey - y0) - r0)
            sel = res < band
            sx, sy = ex[sel], ey[sel]
            A = np.c_[2 * sx, 2 * sy, np.ones_like(sx)]
            (x0, y0, c0), *_ = np.linalg.lstsq(A, sx ** 2 + sy ** 2, rcond=None)
            r0 = float(np.sqrt(c0 + x0 ** 2 + y0 ** 2))
        fits.append((float(x0), float(y0), r0))
    return fits


def fit_spin(lab, names, disks):
    """Find, per sun, the one unbroken orange ring of the spiral (~r=94).

    Everything inside it rotates; clipping there cuts through flat orange on
    both sides, so the turning spiral has no seam against the static rim.
    Returns (cx, cy, r) maximising how much of the ring is orange.
    """
    orange = lab == names.index("orange")
    t = np.linspace(0, 2 * np.pi, 720, endpoint=False)
    out = []
    for x0, y0, _ in disks:
        best = (-1, None)
        for dx in np.arange(-5, 5.5, 0.5):
            for dy in np.arange(-5, 5.5, 0.5):
                for r in np.arange(86, 102, 0.5):
                    # score the band r-2..r+2: every sample on it must be orange
                    sc = 1.0
                    for o in (-2, 0, 2):
                        x = (x0 + dx + (r + o) * np.cos(t)).round().astype(int)
                        y = (y0 + dy + (r + o) * np.sin(t)).round().astype(int)
                        sc = min(sc, orange[y, x].mean())
                    if sc > best[0]:
                        best = (sc, (float(x0 + dx), float(y0 + dy), float(r)))
        print("spin ring", [round(v, 2) for v in best[1]], "orange", round(best[0], 3))
        out.append(best[1])
    return out


def main(src, dst):
    names, cols, lab = classify(src)
    H, W = lab.shape
    idx = {n: names.index(n) for n in names}
    disks = fit_disks(lab, names)
    spins = fit_spin(lab, names, disks)
    yy, xx = np.mgrid[0:H, 0:W]

    def union(order, i):
        return np.isin(lab, [idx[n] for n in order[i:]])

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
           f'<rect id="bg" width="{W}" height="{H}" fill="{PALETTE["navy"]}"/>']

    for name in ("star", "magenta"):
        d, t = trace(lab == idx[name], turd=2)
        out.append(f'<g id="{name}s" transform="{t}"><path fill="{PALETTE[name]}" d="{d}"/></g>')

    # Flames: the full stack over the whole frame. The suns are drawn on top of it
    # clipped to their circles, so what sits under them matches exactly and no
    # seam shows at the clip edge. The cream bridge between the suns lives here.
    full = FLAME_ORDER + DISK_ORDER[1:]
    logo = ~np.isin(lab, [idx["navy"], idx["star"], idx["magenta"]])
    out.append('<g id="flames">')
    for i, n in enumerate(full):
        m = logo if i == 0 else union(full, i)
        d, t = trace(m)
        out.append(f'<g id="L-{n}" class="layer {n}" transform="{t}"><path fill="{PALETTE[n]}" d="{d}"/></g>')
    out.append('</g>')

    # Each sun's spiral reuses the exact disk paths, clipped inside its unbroken
    # orange ring; the inner `spin` group is what rotates.
    for k, ((x, y, r), (sx, sy, sr)) in enumerate(zip(disks, spins)):
        sid = "ab"[k]
        out.append(f'<clipPath id="clip-{sid}"><circle cx="{sx:.2f}" cy="{sy:.2f}" r="{sr:.2f}"/></clipPath>')
        out.append(f'<g id="sun-{sid}" data-cx="{sx:.2f}" data-cy="{sy:.2f}" data-r="{sr:.2f}" '
                   f'data-rim="{r:.2f}" clip-path="url(#clip-{sid})">')
        out.append(f'<g class="spin" style="transform-origin:{sx:.2f}px {sy:.2f}px">')
        out.extend(f'<use href="#L-{n}"/>' for n in DISK_ORDER)
        out.append('</g></g>')
    out.append('</svg>')
    Path(dst).write_text("\n".join(out))
    print("disks", [tuple(round(v, 2) for v in dk) for dk in disks])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
