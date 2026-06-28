#!/usr/bin/env python3
"""Generate the cogpin logo: a cog with a square drive-pin hub and a pawl catching a
tooth — the name AND the thesis (the pin holds the cog so it can't slip back; the gate
can't be loosened). Stdlib only.

Outputs:
  assets/logo.svg            the bare mark (brand blue, transparent) — README/hero
  site/src/assets/logo.svg   same, for the Starlight header
  site/public/favicon.svg    app-icon (rounded navy square + the mark) — browser tab
"""
from __future__ import annotations
import math
import os

BLUE = "#2563eb"
NAVY = "#0b1220"
CX = CY = 100
N = 9                # teeth — chunky, not spiky
R_OUT, R_IN = 84.0, 63.0
TIP_FRAC = 0.34      # fraction of each tooth-step that is the flat tip
HOLE = 44.0          # square drive hole side
ROT = math.radians(-90 - (360 / N) * 0.5)  # orient a clean valley at top for the pawl


def _p(a, r):
    return (CX + r * math.cos(a + ROT), CY + r * math.sin(a + ROT))


def gear_path():
    step = 2 * math.pi / N
    # chunky asymmetric tooth: radial leading edge → short flat tip → ramp down.
    out = ["M %.2f %.2f" % _p(0.0, R_IN)]
    for i in range(N):
        a = i * step
        out.append("L %.2f %.2f" % _p(a, R_OUT))                 # up the steep radial face
        out.append("L %.2f %.2f" % _p(a + TIP_FRAC * step, R_OUT))  # flat tip
        out.append("L %.2f %.2f" % _p(a + step, R_IN))           # ramp to the next valley
    out.append("Z")
    # square drive hole as an evenodd subpath → a real hole on any background
    h = HOLE / 2
    out.append("M %.2f %.2f L %.2f %.2f L %.2f %.2f L %.2f %.2f Z" % (
        CX - h, CY - h, CX + h, CY - h, CX + h, CY + h, CX - h, CY + h))
    return " ".join(out)


def mark(color):
    # the bold asymmetric gear + square drive-pin hole — one clean shape.
    return '<path d="%s" fill="%s" fill-rule="evenodd"/>' % (gear_path(), color)


def svg(body, bg=None, pad=0):
    vb = 200
    rect = ('<rect x="0" y="0" width="200" height="200" rx="44" fill="%s"/>' % bg) if bg else ""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
            'width="%d" height="%d">%s%s</svg>' % (vb, vb, vb, vb, rect, body))


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print("wrote", path)


def main():
    root = os.path.dirname(os.path.abspath(__file__))           # assets/
    repo = os.path.dirname(root)
    write(os.path.join(root, "logo.svg"), svg(mark(BLUE)))
    write(os.path.join(repo, "site/src/assets/logo.svg"), svg(mark(BLUE)))
    write(os.path.join(repo, "site/public/favicon.svg"), svg(mark(BLUE), bg=NAVY))


if __name__ == "__main__":
    main()
