#!/usr/bin/env python3
"""Render amicontained's coloured terminal output as an SVG "screenshot".

Usage: ansi2svg.py OUTPUT.ansi "COMMAND LINE" > screenshot.svg

Capture OUTPUT.ansi with a TTY so colour is on, e.g.
    docker run --rm -t ... amicontained | tr -d '\\r' > run.ansi
then convert to PNG with rsvg-convert. Only the SGR codes amicontained
emits (reset, bold, dim, red, yellow, cyan) are handled.
"""
import re
import sys
from html import escape

FONT = "DejaVu Sans Mono, Menlo, Consolas, monospace"
SIZE = 14
CHAR_W = SIZE * 0.602  # DejaVu Sans Mono advance width
LINE_H = 19
PAD = 20
BAR = 34

BG, FG, BOLD_FG = "#1e2029", "#c8ccd4", "#ffffff"
COLOURS = {"31": "#ff6b6b", "33": "#e5c07b", "36": "#56b6c2"}
DIM = "#7f848e"
PROMPT = "#98c379"

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def spans(line):
    """Split a line into (text, bold, dim, colour) runs."""
    bold = dim = False
    colour = None
    pos = 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            yield line[pos:m.start()], bold, dim, colour
        for code in (m.group(1) or "0").split(";"):
            if code == "0":
                bold = dim = False
                colour = None
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in COLOURS:
                colour = COLOURS[code]
        pos = m.end()
    if pos < len(line):
        yield line[pos:], bold, dim, colour


def tspan(text, bold, dim, colour):
    fill = colour or (DIM if dim else BOLD_FG if bold else FG)
    weight = ' font-weight="bold"' if bold else ""
    return f'<tspan fill="{fill}"{weight}>{escape(text)}</tspan>'


def main():
    lines = open(sys.argv[1], encoding="utf-8").read().rstrip("\n").split("\n")
    command = sys.argv[2]
    cols = max(len(SGR.sub("", l)) for l in lines + ["$ " + command])
    width = int(cols * CHAR_W + 2 * PAD)
    height = BAR + PAD + (len(lines) + 2) * LINE_H + PAD

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>',
        f'<rect width="{width}" height="{BAR}" rx="10" fill="#2a2d38"/>',
        f'<rect y="{BAR - 10}" width="{width}" height="10" fill="#2a2d38"/>',
    ]
    for i, c in enumerate(["#ff5f57", "#febc2e", "#28c840"]):
        out.append(f'<circle cx="{PAD + i * 20}" cy="{BAR // 2}" r="6" fill="{c}"/>')
    out.append(f'<g font-family="{FONT}" font-size="{SIZE}" xml:space="preserve">')

    y = BAR + PAD + SIZE
    out.append(f'<text x="{PAD}" y="{y}"><tspan fill="{PROMPT}">$ </tspan>'
               f'<tspan fill="{BOLD_FG}">{escape(command)}</tspan></text>')
    y += 2 * LINE_H
    for line in lines:
        if line:
            out.append(f'<text x="{PAD}" y="{y}">' + "".join(tspan(*s) for s in spans(line)) + "</text>")
        y += LINE_H
    out.append("</g></svg>")
    print("\n".join(out))


if __name__ == "__main__":
    main()
