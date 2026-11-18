"""Render an asciinema v2 cast to an animated GIF (pure Python: pyte + Pillow).

    python scripts/cast2gif.py docs/casts/demo_audit.cast docs/img/demo_audit.gif

Draws a terminal window (title bar + Monokai-like palette) with DejaVu Sans Mono.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont

FONT_DIRS = [Path("/usr/share/fonts/truetype/dejavu"), Path("C:/Windows/Fonts")]
BG = (39, 40, 34)
FG = (248, 248, 242)
TITLE_BG = (30, 31, 26)
PALETTE = {
    "black": (39, 40, 34), "red": (249, 38, 114), "green": (166, 226, 46), "brown": (230, 219, 116),
    "yellow": (230, 219, 116), "blue": (102, 217, 239), "magenta": (174, 129, 255), "cyan": (161, 239, 228),
    "white": (248, 248, 242), "brightblack": (117, 113, 94), "brightred": (255, 89, 149),
    "brightgreen": (190, 240, 90), "brightbrown": (255, 240, 140), "brightyellow": (255, 240, 140),
    "brightblue": (130, 230, 250), "brightmagenta": (200, 160, 255), "brightcyan": (190, 250, 240),
    "brightwhite": (255, 255, 255),
}


# Box-drawing glyphs drawn as vectors so lines connect across the taller line height.
# char -> (left, right, up, down) arm weights: 0 none, 1 light, 2 heavy
_L, _H = 1, 2
BOX = {
    "─": (_L, _L, 0, 0), "━": (_H, _H, 0, 0), "│": (0, 0, _L, _L), "┃": (0, 0, _H, _H),
    "┌": (0, _L, 0, _L), "┐": (_L, 0, 0, _L), "└": (0, _L, _L, 0), "┘": (_L, 0, _L, 0),
    "╭": (0, _L, 0, _L), "╮": (_L, 0, 0, _L), "╰": (0, _L, _L, 0), "╯": (_L, 0, _L, 0),
    "├": (0, _L, _L, _L), "┤": (_L, 0, _L, _L), "┬": (_L, _L, 0, _L), "┴": (_L, _L, _L, 0),
    "┼": (_L, _L, _L, _L), "┏": (0, _H, 0, _H), "┓": (_H, 0, 0, _H), "┗": (0, _H, _H, 0),
    "┛": (_H, 0, _H, 0), "┣": (0, _H, _H, _H), "┫": (_H, 0, _H, _H), "┳": (_H, _H, 0, _H),
    "┻": (_H, _H, _H, 0), "╋": (_H, _H, _H, _H), "╶": (0, _L, 0, 0), "╴": (_L, 0, 0, 0),
    "╷": (0, 0, 0, _L), "╵": (0, 0, _L, 0), "┡": (0, _H, _L, _L), "┩": (_H, 0, _L, _L),
    "╇": (_H, _H, _L, _L), "╞": (0, _L, _L, _L), "╡": (_L, 0, _L, _L), "╪": (_L, _L, _L, _L),
    "═": (_L, _L, 0, 0), "║": (0, 0, _L, _L),
}


def draw_box(d: ImageDraw.ImageDraw, glyph: str, x: int, y: int, w: int, h: int, fill: tuple) -> None:
    left, right, up, down = BOX[glyph]
    cx, cy = x + w // 2, y + h // 2
    for weight, box in ((left, (x, cy, cx, cy)), (right, (cx, cy, x + w, cy)),
                        (up, (cx, y, cx, cy)), (down, (cx, cy, cx, y + h))):
        if weight:
            d.line(box, fill=fill, width=1 if weight == _L else 2)


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    for d in FONT_DIRS:
        p = d / name
        if p.exists():
            return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()


def color(c: str, default: tuple) -> tuple:
    if c == "default":
        return default
    if c in PALETTE:
        return PALETTE[c]
    if len(c) == 6:
        try:
            return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            pass
    return default


class Renderer:
    def __init__(self, cols: int, rows: int, size: int, title: str):
        self.cols, self.rows, self.title = cols, rows, title
        self.f = font("DejaVuSansMono.ttf", size)
        self.fb = font("DejaVuSansMono-Bold.ttf", size)
        self.cw = round(self.f.getlength("M"))
        self.ch = round(size * 1.3)
        self.pad, self.bar = 14, 30
        self.W = self.cols * self.cw + 2 * self.pad
        self.H = self.rows * self.ch + 2 * self.pad + self.bar

    def frame(self, screen: pyte.Screen) -> Image.Image:
        img = Image.new("RGB", (self.W, self.H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, self.W, self.bar], fill=TITLE_BG)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([14 + i * 20, 10, 26 + i * 20, 22], fill=c)
        tw = d.textlength(self.title, font=self.f)
        d.text(((self.W - tw) / 2, 7), self.title, fill=(160, 160, 150), font=self.f)
        y0 = self.bar + self.pad
        for r in range(self.rows):
            line = screen.buffer[r]
            y = y0 + r * self.ch
            c = 0
            while c < self.cols:
                ch = line[c]
                fg, bg = color(ch.fg, FG), color(ch.bg, BG)
                if ch.reverse:
                    fg, bg = bg, fg
                # extend a run of cells with identical style
                run_end = c + 1
                while run_end < self.cols:
                    n = line[run_end]
                    if (n.fg, n.bg, n.bold, n.reverse) != (ch.fg, ch.bg, ch.bold, ch.reverse):
                        break
                    run_end += 1
                x = self.pad + c * self.cw
                if bg != BG:
                    d.rectangle([x, y, self.pad + run_end * self.cw - 1, y + self.ch - 1], fill=bg)
                text = "".join(line[k].data for k in range(c, run_end))
                if text.strip():
                    f = self.fb if ch.bold else self.f
                    # draw per character to keep the grid exact (box drawing, wide glyph fallbacks)
                    for k, glyph in enumerate(text):
                        if glyph in BOX:
                            draw_box(d, glyph, x + k * self.cw, y, self.cw, self.ch, fg)
                        elif glyph != " ":
                            d.text((x + k * self.cw, y + 2), glyph, fill=fg, font=f)
                c = run_end
        return img


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cast")
    ap.add_argument("gif")
    ap.add_argument("--font-size", type=int, default=15)
    ap.add_argument("--fps", type=float, default=12)
    ap.add_argument("--idle", type=float, default=2.0, help="cap for idle gaps (s)")
    ap.add_argument("--title", default=None)
    a = ap.parse_args()

    lines = Path(a.cast).read_text(encoding="utf-8").splitlines()
    head = json.loads(lines[0])
    events = [json.loads(x) for x in lines[1:] if x.strip()]
    cols, rows = head["width"], head["height"]
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)
    rend = Renderer(cols, rows, a.font_size, a.title or Path(a.cast).stem.replace("_", " "))

    frames: list[Image.Image] = []
    durations: list[int] = []
    step = 1.0 / a.fps
    t_prev, clock, next_frame = 0.0, 0.0, 0.0
    i = 0
    while i < len(events):
        t, _, data = events[i]
        gap = min(t - t_prev, a.idle)
        t_prev = t
        clock += gap
        stream.feed(data)
        i += 1
        # emit a frame when the next event is at least one frame-time away (or at the end)
        nxt = clock + min(events[i][0] - t, a.idle) if i < len(events) else clock + 1.0
        if nxt >= next_frame + step or i == len(events):
            img = rend.frame(screen)
            if frames:
                durations[-1] = max(20, int(round((clock - next_frame) * 1000)))
            frames.append(img)
            durations.append(100)
            next_frame = clock
    durations[-1] = 4000
    out = Path(a.gif)
    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0,
                   optimize=True, disposal=1)
    print(f"{out}: {len(frames)} frames, {sum(durations) / 1000:.1f}s, {out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
