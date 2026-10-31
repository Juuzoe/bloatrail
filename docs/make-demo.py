#!/usr/bin/env python3
"""Regenerate `docs/demo.gif` from the real CLI.

Nothing here is mocked up. The script builds a synthetic project folder, runs
the binary against it, and renders the captured ANSI output frame by frame, so
what the README animates is what the tool actually printed.

The fixture uses sparse files: Bloatrail measures apparent size, so a 3.6 GB
`target/` costs nothing on disk and the demo shows the figures a real developer
machine would.

    cargo build --release
    python3 docs/make-demo.py

Needs Pillow and a DejaVu Sans Mono install (Consolas is used on Windows when
DejaVu is missing).

    python3 docs/make-demo.py --social

renders `docs/social-preview.png` instead: the 1280x640 card GitHub shows when
the repository is linked. It has to be uploaded by hand, under Settings ->
General -> Social preview.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - a setup problem, not a code path
    sys.exit("Pillow is needed: pip install Pillow")

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "demo.gif"
SOCIAL = REPO / "docs" / "social-preview.png"

# ----------------------------------------------------------------- appearance
BG = (17, 19, 26)
CHROME = (26, 29, 38)
FG = (201, 209, 217)
DIM = (110, 118, 129)
BOLD_FG = (240, 246, 252)

ANSI_FG = {
    31: (248, 81, 73),    # red
    32: (86, 211, 100),   # green
    33: (227, 179, 65),   # yellow
    36: (88, 166, 255),   # cyan
}

FONT_DIRS = [
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu",
    "/Library/Fonts",
    "C:/Windows/Fonts",
]
FONT_SIZE = 15
LINE_H = 21
PAD_X = 18
PAD_TOP = 40  # room for the window chrome
PAD_BOT = 20

SGR = re.compile(r"\x1b\[([0-9;]*)m")

# The scenes, in order. Each is a shell-visible command and the argv to run.
SCENES = [
    ("bloatrail tree ~/Projects --depth 2", ["tree", "{root}", "--depth", "2"]),
    ("bloatrail explain ~/Projects/marketing/target",
     ["explain", "{root}/marketing/target"]),
]


# Consolas stands in for DejaVu on a Windows machine without it; the published
# GIF is rendered with DejaVu.
FALLBACKS = {
    "DejaVuSansMono.ttf": "consola.ttf",
    "DejaVuSansMono-Bold.ttf": "consolab.ttf",
}


def find_font(name: str) -> str:
    for candidate_name in (name, FALLBACKS.get(name)):
        if candidate_name is None:
            continue
        for directory in FONT_DIRS:
            candidate = Path(directory) / candidate_name
            if candidate.exists():
                return str(candidate)
    sys.exit(f"{name} not found; install the DejaVu fonts")


def sparse(path: Path, size: int) -> None:
    """Create `path` with `size` apparent bytes and nothing allocated.

    On Windows this must not be Python's `truncate()`, which zero-fills the
    extension: the fixture would really occupy its 13 GB. The file is flagged
    sparse and its end moved with fsutil, and there is no allocating fallback.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb"):
        pass
    if sys.platform == "win32":
        for command in (["sparse", "setflag", str(path)],
                        ["file", "setEOF", str(path), str(size)]):
            done = subprocess.run(["fsutil", *command], capture_output=True)
            if done.returncode != 0:
                sys.exit(f"fsutil {' '.join(command)} failed; refusing to "
                         "allocate the fixture for real")
        return
    with open(path, "r+b") as fh:
        fh.truncate(size)


def build_fixture(root: Path) -> None:
    """A synthetic developer folder. No real machine is depicted."""
    mb = 1000 * 1000

    # A Rust service.
    (root / "backend-api/src").mkdir(parents=True)
    (root / "backend-api/Cargo.toml").write_text(
        '[package]\nname = "backend-api"\nversion = "0.1.0"\nedition = "2021"\n')
    (root / "backend-api/Cargo.lock").write_text('[[package]]\nname = "backend-api"\n')
    (root / "backend-api/src/main.rs").write_text("fn main() {}\n")
    sparse(root / "backend-api/target/debug/deps/libbackend.rlib", 2400 * mb)
    sparse(root / "backend-api/target/debug/incremental/cache.bin", 1300 * mb)
    sparse(root / "backend-api/.git/objects/pack/pack-a1b2.pack", 910 * mb)
    sparse(root / "backend-api/logs/api.log", 383 * mb)

    # A Next.js front end installed with pnpm.
    (root / "dashboard/src").mkdir(parents=True)
    (root / "dashboard/package.json").write_text('{"name": "dashboard"}\n')
    (root / "dashboard/pnpm-lock.yaml").write_text("lockfileVersion: 9.0\n")
    (root / "dashboard/src/app.tsx").write_text("export default function App() {}\n")
    sparse(root / "dashboard/.next/cache/webpack/client.pack", 1100 * mb)
    sparse(root / "dashboard/node_modules/.pnpm/react@19.0.0/store.bin", 1000 * mb)
    sparse(root / "dashboard/public/demo-reel.mp4", 633 * mb)
    sparse(root / "dashboard/dist/bundle.js", 40 * mb)

    # A Python project.
    (root / "ml-pipeline").mkdir(parents=True)
    (root / "ml-pipeline/pyproject.toml").write_text('[project]\nname = "ml-pipeline"\n')
    (root / "ml-pipeline/train.py").write_text('print("train")\n')
    sparse(root / "ml-pipeline/.venv/lib/python3.12/site-packages/torch.so", 807 * mb)
    sparse(root / "ml-pipeline/.mypy_cache/3.12/cache.data.json", 17 * mb)
    sparse(root / "ml-pipeline/__pycache__/train.cpython-312.pyc", 11 * mb)

    # A Gradle project.
    (root / "android-client").mkdir(parents=True)
    (root / "android-client/build.gradle").write_text(
        'plugins { id "com.android.application" }\n')
    (root / "android-client/settings.gradle").write_text(
        'rootProject.name = "android-client"\n')
    sparse(root / "android-client/build/intermediates/classes.jar", 467 * mb)
    sparse(root / "android-client/.gradle/caches/modules.bin", 342 * mb)

    # The point of the demo: a `target` directory with no project around it.
    sparse(root / "marketing/target/q3-campaign.psd", 2 * mb)


def capture(binary: Path, argv: list[str], root: Path) -> list[str]:
    env = dict(os.environ, CLICOLOR_FORCE="1", COLUMNS="88")
    args = [a.replace("{root}", str(root)) for a in argv]
    # The binary writes UTF-8 everywhere; without `encoding` Python decodes
    # with the Windows ANSI code page and every glyph turns to mojibake.
    done = subprocess.run([str(binary), *args], capture_output=True,
                          encoding="utf-8", env=env)
    if done.returncode != 0:
        sys.exit(f"{args} failed:\n{done.stderr}")
    # The fixture lives in a temporary directory; the demo shows it as
    # `~/Projects`, which is where the equivalent folder would really sit.
    text = done.stdout.replace(str(root), "~/Projects")
    lines = text.rstrip("\n").split("\n")
    if os.name == "nt":
        # On Windows the paths come out with backslashes, with home folded to
        # `~`, and long enough to be shortened before the replace above can
        # see them. Show the same `~/Projects` a Unix run prints.
        lines = [line.replace("\\", "/") for line in lines]
        lines = [re.sub(r"^\S*bloatrail-demo-\S*\s+",
                        lambda m: "~/Projects".ljust(len(m.group(0))), line)
                 for line in lines]
    return lines


def spans(line: str):
    """An ANSI line as [(text, colour, bold)]."""
    out, pos = [], 0
    colour, bold, dim = FG, False, False
    for match in SGR.finditer(line):
        if match.start() > pos:
            out.append((line[pos:match.start()], DIM if dim else colour, bold))
        for raw in (match.group(1) or "0").split(";"):
            code = int(raw or 0)
            if code == 0:
                colour, bold, dim = FG, False, False
            elif code == 1:
                bold, colour = True, BOLD_FG
            elif code == 2:
                dim = True
            elif code in ANSI_FG:
                colour, dim = ANSI_FG[code], False
        pos = match.end()
    if pos < len(line):
        out.append((line[pos:], DIM if dim else colour, bold))
    return out


def plain(line: str) -> str:
    return SGR.sub("", line)


class Terminal:
    """A fixed-size terminal window that draws a list of ANSI lines."""

    def __init__(self, cols: int, rows: int, title: str = "bloatrail"):
        self.regular = ImageFont.truetype(find_font("DejaVuSansMono.ttf"), FONT_SIZE)
        self.bold = ImageFont.truetype(find_font("DejaVuSansMono-Bold.ttf"), FONT_SIZE)
        self.chrome_font = ImageFont.truetype(find_font("DejaVuSansMono.ttf"), 12)
        self.cw = self.regular.getlength("M")
        self.width = int(PAD_X * 2 + self.cw * cols)
        self.height = PAD_TOP + LINE_H * rows + PAD_BOT
        self.title = title
        self.lines: list[str] = []

    def render(self, cursor: bool = False) -> Image.Image:
        img = Image.new("RGB", (self.width, self.height), BG)
        draw = ImageDraw.Draw(img)

        draw.rectangle([0, 0, self.width, PAD_TOP - 12], fill=CHROME)
        for i, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            x = 16 + i * 18
            draw.ellipse([x, 11, x + 11, 22], fill=colour)
        label_w = draw.textlength(self.title, font=self.chrome_font)
        draw.text(((self.width - label_w) / 2, 10), self.title,
                  font=self.chrome_font, fill=DIM)

        y = PAD_TOP
        for line in self.lines:
            x = PAD_X
            for text, colour, bold in spans(line):
                for ch in text:
                    if ch != " ":
                        draw.text((x, y), ch, font=self.bold if bold else self.regular,
                                  fill=colour)
                    wide = unicodedata.east_asian_width(ch) in ("W", "F")
                    x += self.cw * (2 if wide else 1)
            y += LINE_H

        if cursor and self.lines:
            x = PAD_X + self.cw * len(plain(self.lines[-1]))
            draw.rectangle([x, y - LINE_H + 3, x + self.cw - 1, y - 4], fill=FG)
        return img


def social_card(body: list[str]) -> Image.Image:
    """The 1280x640 repository card: the name, one line, and real output."""
    width, height, margin = 1280, 640, 64
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)

    title = ImageFont.truetype(find_font("DejaVuSansMono-Bold.ttf"), 58)
    lead = ImageFont.truetype(find_font("DejaVuSansMono.ttf"), 23)
    draw.text((margin, margin - 6), "bloatrail", font=title, fill=BOLD_FG)
    draw.text((margin, margin + 70),
              "Reads the project around each folder before",
              font=lead, fill=FG)
    draw.text((margin, margin + 102),
              "saying what is safe to delete.", font=lead, fill=FG)

    # The tree output, cut to what fits under the heading, in a window.
    size = 17
    regular = ImageFont.truetype(find_font("DejaVuSansMono.ttf"), size)
    bold = ImageFont.truetype(find_font("DejaVuSansMono-Bold.ttf"), size)
    cw = regular.getlength("M")
    line_h = 24
    top = margin + 160
    rows = (height - top - 28) // line_h
    lines = [line for line in body if plain(line).strip()][:rows]
    cols = max(len(plain(line)) for line in lines)
    box = [margin - 16, top - 14, min(width - margin + 16, margin + cols * cw + 16),
           top + rows * line_h + 6]
    draw.rectangle(box, fill=CHROME)

    y = top
    for line in lines:
        x = margin
        for text, colour, is_bold in spans(line):
            for ch in text:
                if x + cw > box[2] - 8:
                    break
                if ch != " ":
                    draw.text((x, y), ch, font=bold if is_bold else regular, fill=colour)
                wide = unicodedata.east_asian_width(ch) in ("W", "F")
                x += cw * (2 if wide else 1)
        y += line_h
    return img


def main() -> None:
    binary = REPO / "target" / "release" / ("bloatrail.exe" if os.name == "nt"
                                           else "bloatrail")
    if not binary.exists():
        sys.exit(f"{binary} not found; run `cargo build --release` first")

    tmp = Path(tempfile.mkdtemp(prefix="bloatrail-demo-"))
    try:
        root = tmp / "Projects"
        root.mkdir()
        build_fixture(root)
        bodies = [capture(binary, argv, root) for _, argv in SCENES]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if "--social" in sys.argv[1:]:
        card = social_card(bodies[0])
        card.save(SOCIAL, optimize=True)
        print(f"{SOCIAL.relative_to(REPO)}  {card.width}x{card.height}  "
              f"{SOCIAL.stat().st_size / 1024:.0f} KB")
        return

    cols = max(max(len(plain(l)) for l in body) for body in bodies)
    cols = max(cols, max(len(cmd) for cmd, _ in SCENES) + 2) + 4
    rows = max(len(body) + 2 for body in bodies)

    frames: list[Image.Image] = []
    delays: list[int] = []
    finals: list[Image.Image] = []

    for index, (cmd, _) in enumerate(SCENES):
        term = Terminal(cols, rows)
        last = index == len(SCENES) - 1

        for typed in range(len(cmd) + 1):
            term.lines = [f"\x1b[32m$\x1b[0m \x1b[1m{cmd[:typed]}\x1b[0m"]
            frames.append(term.render(cursor=True))
            delays.append(500 if typed == 0 else 45)
        frames.append(term.render(cursor=True))
        delays.append(420)

        term.lines.append("")
        for line in bodies[index]:
            term.lines.append(line)
            frames.append(term.render())
            delays.append(55)

        final = term.render()
        finals.append(final)
        frames.append(final)
        delays.append(4200 if last else 2600)

    # One shared palette lets Pillow store only the strip each frame changed,
    # which is what keeps a 100-plus frame animation inside a few hundred KB.
    # It is built from the finished frames so every colour in use is in it.
    probe = Image.new("RGB", (finals[0].width, finals[0].height * len(finals)))
    for i, frame in enumerate(finals):
        probe.paste(frame, (0, i * frame.height))
    palette = probe.quantize(colors=128, method=Image.MEDIANCUT)
    quantized = [f.quantize(palette=palette, dither=Image.NONE) for f in frames]

    quantized[0].save(OUT, save_all=True, append_images=quantized[1:],
                      duration=delays, loop=0, optimize=True, disposal=1)
    size_kb = OUT.stat().st_size / 1024
    print(f"{OUT.relative_to(REPO)}  {len(frames)} frames  "
          f"{frames[0].width}x{frames[0].height}  {size_kb:.0f} KB")


if __name__ == "__main__":
    main()
