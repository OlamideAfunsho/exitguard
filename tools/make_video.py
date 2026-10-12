"""Render the demo video from a real `exitguard demo` run.

Runs the demo with colour forced on, captures its output, and replays that
output as a terminal recording with a caption bar. Nothing on screen is typed
by hand: every terminal line in the video is a line the demo printed.

    python tools/make_video.py [--ffmpeg PATH] [--out docs/demo/exitguard-demo.mp4]

Needs Pillow and an ffmpeg binary. Windows fonts (Consolas, Segoe UI) are used.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
W, H, FPS = 1920, 1080, 24
TOP, BOTTOM = 64, 150
MARGIN, SIZE, LINE_H = 56, 20, 29
ROWS = (H - TOP - BOTTOM - 16) // LINE_H

BG, BAR, RULE = (15, 17, 21), (23, 26, 33), (44, 49, 60)
FG, DIM = (212, 214, 219), (124, 130, 143)
COLOURS = {"31": (240, 113, 120), "32": (140, 200, 130), "33": (229, 192, 123), "34": (110, 160, 240), "36": (102, 194, 205)}
FONTS = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"

# (text that starts the cue, caption, seconds to hold once the cue's output is on screen)
CUES = [
    ("[1] The organisation",
     "A two-treasury organisation on a local chain, running the Squads v4 program exactly as deployed on mainnet. dana is leaving.", 6),
    ("[2] What happens with member removal alone",
     "First, what teams usually do: remove the member and stop there.", 1.5),
    ("    dana spends",
     "dana is no longer a member, and the spending limit still pays out. A spending limit is a separate account with its own delegate list.", 8),
    ("[3] Scan the declared scope",
     "ExitGuard reads everything the declared treasuries depend on: members, limits, and every transaction index from 1 to the latest.", 3),
    ("Authority held by the subject",
     "Two memberships and one spending limit. All three can be removed by proposal.", 5),
    ("Unfinished actions in these treasuries",
     "Unfinished business is listed too. Payments that are already approved stay executable after a member is removed.", 7),
    ("Found outside the declared scope",
     "A treasury nobody declared, found by a best-effort probe and reported separately.", 5),
    ("[4] Decide each row",
     "The operator decides every row: keep, revoke or blocked. Each decision is bound to the hash of what was reviewed.", 8),
    ("[5] Plan the removal",
     "One unsigned config transaction per treasury, limits first, then the member. Built by the official SDK and decoded back independently.", 8),
    ("$ exitguard verify-plan",
     "Before anyone signs, the packet is checked against fresh chain state.", 5),
    ("[6] Members approve and execute",
     "ExitGuard holds no keys. Members approve in their own tooling, and the plan is rechecked before every hand-off.", 7),
    ("[7] Certify the result",
     "After execution it rereads the chain and checks every postcondition before it writes a record.", 6),
    ("  The same spends as before",
     "The same spend as before now fails, and the vault is untouched. The service key's limit, which was meant to stay, still works.", 9),
    ("[8] Verify the record",
     "Anyone holding the digest can verify the record: its integrity, what it recorded, and whether it is still true.", 6),
    ("  A record is not a lock",
     "A record is not a lock. Once dana is added back, the record is still intact as history, but it is no longer current.", 9),
    ("[9] Negative controls",
     "Nineteen ways to break it. Each has to be refused with a named blocker, without publishing a packet or a record.", 11),
    ("Files written",
     "One command, about thirty seconds. The same commit produces the same record digest every time.", 7),
]

ANSI = re.compile(r"\x1b\[([0-9;]*)m")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


MONO, MONO_BOLD = font("consola.ttf", SIZE), font("consolab.ttf", SIZE)
SANS, SANS_SMALL, SANS_BIG = font("segoeui.ttf", 29), font("segoeui.ttf", 21), font("segoeuib.ttf", 76)
SANS_MED = font("segoeui.ttf", 34)
CHAR_W = MONO.getlength("M")


def spans(line: str) -> list[tuple[str, tuple, bool]]:
    """Split one captured line into (text, colour, bold) runs."""
    out, pos, colour, bold = [], 0, FG, False
    for match in ANSI.finditer(line):
        if match.start() > pos:
            out.append((line[pos : match.start()], colour, bold))
        for code in (match.group(1) or "0").split(";"):
            if code in ("0", ""):
                colour, bold = FG, False
            elif code == "1":
                bold = True
            elif code == "2":
                colour = DIM
            elif code in COLOURS:
                colour = COLOURS[code]
        pos = match.end()
    if pos < len(line):
        out.append((line[pos:], colour, bold))
    return out


def plain(line: str) -> str:
    return ANSI.sub("", line)


def capture() -> list[str]:
    env = {**os.environ, "EXITGUARD_COLOR": "1", "PYTHONIOENCODING": "utf-8"}
    env.pop("NO_COLOR", None)
    out_dir = ROOT / "demo-out"
    proc = subprocess.run([sys.executable, "-m", "exitguard", "demo", "--out", "demo-out"], cwd=ROOT, env=env,
                          capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        sys.exit(f"demo failed, not recording:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    assert out_dir.exists()
    return proc.stdout.splitlines()


class Screen:
    def __init__(self, sink):
        self.sink = sink
        self.lines: list[list[tuple[str, tuple, bool]]] = []
        self.caption = ""
        self.section = ""
        self.frames = 0

    def frame(self) -> bytes:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, TOP], fill=BAR)
        d.text((MARGIN, 18), "exitguard demo", font=SANS_SMALL, fill=FG)
        d.text((W - MARGIN, 18), self.section, font=SANS_SMALL, fill=DIM, anchor="ra")
        y = TOP + 16
        for line in self.lines[-ROWS:]:
            x = MARGIN
            for text, colour, bold in line:
                d.text((x, y), text, font=MONO_BOLD if bold else MONO, fill=colour)
                x += CHAR_W * len(text)
            y += LINE_H
        d.rectangle([0, H - BOTTOM, W, H], fill=BAR)
        d.line([0, H - BOTTOM, W, H - BOTTOM], fill=RULE, width=2)
        wrapped = textwrap.wrap(self.caption, 112)[:3]
        cy = H - BOTTOM + (BOTTOM - 40 * len(wrapped)) // 2
        for row in wrapped:
            d.text((MARGIN, cy), row, font=SANS, fill=(236, 237, 240))
            cy += 40
        return img.tobytes()

    def emit(self, frames: int = 1, image: bytes | None = None) -> None:
        data = image or self.frame()
        for _ in range(max(1, frames)):
            self.sink.write(data)
        self.frames += max(1, frames)

    def hold(self, seconds: float) -> None:
        self.emit(int(seconds * FPS))

    def type_command(self, line: str) -> None:
        text = plain(line)
        self.lines.append([])
        for end in range(2, len(text) + 5, 5):
            shown = text[:end]
            self.lines[-1] = [(shown[:2], DIM, False), (shown[2:], FG, True)]
            self.emit(1)
        self.hold(0.35)


def card(sink, title: str, rows: list[str], seconds: float, foot: str = "") -> int:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 330), title, font=SANS_BIG, fill=(240, 241, 244))
    y = 460
    for row in rows:
        d.text((144, y), row, font=SANS_MED, fill=FG)
        y += 56
    if foot:
        d.text((144, H - 150), foot, font=SANS_SMALL, fill=DIM)
    data = img.tobytes()
    for _ in range(int(seconds * FPS)):
        sink.write(data)
    return int(seconds * FPS)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ffmpeg", default=os.environ.get("FFMPEG") or shutil.which("ffmpeg"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo" / "exitguard-demo.mp4"))
    args = ap.parse_args()
    if not args.ffmpeg:
        sys.exit("ffmpeg not found; pass --ffmpeg PATH")

    lines = capture()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    encoder = subprocess.Popen(
        [args.ffmpeg, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
         "-i", "-", "-c:v", "libx264", "-preset", "medium", "-crf", "21", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
         args.out],
        stdin=subprocess.PIPE,
    )
    sink = encoder.stdin
    total = card(sink, "ExitGuard", ["Offboarding a wallet from Squads v4 treasuries,", "spending limits included."], 4.5,
                 "Unedited output of `exitguard demo`. Local simulation against the Squads v4 executable captured from mainnet.")

    screen = Screen(sink)
    cues = list(CUES)
    pending_hold = 0.0
    for raw in lines:
        text = plain(raw)
        if cues and text.startswith(cues[0][0]):
            if pending_hold:
                screen.hold(pending_hold)
            _, caption, pending_hold = cues.pop(0)
            if text.startswith("["):
                screen.lines = []
                screen.section = text
            screen.caption = caption
        if text.startswith("$ "):
            screen.type_command(raw)
            continue
        screen.lines.append(spans(raw))
        screen.emit(2 if text.strip() else 1)
    screen.hold(pending_hold or 4)
    if cues:
        print("warning: cues never matched:", [c[0] for c in cues])
    total += screen.frames
    total += card(sink, "What this was", [
        "A local run. Every record it wrote is labelled LOCAL_SIMULATION.",
        "On mainnet, only a read-only scan has been run. No packet has been executed there.",
        "ExitGuard never holds keys, signs or broadcasts.",
    ], 7, "Source, tests and one full set of output files are in the repository. Start with README.md.")
    sink.close()
    encoder.wait()
    print(f"{args.out}: {total / FPS:.0f}s, {Path(args.out).stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
