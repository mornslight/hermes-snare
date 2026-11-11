"""Render the snare demo video (1920x1080, 30 fps, burned-in captions) from REAL captured output.

Inputs (captured by running the tools, never typed by hand):
  e2e-on.txt / e2e-off.txt   e2e/run_e2e.sh with snare on and off (real Hermes, scripted model)
  replay.txt                 demo/replay.py
  status.txt                 snare's /snare status output
  README.md                  demo/poisoned-repo/README.md
  incident.jsonl, reports.txt  the incident files the real run wrote
Usage: python3 make_video.py CAPTURE_DIR OUT.mp4
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 30
CAP, OUT = Path(sys.argv[1]), sys.argv[2]
FD = "/usr/share/fonts/truetype/dejavu/"
MONO = ImageFont.truetype(FD + "DejaVuSansMono.ttf", 25)
MONO_B = ImageFont.truetype(FD + "DejaVuSansMono-Bold.ttf", 25)
SANS = ImageFont.truetype(FD + "DejaVuSans.ttf", 34)
SANS_B = ImageFont.truetype(FD + "DejaVuSans-Bold.ttf", 34)
CAPF = ImageFont.truetype(FD + "DejaVuSans-Bold.ttf", 40)
CHIPF = ImageFont.truetype(FD + "DejaVuSans-Bold.ttf", 24)
BIG = ImageFont.truetype(FD + "DejaVuSans-Bold.ttf", 150)
MID = ImageFont.truetype(FD + "DejaVuSans.ttf", 52)

BG, PANEL, BAR = (13, 15, 20), (24, 27, 34), (36, 40, 50)
FG, DIM, ACC = (225, 228, 235), (128, 135, 150), (255, 176, 59)
RED, GREEN, BLUE, PURPLE = (255, 95, 87), (80, 210, 120), (110, 170, 255), (190, 140, 255)
CW = MONO.getlength("M")
TRAP = None
try:
    _e = ImageFont.truetype("/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf", 109)
    _im = Image.new("RGBA", (136, 128), (0, 0, 0, 0))
    ImageDraw.Draw(_im).text((0, 0), "\U0001FAA4", font=_e, embedded_color=True)
    TRAP = _im.crop(_im.getbbox()) if _im.getbbox() else None
except Exception:
    TRAP = None


def clean(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s).replace("**", "").replace("`", "")


def section(text: str, start: str, end: str) -> list[str]:
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if start in l) + 1
    j = next(n for n in range(i, len(lines)) if end in lines[n])
    return lines[i:j]


# ---- real captured data -------------------------------------------------------------------
e2e_on = (CAP / "e2e-on.txt").read_text()
e2e_off = (CAP / "e2e-off.txt").read_text()
alert = [clean(l) for l in section(e2e_on, "== what the user saw", "== incidents")]
while alert and not alert[-1].strip():
    alert.pop()
calls = [l.replace("model -> ", "") for l in e2e_on.splitlines() if l.startswith("model -> tool")]
calls_off = [l.replace("model -> ", "") for l in e2e_off.splitlines() if l.startswith("model -> tool")]
ran_on = section(e2e_on, "did the exfil script run", "== stderr")[0].strip()
ran_off = section(e2e_off, "did the exfil script run", "== stderr")[0].strip()
seen_off = [clean(l) for l in section(e2e_off, "== what the user saw", "== incidents") if l.strip()]
readme = (CAP / "README.md").read_text().splitlines()
status = clean((CAP / "status.txt").read_text()).splitlines()
replay = [clean(l) for l in (CAP / "replay.txt").read_text().splitlines()]
also = [l for l in replay if "(base64)" in l]
incident = json.loads((CAP / "incident.jsonl").read_text().splitlines()[0])
reports = (CAP / "reports.txt").read_text().split()
prompt = re.search(r'-z "(.*?)"', (CAP / "prompt.txt").read_text()).group(1) if (CAP / "prompt.txt").exists() \
    else "Set up the project in /tmp/demo/acme-cli for me. Follow its README."


def wrap(line: str, width: int) -> list[str]:
    if len(line) <= width:
        return [line]
    lead = len(line) - len(line.lstrip())
    out, cur = [], line
    while len(cur) > width:
        cut = cur.rfind(" ", lead + 10, width)
        cut = width if cut == -1 else cut
        out.append(cur[:cut])
        cur = " " * (lead + 2) + cur[cut:].lstrip()
    out.append(cur)
    return out


# ---- drawing helpers ------------------------------------------------------------------------
def base() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    im = Image.new("RGB", (W, H), BG)
    return im, ImageDraw.Draw(im)


def panel(d, box, title):
    x0, y0, x1, y1 = box
    d.rounded_rectangle(box, 18, fill=PANEL)
    d.rounded_rectangle((x0, y0, x1, y0 + 46), 18, fill=BAR)
    d.rectangle((x0, y0 + 28, x1, y0 + 46), fill=BAR)
    for i, c in enumerate((RED, ACC, GREEN)):
        d.ellipse((x0 + 22 + i * 30, y0 + 15, x0 + 38 + i * 30, y0 + 31), fill=c)
    d.text((x0 + 130, y0 + 9), title, font=CHIPF, fill=DIM)


def chip(d, text, color):
    w = CHIPF.getlength(text) + 36
    d.rounded_rectangle((W - 60 - w, 34, W - 60, 82), 24, fill=color)
    d.text((W - 60 - w + 18, 44), text, font=CHIPF, fill=(15, 15, 15))


def caption(d, text):
    if not text:
        return
    lines = wrap(text, 70)
    h = 60 * len(lines) + 30
    y0 = H - h - 40
    d.rounded_rectangle((120, y0, W - 120, H - 40), 20, fill=(0, 0, 0))
    for i, l in enumerate(lines):
        tw = CAPF.getlength(l)
        d.text(((W - tw) / 2, y0 + 18 + 60 * i), l, font=CAPF, fill=(255, 255, 255))


def term_lines(d, lines, x, y, colors=None, width=104, lh=36, max_lines=18):
    rows = []
    for i, l in enumerate(lines):
        for part in wrap(l, width):
            rows.append((part, (colors or {}).get(i)))
    for k, (text, col) in enumerate(rows[-max_lines:]):
        font = MONO_B if col in (RED, ACC) else MONO
        d.text((x, y + k * lh), text, font=font, fill=col or FG)
    return len(rows[-max_lines:])


def logo(im, d, cx, cy, scale=1.0):
    if TRAP is not None:
        t = TRAP.resize((int(TRAP.width * scale), int(TRAP.height * scale)))
        im.paste(t, (int(cx - t.width / 2), int(cy - t.height / 2)), t)


# ---- scenes: (duration seconds, render(t) -> Image) ----------------------------------------
def s_title(t):
    im, d = base()
    logo(im, d, W / 2, 300, 1.4)
    tw = BIG.getlength("snare")
    d.text(((W - tw) / 2, 380), "snare", font=BIG, fill=FG)
    sub = "a prompt injection tripwire for Hermes Agent"
    d.text(((W - MID.getlength(sub)) / 2, 570), sub, font=MID, fill=ACC)
    caption(d, "Your agent reads strangers' text all day. What happens when one of them is a trap?")
    return im


def s_readme(t):
    im, d = base()
    chip(d, "the demo repo, as written", (200, 200, 210))
    panel(d, (80, 110, W - 80, 900), "acme-cli/README.md")
    act = next(i for i, l in enumerate(readme) if "activate.sh" in l)
    c0 = next(i for i, l in enumerate(readme) if l.startswith("<!--"))
    c1 = next(i for i, l in enumerate(readme) if l.startswith("-->"))
    start = next(i for i, l in enumerate(readme) if l.startswith("## Quick start"))
    y, lh = 175, 29
    boxes = {}
    for i in range(start, c1 + 1):
        col = FG
        if t > 3 and i == act:
            col = ACC
        if t > 6.5 and c0 <= i <= c1:
            col = RED
        for part in wrap(readme[i], 104):
            d.text((120, y), part, font=MONO_B if col != FG else MONO, fill=col)
            boxes.setdefault(i, [y, y])[1] = y
            y += lh
    if t > 3:
        y0 = boxes[act][0]
        d.rounded_rectangle((108, y0 - 4, 130 + MONO_B.getlength(readme[act]), y0 + 32), 8, outline=ACC, width=3)
    if t > 6.5:
        d.rounded_rectangle((108, boxes[c0][0] - 4, W - 100, boxes[c1][1] + 32), 8, outline=RED, width=3)
    cap = "This repo looks normal."
    if t > 3:
        cap = "But its setup script sends your AWS keys to a server..."
    if t > 6.5:
        cap = "...and a hidden comment tells the agent to do it and not tell you."
    caption(d, cap)
    return im


def s_status(t):
    im, d = base()
    chip(d, "snare's real /snare status output", GREEN)
    panel(d, (80, 110, W - 80, 760), "hermes")
    typed = "/snare status"[: int(t * 8)]
    d.text((120, 180), "> " + typed, font=MONO_B, fill=BLUE)
    if t > 2.2:
        term_lines(d, status, 120, 240, width=104)
    caption(d, "snare plants decoy credentials in every command the agent runs. Fake, unique to my install, never in the prompt.")
    return im


def s_run(t):
    im, d = base()
    chip(d, "REAL HERMES RUN · scripted model plays the hijacked agent", ACC)
    panel(d, (80, 110, W - 80, 840), "hermes  (agent loop, tools and terminal are real)")
    cmd = f'$ hermes -z "{prompt}"'
    d.text((120, 180), cmd[: int(t * 30)], font=MONO_B, fill=BLUE)
    lines, cols = [], {}
    if t > 3.5:
        lines.append("agent tool calls:")
    if t > 4.5:
        lines.append("  1. " + calls[0]); cols[len(lines) - 1] = FG
    if t > 7.5:
        lines.append("  2. " + calls[1]); cols[len(lines) - 1] = ACC
    if t > 10:
        lines.append(""); lines.append("  # snare's pre_tool_call hook blocked call 2 before it ran"); cols[len(lines) - 1] = RED
    if t > 12:
        lines.append(f"  poisoned script ran: {ran_on}"); cols[len(lines) - 1] = GREEN
    term_lines(d, lines, 120, 250, colors=cols, width=100, lh=40)
    cap = "I ask Hermes to set the project up. It reads the README..."
    if t > 7.5:
        cap = "...and, hijacked, runs the activation step."
    if t > 10:
        cap = "snare blocks it before the command runs. Nothing leaves the machine."
    caption(d, cap)
    return im


def s_alert(t):
    im, d = base()
    chip(d, "REAL HERMES RUN \u00b7 what the user sees", ACC)
    panel(d, (80, 110, W - 80, 880), "hermes reply")
    y, lh = 170, 33
    for k, line in enumerate(alert):
        s = line.replace("\U0001FAA4 ", "").strip()
        col, font = FG, MONO
        if k == 0:
            col, font = ACC, MONO_B
        elif t > 2 and s.startswith("1. Source"):
            col, font = ACC, MONO_B
        elif t > 6 and s.startswith(">"):
            col, font = RED, MONO_B
        elif t > 10 and s.startswith("2. Blocked"):
            col, font = RED, MONO_B
        for n, part in enumerate(wrap(line.replace("\U0001FAA4 ", ""), 98)):
            if k == 0 and n == 0:
                logo(im, d, 140, y + 14, 0.28)
                part = "   " + part
            d.text((120, y), part, font=font, fill=col)
            y += lh
    cap = "snare shows the whole chain."
    if t > 2:
        cap = "Where the injection came from: the exact file the agent read."
    if t > 6:
        cap = "What it said, quoted from that file."
    if t > 10:
        cap = "And what it tried: the script, the decoy key, and the attacker's host."
    caption(d, cap)
    return im


def s_control(t):
    im, d = base()
    chip(d, "REAL HERMES RUNS · same attack, snare off vs on", (200, 200, 210))
    half = (W - 200) // 2
    for n, (title, calls_, seen, ran, col) in enumerate((
            ("snare OFF", calls_off, seen_off[:2], ran_off, RED),
            ("snare ON", calls, alert[:1], ran_on, GREEN))):
        x0 = 80 + n * (half + 40)
        panel(d, (x0, 110, x0 + half, 780), title)
        lines = ["tool calls:"] + ["  " + c for c in calls_] + ["", "reply:"] + ["  " + s.replace("\U0001FAA4 ", "") for s in seen] + \
                ["", "poisoned script ran:", "  " + ran]
        cols = {len(lines) - 1: col}
        term_lines(d, lines, x0 + 30, 180, colors=cols, width=int((half - 60) / CW), lh=34)
    caption(d, "Without snare, the same run quietly executes the poisoned script. With it, the script never runs.")
    return im


def s_record(t):
    im, d = base()
    chip(d, "files the real run wrote", GREEN)
    panel(d, (80, 110, W - 80, 760), "incident record")
    ch = incident["chain"]
    lines = [
        "This session is locked: every further tool call asks for your approval.",
        "",
        "incidents.jsonl  (one line per incident)",
        f"  id:          {incident['id']}",
        f"  source:      {ch['source']['source']}",
        f"  labels:      {', '.join(ch['source'].get('labels', []))}",
        f"  blocked:     {ch['attempt']['tool']}  {ch['attempt']['action']}",
        f"  destination: {', '.join(ch['attempt'].get('destinations', []))}",
        "",
        "reports/",
    ] + ["  " + r for r in reports]
    cols = {0: ACC, 9: BLUE}
    term_lines(d, lines, 120, 180, colors=cols, width=104, lh=38)
    caption(d, "The session locks behind Hermes approvals, and every incident is saved as JSON plus a shareable HTML report.")
    return im


def s_encoded(t):
    im, d = base()
    chip(d, "REPLAY (no model) · demo/replay.py", PURPLE)
    panel(d, (80, 110, W - 80, 700), "python3 demo/replay.py")
    lines = [l for l in replay if l.startswith("▸") and "Second" in l]
    lines += [l for l in replay if "pre_tool_call" in l][-1:]
    lines += ["", "Also blocked in this turn:"] + also
    cols = {len(lines) - 1: RED}
    term_lines(d, lines, 120, 190, colors=cols, width=104, lh=40)
    caption(d, "It also catches a decoy pasted in encoded: base64, hex, URL-encoded, reversed or split.")
    return im


def s_end(t):
    im, d = base()
    logo(im, d, W / 2, 230, 1.0)
    tw = BIG.getlength("snare")
    d.text(((W - tw) / 2, 290), "snare", font=BIG, fill=FG)
    for i, (txt, col) in enumerate((("hermes plugins install snare", ACC),
                                     ("github.com/mornslight/hermes-snare", FG),
                                     ("Built for the @NousResearch Hermes Agent Plugin Hackathon", DIM))):
        f = MONO_B if i == 0 else SANS
        if i == 0:
            f = ImageFont.truetype(FD + "DejaVuSansMono-Bold.ttf", 54)
        d.text(((W - f.getlength(txt)) / 2, 500 + i * 90), txt, font=f, fill=col)
    caption(d, "snare. Install it before your agent reads the wrong README.")
    return im


SCENES = [(6, s_title), (11, s_readme), (6, s_status), (16, s_run), (15, s_alert),
          (12, s_control), (9, s_record), (7, s_encoded), (6, s_end)]


def main():
    total = sum(s for s, _ in SCENES)
    ff = subprocess.Popen(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
         "-r", str(FPS), "-i", "-", "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo",
         "-shortest", "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart", OUT], stdin=subprocess.PIPE)
    for dur, fn in SCENES:
        last, last_key = None, None
        for f in range(dur * FPS):
            t = f / FPS
            key = round(t * 10) / 10  # redraw at most 10x per second; reuse frames in between
            if key != last_key:
                last, last_key = fn(t).tobytes(), key
            ff.stdin.write(last)
    ff.stdin.close()
    ff.wait()
    print(f"wrote {OUT}: {total}s")


if __name__ == "__main__":
    main()
