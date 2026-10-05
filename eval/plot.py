"""Draw the README figures, in a dark and a light version each.

    python eval/plot.py        # the results and retries figures read eval/data/ (see eval/README.md)

Writes to docs/img/:

  beacon-vs-browsing-{dark,light}.svg   what a beacon looks like next to a person browsing
  missed-checkins-{dark,light}.svg      problem 1: gaps that are whole multiples of the timer
  retries-{dark,light}.svg              problem 2: how a dead server scrambles Hakai's timer in Zeek's log
  results-{dark,light}.svg              every scorable C&C channel in IoT-23, before and after
  simulation-{dark,light}.svg           how detection holds up as check-ins go missing

The README picks the version that matches the viewer's GitHub theme. Each SVG
carries its own colours (no stylesheet), so it renders the same everywhere.
"""

from __future__ import annotations

import random
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

import iot23  # noqa: E402
import simulate  # noqa: E402
from beacon_hunter.scoring import Settings, analyze, merge_events  # noqa: E402

OUT = ROOT / "docs" / "img"
DATA = ROOT / "eval" / "data"
W = 760
FONT = 'system-ui, -apple-system, &quot;Segoe UI&quot;, Helvetica, Arial, sans-serif'

THEMES = {
    "dark": dict(surface="#1a1a19", ink="#ffffff", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a",
                 axis="#4a4a46", accent="#3987e5", zone="#17304d", context="#898781",
                 good="#0ca30c", bad="#d03b3b", glyph="#ffffff"),
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9",
                  axis="#c3c2b7", accent="#2a78d6", zone="#dbe9fa", context="#898781",
                  good="#0ca30c", bad="#d03b3b", glyph="#ffffff"),
}


# --------------------------------------------------------------- primitives

class Canvas:
    def __init__(self, theme: dict, height: int, label: str):
        self.t, self.h, self.label, self.parts = theme, height, label, []

    def add(self, svg: str) -> None:
        self.parts.append(svg)

    def text(self, x, y, s, size=12, color="ink2", weight=400, anchor="start"):
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" '
                 f'fill="{self.t[color]}" text-anchor="{anchor}">{escape(str(s))}</text>')

    def line(self, x1, y1, x2, y2, color="axis", width=1, dash=None, cap="butt"):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{self.t[color]}" '
                 f'stroke-width="{width}" stroke-linecap="{cap}"{d}/>')

    def dot(self, x, y, color, r=5):
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{self.t[color]}" '
                 f'stroke="{self.t["surface"]}" stroke-width="2"/>')

    def title(self, title, subtitle=None):
        self.text(28, 40, title, size=17, color="ink", weight=600)
        if subtitle:
            self.text(28, 63, subtitle, size=13, color="ink2")

    def verdict(self, x, y, ok: bool, bold: str, rest: str):
        """A status mark with its label: never colour alone."""
        c = self.t["good" if ok else "bad"]
        g = self.t["glyph"]
        if ok:
            glyph = (f'<path d="M{x - 3.6:.1f},{y:.1f} l2.4,2.6 l4.8,-5.2" stroke="{g}" stroke-width="1.8" '
                     f'fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
        else:
            glyph = (f'<path d="M{x - 3:.1f},{y - 3:.1f} l6,6 M{x + 3:.1f},{y - 3:.1f} l-6,6" stroke="{g}" '
                     f'stroke-width="1.8" stroke-linecap="round"/>')
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{c}"/>{glyph}')
        self.add(f'<text x="{x + 16:.1f}" y="{y + 4.5:.1f}" font-size="13" fill="{self.t["ink2"]}">'
                 f'<tspan font-weight="600" fill="{self.t["ink"]}">{escape(bold)}</tspan> {escape(rest)}</text>')

    def bracket(self, x1, x2, y, label, color="ink2"):
        self.add(f'<path d="M{x1:.1f},{y + 5:.1f} V{y:.1f} H{x2:.1f} V{y + 5:.1f}" fill="none" '
                 f'stroke="{self.t["muted"]}" stroke-width="1"/>')
        self.text((x1 + x2) / 2, y - 7, label, size=12, color=color, anchor="middle")

    def render(self) -> str:
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {self.h}" width="{W}" height="{self.h}" '
                f'role="img" aria-label="{escape(self.label)}" font-family="{FONT}">'
                f'<rect width="{W}" height="{self.h}" rx="10" fill="{self.t["surface"]}"/>'
                + "".join(self.parts) + "</svg>\n")


def ticks(c: Canvas, x0, x1, y, times, span, color="accent", height=13, width=2):
    for t in times:
        x = x0 + t / span * (x1 - x0)
        c.line(x, y - height, x, y + height, color=color, width=width, cap="round")


# ------------------------------------------------------------------ figure 1

def beacon_vs_browsing(theme: dict) -> str:
    c = Canvas(theme, 300, "Two timelines over one hour: a person browsing makes connections at irregular "
                           "moments, malware checking in makes one every five minutes")
    c.title("A beacon is a program that checks in on a timer",
            "One hour of connections from a laptop to two destinations. Each line is one connection.")
    x0, x1, span = 220, 732, 60.0

    rng = random.Random(11)
    browsing, t = [], 1.5
    while t < 59:
        burst = [t + rng.uniform(0, 0.6) for _ in range(rng.randint(2, 5))]
        browsing += [b for b in burst if b < 59.5]
        t = max(burst) + rng.expovariate(1 / 9)
    beacon = [2.5 + 5 * i for i in range(12)]

    rows = ((130, "A person browsing", "gaps all over the place", browsing, "context"),
            (215, "Malware checking in", "the same gap, all day", beacon, "accent"))
    for y, name, note, times, color in rows:
        c.text(28, y - 3, name, size=14, color="ink", weight=600)
        c.text(28, y + 15, note, size=12.5, color="muted")
        c.line(x0, y + 14, x1, y + 14, color="axis")
        ticks(c, x0, x1, y, times, span, color=color)

    bx = lambda m: x0 + m / span * (x1 - x0)  # noqa: E731
    c.bracket(bx(beacon[5]), bx(beacon[6]), 215 - 22, "5 min", color="ink")
    for m in (0, 15, 30, 45, 60):
        c.text(bx(m), 262, f"{m} min", size=11.5, color="muted", anchor="middle")
    c.text(x0, 286, "beacon-hunter measures how regular the gaps are, for every pair of machines in your logs.",
           size=12.5, color="ink2")
    return c.render()


# ------------------------------------------------------------------ figure 2

def missed_checkins(theme: dict) -> str:
    c = Canvas(theme, 300, "A one-minute timer that missed three check-ins: the gaps are 1, 1, 1, 2, 1, 3, 1, 1, 1 "
                           "minutes, all whole multiples of one minute")
    c.title("Problem 1: real beacons miss check-ins",
            "A laptop sleeps, a packet drops. Here a 1-minute timer misses 3 of its 13 check-ins.")
    x0, x1, span, y = 60, 700, 12.0, 140
    present = [0, 1, 2, 3, 5, 6, 9, 10, 11, 12]
    missed = [4, 7, 8]
    X = lambda m: x0 + m / span * (x1 - x0)  # noqa: E731

    c.line(x0, y + 14, x1, y + 14, color="axis")
    ticks(c, x0, x1, y, present, span, color="accent")
    for m in missed:
        c.line(X(m), y - 13, X(m), y + 13, color="muted", width=1.5, dash="3 3")
    c.text(X(4), y - 24, "missed", size=12, color="muted", anchor="middle")
    c.text(X(7.5), y - 24, "missed", size=12, color="muted", anchor="middle")

    c.text(x0 - 12, y + 40, "gap", size=12, color="muted", anchor="end")
    for a, b in zip(present, present[1:]):
        gap = b - a
        c.text((X(a) + X(b)) / 2, y + 40, f"{gap}m", size=12.5,
               color="ink" if gap > 1 else "muted", weight=600 if gap > 1 else 400, anchor="middle")

    c.verdict(36, 232, False, "Standard check:", "gaps of 1, 2 and 3 minutes look irregular, so it isn't flagged.")
    c.verdict(36, 266, True, "beacon-hunter:", "every gap is a whole number of minutes. A 1-minute timer, 3 check-ins missed.")
    return c.render()


# ------------------------------------------------------------------ figure 3

HAKAI = DATA / "CTU-IoT-Malware-Capture-8-1.conn.log.labeled"
HAKAI_PCAP = DATA / "CTU-IoT-Malware-Capture-8-1.pcap"
C2 = "128.185.250.50"


def hakai_real():
    """Two full attempts from the raw packets, and Zeek's records for the same moments."""
    from beacon_hunter import pcap
    syns = []
    with open(HAKAI_PCAP, "rb") as fh:
        for ts, lt, frame in pcap.packets(fh):
            p = pcap.decode(lt, frame)
            if p and p.proto == "tcp" and p.dst == C2 and p.flags & 0x02:
                syns.append((ts, p.sport))
            if len(syns) > 40:
                break
    ports = []
    for _, port in syns:
        if port not in ports:
            ports.append(port)
    first, third = ports[0], ports[2]
    t0 = min(t for t, port in syns if port == first)
    t_end = min(t for t, port in syns if port == third)
    packets = [(t - t0, port) for t, port in syns if t < t_end]
    conns, _ = iot23.read_labeled(HAKAI)
    records = sorted(c.ts - t0 for c in conns if c.dst == C2 and t0 - 0.5 <= c.ts <= t_end + 0.5)
    return packets, records, t_end - t0


def retries(theme: dict) -> str:
    packets, records, span = hakai_real()
    c = Canvas(theme, 404, "Hakai malware makes one connection attempt every 80 seconds to a server that never "
                           "answers; the operating system retries each one, and Zeek logs the retries as separate "
                           "connections 7, 8, 17 and 48 seconds apart")
    c.title("Problem 2: a dead server scrambles the timer in the log",
            "Real traffic: Hakai malware calling its command server, which never answers (IoT-23 capture 8-1).")
    x0, x1 = 196, 724
    X = lambda t: x0 + t / span * (x1 - x0)  # noqa: E731

    # What the program does: one attempt per source port, plus the OS's automatic retries.
    y1 = 140
    c.text(28, y1 - 3, "What the malware does", size=14, color="ink", weight=600)
    c.text(28, y1 + 15, "one attempt every 80 s", size=12.5, color="muted")
    c.line(x0, y1 + 14, x1, y1 + 14, color="axis")
    seen = set()
    for t, port in packets:
        if port not in seen:
            seen.add(port)
            c.line(X(t), y1 - 16, X(t), y1 + 14, color="accent", width=2.5, cap="round")
        else:
            c.line(X(t), y1 + 2, X(t), y1 + 14, color="muted", width=1.5, cap="round")
    starts = sorted({min(t for t, p in packets if p == port) for port in seen})
    c.bracket(X(starts[0]), X(starts[1]), y1 - 26, "80 s", color="ink")
    c.text(X(starts[0]) + 6, y1 + 32, "short marks: the OS re-sending the unanswered request (1, 3, 7, 15, 31 s)",
           size=11.5, color="muted")

    # What Zeek's conn.log records for the same minutes.
    y2 = 250
    c.text(28, y2 - 3, "What Zeek's log records", size=14, color="ink", weight=600)
    c.text(28, y2 + 15, "4 \"connections\" per attempt", size=12.5, color="muted")
    c.line(x0, y2 + 14, x1, y2 + 14, color="axis")
    for t in records:
        c.line(X(t), y2 - 14, X(t), y2 + 14, color="context", width=2.5, cap="round")
    for a, b in zip(records, records[1:]):
        c.text((X(a) + X(b)) / 2, y2 + 34, f"{b - a:.0f}s", size=12, color="ink2", anchor="middle")

    c.verdict(36, 324, False, "Standard check on the log:", "gaps of 7, 8, 17, 48 s look irregular. Score 0.65, not flagged.")
    c.verdict(36, 358, True, "beacon-hunter:", "retries keep the same source port, so they count once. Every 80 s: score 1.00.")
    return c.render()


# ------------------------------------------------------------------ figure 4

def results_rows():
    """Every scorable C&C channel in the IoT-23 captures, grouped by what it is."""
    found = {}
    plain_settings = Settings(fold=False, cycles=False, merge_retries=False)
    for path in sorted(DATA.glob("CTU-IoT-*.labeled")):
        name = path.name.split(".")[0]
        conns, labels = iot23.read_labeled(path)
        full = analyze(conns, Settings())
        plain = {iot23.key(f): f.timing for f in analyze(conns, plain_settings)}
        found[name] = [(f.timing, plain[iot23.key(f)]) for f in full if iot23.key(f) in labels]

    def avg(*names):
        pairs = [p for n in names for p in found[f"CTU-IoT-Malware-Capture-{n}"]]
        return (sum(p for _, p in pairs) / len(pairs), sum(f for f, _ in pairs) / len(pairs))

    return [
        ("Mirai botnet", "IRC command channel", *avg("34-1"), True, "Caught.", "Tries every 10 s; rarely answered."),
        ("Hakai botnet", "2 command servers", *avg("8-1"), True, "Caught.", "Tries every 80 s; never answered."),
        ("Mirai botnet", "malware download", *avg("44-1"), False, "Not a beacon.", "One burst of downloads."),
    ]


def results(theme: dict) -> str:
    rows = results_rows()
    top, row_h = 140, 62
    bottom = top + row_h * len(rows) - 20
    H = bottom + 82
    c = Canvas(theme, H, "Real command-and-control traffic from IoT-23: the standard method misses the Mirai and "
                         "Hakai channels, beacon-hunter flags both; a one-off download stays unflagged")
    c.title("Tested on real malware traffic",
            "How regular each command-and-control channel looks, from 0 (random) to 1 (clockwork).")
    x0, x1 = 236, 520
    X = lambda v: x0 + v * (x1 - x0)  # noqa: E731

    c.add(f'<rect x="{X(0.8):.1f}" y="{top - 26}" width="{X(1.0) - X(0.8) + 10:.1f}" '
          f'height="{bottom - top + 34}" rx="4" fill="{theme["zone"]}"/>')
    c.text(X(0.9) + 5, top - 34, "flagged as a beacon", size=12, color="ink", weight=600, anchor="middle")
    for v, lab in ((0, "0 · random"), (0.5, "0.5"), (1.0, "1 · clockwork")):
        c.line(X(v), top - 26, X(v), bottom + 8, color="grid")
        c.text(X(v), bottom + 26, lab, size=11.5, color="muted", anchor="middle")

    c.dot(34, 92, "context", r=6)
    c.text(47, 96.5, "standard method", size=12.5, color="ink2")
    c.dot(176, 92, "accent", r=6)
    c.text(189, 96.5, "beacon-hunter", size=12.5, color="ink2")

    for i, (name, what, plain, full, caught, verdict, why) in enumerate(rows):
        y = top + i * row_h
        c.text(28, y + 4, name, size=14, color="ink", weight=600)
        c.text(28, y + 22, what, size=12.5, color="muted")
        if full - plain > 0.15:   # only draw an arrow for a real move
            c.line(X(plain) + 8, y, X(full) - 10, y, color="muted", width=1.5)
            tip = X(full) - 9
            c.add(f'<path d="M{tip - 7:.1f},{y - 4.5:.1f} L{tip:.1f},{y:.1f} L{tip - 7:.1f},{y + 4.5:.1f}" '
                  f'fill="none" stroke="{theme["muted"]}" stroke-width="1.5" stroke-linejoin="round"/>')
        c.dot(X(plain), y, "context", r=6)
        c.dot(X(full), y, "accent", r=6)
        c.text(552, y + 4, verdict, size=13.5, color="ink" if caught else "ink2", weight=600)
        c.text(552, y + 22, why, size=12, color="muted")

    c.text(28, H - 22, "Not shown: 9 more C&C channels had too few attempts to judge (one-off downloads, single "
                       "long sessions, Torii's handful of tries).", size=12, color="muted")
    return c.render()


# ------------------------------------------------------------------ figure 5

def simulation(theme: dict) -> str:
    levels = (0.0, 0.15, 0.3, 0.45)
    plain, full = [], []
    for m in levels:
        gen = (lambda r, m=m: simulate.beacon(r, 0.2, m))
        plain.append(simulate.rate(gen, False, random.Random(1)))
        full.append(simulate.rate(gen, True, random.Random(1)))

    c = Canvas(theme, 360, "Line chart: as more check-ins go missing, the standard method stops catching "
                           "beacons while beacon-hunter keeps catching most of them")
    c.title("Missed check-ins break the standard method",
            "Share of 500 simulated beacons caught (5-minute timer, ±20% jitter). Random traffic flagged: 0% for both.")
    x0, x1, y0, y1 = 90, 560, 296, 104
    X = lambda i: x0 + i / (len(levels) - 1) * (x1 - x0)  # noqa: E731
    Y = lambda v: y0 - v * (y0 - y1)  # noqa: E731
    for v in (0, 0.5, 1.0):
        c.line(x0, Y(v), x1, Y(v), color="axis" if v == 0 else "grid")
        c.text(x0 - 10, Y(v) + 4, f"{v:.0%}", size=11.5, color="muted", anchor="end")
    for i, m in enumerate(levels):
        c.text(X(i), y0 + 20, f"{m:.0%}", size=11.5, color="muted", anchor="middle")
    c.text((x0 + x1) / 2, y0 + 44, "check-ins missed", size=12.5, color="ink2", anchor="middle")

    for series, color in ((plain, "context"), (full, "accent")):
        pts = " ".join(f"{X(i):.1f},{Y(v):.1f}" for i, v in enumerate(series))
        c.add(f'<polyline points="{pts}" fill="none" stroke="{theme[color]}" stroke-width="2.5" '
              f'stroke-linejoin="round" stroke-linecap="round"/>')
        for i, v in enumerate(series):
            c.dot(X(i), Y(v), color, r=5)

    c.text(X(3) + 14, Y(full[3]) + 4, "beacon-hunter", size=13, color="ink", weight=600)
    c.text(X(3) + 14, Y(plain[3]) + 4, "standard method", size=13, color="ink2", weight=600)
    c.text(X(2) - 12, Y(full[2]) + 22, f"{full[2]:.0%} caught", size=13, color="ink", weight=600, anchor="end")
    c.text(X(2) + 12, Y(plain[2]) - 10, f"{plain[2]:.0%}", size=13, color="ink2", weight=600)
    return c.render()


FIGURES = {
    "beacon-vs-browsing": (beacon_vs_browsing, False),
    "missed-checkins": (missed_checkins, False),
    "retries": (retries, True),
    "results": (results, True),
    "simulation": (simulation, False),
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    have_data = HAKAI.exists() and HAKAI_PCAP.exists()
    for name, (draw, needs_data) in FIGURES.items():
        if needs_data and not have_data:
            print(f"skipped {name}: needs the IoT-23 logs in eval/data/ (see eval/README.md)")
            continue
        for mode, theme in THEMES.items():
            (OUT / f"{name}-{mode}.svg").write_text(draw(theme), encoding="utf-8")
    print(f"wrote figures to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
