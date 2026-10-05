"""Draw the two README figures as SVG, straight from the evaluation code.

    python eval/plot.py            # needs eval/data/ for the IoT-23 figure

docs/img/simulation.svg   detection rate vs missed check-ins, three jitter levels
docs/img/iot23.svg        timing score of each scorable C&C pair, plain vs beacon-hunter

Emphasis form: beacon-hunter in the accent blue, plain scoring in gray. Light
and dark palettes are both selected, so the images follow the viewer's theme.
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
from beacon_hunter.scoring import ON_A_TIMER, Settings, analyze  # noqa: E402

OUT = ROOT / "docs" / "img"
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

STYLE = f"""
<style>
  svg {{ --surface:#fcfcfb; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781; --grid:#e1e0d9;
         --axis:#c3c2b7; --accent:#2a78d6; --context:#898781; }}
  @media (prefers-color-scheme: dark) {{
    svg {{ --surface:#1a1a19; --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781; --grid:#2c2c2a;
           --axis:#383835; --accent:#3987e5; --context:#898781; }}
  }}
  text {{ font-family:{FONT}; fill:var(--muted); font-size:12px; }}
  .title {{ fill:var(--ink); font-size:15px; font-weight:600; }}
  .sub {{ fill:var(--ink-2); font-size:12.5px; }}
  .label {{ fill:var(--ink-2); font-size:12px; }}
  .value {{ fill:var(--ink); font-size:12px; font-weight:600; }}
  .grid {{ stroke:var(--grid); stroke-width:1; }}
  .axis {{ stroke:var(--axis); stroke-width:1; }}
  .accent {{ stroke:var(--accent); fill:var(--accent); }}
  .context {{ stroke:var(--context); fill:var(--context); }}
  .line {{ fill:none; stroke-width:2; stroke-linejoin:round; stroke-linecap:round; }}
  .dot {{ stroke:var(--surface); stroke-width:2; }}
</style>"""


def svg(width: int, height: int, body: str, label: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" role="img" aria-label="{escape(label)}">'
            f'{STYLE}<rect width="100%" height="100%" fill="var(--surface)" rx="8"/>{body}</svg>\n')


def legend(x: float, y: float) -> str:
    return (f'<line x1="{x}" y1="{y}" x2="{x + 18}" y2="{y}" class="line accent"/>'
            f'<text x="{x + 24}" y="{y + 4}" class="label">beacon-hunter</text>'
            f'<line x1="{x + 130}" y1="{y}" x2="{x + 148}" y2="{y}" class="line context"/>'
            f'<text x="{x + 154}" y="{y + 4}" class="label">plain timing score</text>')


# ------------------------------------------------------------------ simulation

def simulation_figure() -> str:
    missed_levels = (0.0, 0.15, 0.3, 0.45)
    panels = []
    for jitter in (0.1, 0.2, 0.3):
        plain, full = [], []
        for missed in missed_levels:
            gen = (lambda r, j=jitter, m=missed: simulate.beacon(r, j, m))
            plain.append(simulate.rate(gen, False, random.Random(1)))
            full.append(simulate.rate(gen, True, random.Random(1)))
        panels.append((jitter, plain, full))

    W, H = 760, 354
    left, top, pw, ph, gap = 56, 116, 200, 170, 28
    body = [
        f'<text x="24" y="32" class="title">Beacons that miss check-ins are still found</text>',
        f'<text x="24" y="52" class="sub">Share of 500 simulated beacons called a timer, by how many check-ins were missed. '
        f'Random traffic: 0% either way.</text>',
        legend(24, 72),
    ]
    for n, (jitter, plain, full) in enumerate(panels):
        x0 = left + n * (pw + gap)
        body.append(f'<text x="{x0}" y="{top - 8}" class="label">±{jitter:.0%} jitter</text>')
        for pct in (0, 0.5, 1.0):
            y = top + ph - pct * ph
            body.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x0 + pw}" y2="{y:.1f}" '
                        f'class="{"axis" if pct == 0 else "grid"}"/>')
            if n == 0:
                body.append(f'<text x="{x0 - 8}" y="{y + 4:.1f}" text-anchor="end">{pct:.0%}</text>')
        xs = [x0 + i / (len(missed_levels) - 1) * pw for i in range(len(missed_levels))]
        for i, m in enumerate(missed_levels):
            body.append(f'<text x="{xs[i]:.1f}" y="{top + ph + 18}" text-anchor="middle">{m:.0%}</text>')
        for series, cls in ((plain, "context"), (full, "accent")):
            pts = " ".join(f"{x:.1f},{top + ph - v * ph:.1f}" for x, v in zip(xs, series))
            body.append(f'<polyline points="{pts}" class="line {cls}"/>')
            for x, v in zip(xs, series):
                body.append(f'<circle cx="{x:.1f}" cy="{top + ph - v * ph:.1f}" r="4" class="dot {cls}"/>')
        # Label the point the story is about: 30% missed. The blue line arrives from the
        # upper left and leaves to the lower right, so its label sits below-left; the
        # gray one sits above-right, clear of its own steep drop.
        yf = top + ph - full[2] * ph
        yp = top + ph - plain[2] * ph
        body.append(f'<text x="{xs[2] - 8:.1f}" y="{yf + 18:.1f}" text-anchor="end" class="value">{full[2]:.0%}</text>')
        body.append(f'<text x="{xs[2] + 8:.1f}" y="{yp - 9:.1f}" class="label">{plain[2]:.0%}</text>')
    body.append(f'<text x="{left + (3 * pw + 2 * gap) / 2}" y="{H - 14}" text-anchor="middle" class="label">'
                f'check-ins missed</text>')
    return svg(W, H, "".join(body), "Line charts: detection rate of simulated beacons as missed check-ins rise, "
                                   "beacon-hunter versus plain scoring, at three jitter levels")


# ----------------------------------------------------------------------- IoT-23

def iot23_rows(data: Path):
    """(label, detail, plain timing, beacon-hunter timing) per scorable C&C pair."""
    found = []
    for path in sorted(data.glob("*.labeled")):
        name = path.name.split(".")[0]
        capture = name.rsplit("-", 2)[-2] + "-" + name.rsplit("-", 2)[-1]
        conns, labels = iot23.read_labeled(path)
        full = analyze(conns, Settings())
        plain = {iot23.key(f): f for f in analyze(conns, Settings(fold=False, cycles=False))}
        for f in full:
            if iot23.key(f) in labels:
                found.append((iot23.FAMILY[name], capture, f, plain[iot23.key(f)].timing))

    rows, hakai = [], [r for r in found if r[0] == "Hakai"]
    for family, capture, f, p in found:
        if family == "Hakai":
            continue
        rows.append((f"{family} · {f.dst}:{f.dport}", f"capture {capture} · {f.connections:,} connections", p, f.timing))
    if hakai:
        # Two C2 servers, same retry loop, same scores: one row.
        conns = " + ".join(f"{r[2].connections:,}" for r in hakai)
        p = sum(r[3] for r in hakai) / len(hakai)
        b = sum(r[2].timing for r in hakai) / len(hakai)
        rows.append((f"Hakai · {len(hakai)} C2 servers :{hakai[0][2].dport}",
                     f"capture {hakai[0][1]} · {conns} connections", p, b))
    rows.sort(key=lambda r: -(r[3] - r[2]))
    return rows


def iot23_figure(data: Path) -> str:
    rows = iot23_rows(data)
    W = 760
    left, right, top, row_h = 270, 60, 104, 44
    H = top + row_h * len(rows) + 46
    pw = W - left - right
    xof = lambda v: left + v * pw  # noqa: E731
    body = [
        f'<text x="24" y="32" class="title">Real C&amp;C traffic from IoT-23 malware captures</text>',
        f'<text x="24" y="52" class="sub">Timing score of every labeled C&amp;C pair with enough connections to judge.</text>',
        legend(24, 72),
    ]
    for v in (0, 0.25, 0.5, 0.75, 1.0):
        body.append(f'<line x1="{xof(v):.1f}" y1="{top - 8}" x2="{xof(v):.1f}" y2="{H - 40}" '
                    f'class="{"axis" if v == 0 else "grid"}"/>')
        body.append(f'<text x="{xof(v):.1f}" y="{H - 22}" text-anchor="middle">{v:.2f}</text>')
    tx = xof(ON_A_TIMER)
    body.append(f'<line x1="{tx:.1f}" y1="{top - 14}" x2="{tx:.1f}" y2="{H - 40}" class="axis"/>'
                f'<text x="{tx + 6:.1f}" y="{top - 4}" class="label">called a timer</text>')
    for i, (label, detail, p, b) in enumerate(rows):
        y = top + 16 + i * row_h
        body.append(f'<text x="{left - 14}" y="{y + 4}" text-anchor="end" class="label">{escape(label)}</text>')
        body.append(f'<text x="{left - 14}" y="{y + 18}" text-anchor="end">{escape(detail)}</text>')
        if abs(b - p) > 0.005:
            body.append(f'<line x1="{xof(p):.1f}" y1="{y}" x2="{xof(b):.1f}" y2="{y}" class="grid" stroke-width="2"/>')
        body.append(f'<circle cx="{xof(p):.1f}" cy="{y}" r="5" class="dot context"/>')
        body.append(f'<circle cx="{xof(b):.1f}" cy="{y}" r="5" class="dot accent"/>')
        body.append(f'<text x="{xof(b) + 10:.1f}" y="{y + 4}" class="value">{b:.2f}</text>')
    return svg(W, H, "".join(body), "Dot plot: timing score of each IoT-23 C&C pair, plain versus beacon-hunter")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "simulation.svg").write_text(simulation_figure(), encoding="utf-8")
    data = ROOT / "eval" / "data"
    if any(data.glob("*.labeled")):
        (OUT / "iot23.svg").write_text(iot23_figure(data), encoding="utf-8")
    else:
        print("eval/data/ is empty; skipped the IoT-23 figure (see eval/README.md)")
    print(f"wrote figures to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
