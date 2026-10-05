"""A single self-contained HTML file: one card per finding.

Each card has a heartbeat strip (one tick per check-in across the whole
capture) and a histogram of the gaps between check-ins, marked at 1x, 2x and
3x the detected period. A timer is obvious at a glance in both: evenly spaced
ticks, and gaps piled up on the period marks. No JavaScript, no external files,
so it can be attached to a ticket as is.
"""

from __future__ import annotations

from html import escape
from typing import Sequence

from .report import destination
from .scoring import Finding
from .timefmt import human_duration, iso

STRIP_W, STRIP_H = 720, 34
HIST_W, HIST_H, HIST_BINS, HIST_SPAN = 720, 90, 64, 4.0

CSS = """
:root { --bg:#f7f7f5; --card:#fff; --ink:#1d2329; --muted:#5f6b76; --line:#d9dde1;
        --tick:#1f5f99; --hot:#b42318; --warm:#b54708; --cool:#5f6b76; --bar:#7a9cc6; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#14181c; --card:#1c2227; --ink:#e6e9ec; --muted:#9aa5b1; --line:#2e363d;
          --tick:#7cb3e8; --hot:#f97066; --warm:#fdb022; --cool:#9aa5b1; --bar:#4f79a8; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:800px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; }
.meta { color:var(--muted); font-size:13px; margin-bottom:24px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px;
        padding:16px 18px; margin-bottom:16px; }
.head { display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }
.score { font:600 20px/1 ui-monospace, Consolas, monospace; }
.hot { color:var(--hot); } .warm { color:var(--warm); } .cool { color:var(--cool); }
.pair { font-family:ui-monospace, Consolas, monospace; font-size:14px; word-break:break-all; }
ul { margin:10px 0 12px; padding-left:20px; }
.parts { color:var(--muted); font-size:13px; font-family:ui-monospace, Consolas, monospace; }
svg { display:block; width:100%; height:auto; margin-top:8px; }
.label { font-size:11px; fill:var(--muted); font-family:system-ui, sans-serif; }
footer { color:var(--muted); font-size:12px; margin-top:32px; }
"""


def _heat(score: float) -> str:
    return "hot" if score >= 0.85 else "warm" if score >= 0.7 else "cool"


def heartbeat_strip(f: Finding) -> str:
    span = max(f.capture_end - f.capture_start, 1e-9)
    ticks = []
    for ts in f.timestamps:
        x = (ts - f.capture_start) / span * STRIP_W
        ticks.append(f'<line x1="{x:.1f}" y1="4" x2="{x:.1f}" y2="{STRIP_H - 12}"/>')
    return (
        f'<svg viewBox="0 0 {STRIP_W} {STRIP_H}" role="img" '
        f'aria-label="check-ins across the capture">'
        f'<rect x="0" y="0" width="{STRIP_W}" height="{STRIP_H - 8}" fill="none" stroke="var(--line)"/>'
        f'<g stroke="var(--tick)" stroke-width="1" opacity="0.8">{"".join(ticks)}</g>'
        f'<text class="label" x="0" y="{STRIP_H}">{escape(iso(f.capture_start))}</text>'
        f'<text class="label" x="{STRIP_W}" y="{STRIP_H}" text-anchor="end">{escape(iso(f.capture_end))}</text>'
        f"</svg>"
    )


def gap_histogram(f: Finding) -> str:
    gaps = [b - a for a, b in zip(f.timestamps, f.timestamps[1:])]
    top = HIST_SPAN * f.period
    counts = [0] * HIST_BINS
    for gap in gaps:
        counts[min(int(gap / top * HIST_BINS), HIST_BINS - 1)] += 1
    tallest = max(counts) or 1
    plot_h = HIST_H - 18
    bar_w = HIST_W / HIST_BINS
    bars = []
    for i, c in enumerate(counts):
        if c:
            h = max(1.0, c / tallest * plot_h)
            bars.append(f'<rect x="{i * bar_w + 0.5:.1f}" y="{plot_h - h:.1f}" '
                        f'width="{bar_w - 1:.1f}" height="{h:.1f}"/>')
    marks = []
    for k in (1, 2, 3):
        x = k / HIST_SPAN * HIST_W
        marks.append(f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{plot_h}" '
                     f'stroke="var(--muted)" stroke-dasharray="3 3"/>'
                     f'<text class="label" x="{x:.1f}" y="{HIST_H - 4}" text-anchor="middle">'
                     f'{k}× {escape(human_duration(k * f.period))}</text>')
    return (
        f'<svg viewBox="0 0 {HIST_W} {HIST_H}" role="img" aria-label="histogram of gaps between check-ins">'
        f'<g fill="var(--bar)">{"".join(bars)}</g>{"".join(marks)}'
        f'<line x1="0" y1="{plot_h}" x2="{HIST_W}" y2="{plot_h}" stroke="var(--line)"/>'
        f'<text class="label" x="{HIST_W}" y="{HIST_H - 4}" text-anchor="end">≥{HIST_SPAN:.0f}×</text>'
        f"</svg>"
    )


def card(f: Finding) -> str:
    size = "-" if f.size is None else f"{f.size:.2f}"
    reasons = "".join(f"<li>{escape(r)}</li>" for r in f.reasons)
    return f"""
<section class="card">
  <div class="head">
    <span class="score {_heat(f.score)}">{f.score:.2f}</span>
    <span class="pair">{escape(f.src)} → {escape(destination(f))}</span>
  </div>
  <ul>{reasons}</ul>
  <div class="parts">timing {f.timing:.2f} · size {size} · persistence {f.persistence:.2f} · {f.connections} connections</div>
  {heartbeat_strip(f)}
  {gap_histogram(f)}
</section>"""


def render(findings: Sequence[Finding], sources: Sequence[str], rows: int, skipped: int) -> str:
    names = ", ".join(escape(s) for s in sources)
    body = "".join(card(f) for f in findings) or "<p>No pairs had enough check-ins to score.</p>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>beacon-hunter report</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <h1>beacon-hunter report</h1>
  <div class="meta">{names}<br>{rows} connections read, {skipped} skipped · {len(findings)} findings shown</div>
  {body}
  <footer>Scores rank how much a pair behaves like a timer; they are not verdicts. Read the reasons, check the destination, and allowlist what you have verified.</footer>
</main>
</body>
</html>
"""
