"""A single self-contained HTML report that reads like a triage note.

It leads with the answer (how many pairs are worth a look), shows a beacon map
of every timer in the capture, then a card per finding:

  Worth a look           timers on one or two hosts, explained, with next steps
  Probably deployed      the same timer on many hosts, with allowlist lines
  No clear timer         everything else that was scored

Dark by default with a light/dark toggle. No external files: it can be
attached to a ticket as is. The small script adds hover readouts and the
theme toggle; the report reads fine without it.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from html import escape
from typing import Optional, Sequence

from .report import destination
from .scoring import ON_A_TIMER, Finding, Settings
from .timefmt import human_duration

FLEET = 3                          # timer on this many hosts = probably deployed software
MAX_CARDS = 10
MAX_OTHERS = 15
MAX_MAP_ROWS = 14

STRIP_W, STRIP_H = 760, 44
HIST_W, HIST_H, HIST_BINS, HIST_SPAN = 760, 150, 42, 3.5
HIST_TOP, HIST_AXIS = 18, 26       # room for the peak label above, axis labels below

TOKENS_DARK = """
  --page:#0d0d0d; --surface:#1a1a19; --raised:#222220; --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,0.10);
  --series:#3987e5; --series-wash:#184f95; --callout:#14273d; --context:#6f6e69;
  --serious:#ec835a; --good:#0ca30c;"""
TOKENS_LIGHT = """
  --page:#f9f9f7; --surface:#fcfcfb; --raised:#ffffff; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,0.10);
  --series:#2a78d6; --series-wash:#cde2fb; --callout:#eef4fc; --context:#b5b3ac;
  --serious:#ec835a; --good:#0ca30c;"""

CSS = f"""
:root, :root[data-theme="dark"] {{ color-scheme: dark; {TOKENS_DARK} }}
:root[data-theme="light"] {{ color-scheme: light; {TOKENS_LIGHT} }}

* {{ box-sizing: border-box; }}
html, body {{ margin: 0; }}
body {{ background: var(--page); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 920px; margin: 0 auto; padding: 36px 16px 64px; }}
.addr {{ font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 0.93em; white-space: nowrap; }}

header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
header .kicker {{ color: var(--muted); font-size: 13px; letter-spacing: .02em; }}
header h1 {{ font-size: 22px; font-weight: 600; margin: 2px 0 6px; }}
header .scope {{ color: var(--ink-2); font-size: 13px; overflow-wrap: anywhere; }}
.toggle {{ flex: none; background: var(--surface); color: var(--ink-2); border: 1px solid var(--ring);
  border-radius: 999px; padding: 6px 12px; font: inherit; font-size: 13px; cursor: pointer; }}
.toggle:hover {{ color: var(--ink); }}

.verdict {{ margin: 32px 0 8px; display: flex; gap: 20px; align-items: flex-start; }}
.hero {{ font-size: 64px; font-weight: 600; line-height: 1; }}
.verdict h2 {{ font-size: 20px; font-weight: 600; margin: 4px 0 6px; display: flex; align-items: center; gap: 8px; }}
.verdict p {{ margin: 0; color: var(--ink-2); max-width: 64ch; }}

.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 28px 0 0; }}
.tile {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; }}
.tile .label {{ color: var(--ink-2); font-size: 13px; }}
.tile .value {{ font-size: 26px; font-weight: 600; margin-top: 2px; }}

.how {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; margin: 16px 0 0; }}
.how-item {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 12px 14px; }}
.how-item svg {{ display: block; width: 100%; height: 28px; margin-bottom: 8px; }}
.how-item b {{ display: block; font-size: 13.5px; font-weight: 600; }}
.how-item span {{ color: var(--ink-2); font-size: 13px; }}

section > h2 {{ font-size: 17px; font-weight: 600; margin: 44px 0 4px; }}
section > .lede {{ color: var(--ink-2); margin: 0 0 16px; max-width: 72ch; }}

.map {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 10px 18px 14px; }}
.map-row {{ display: grid; grid-template-columns: 230px 1fr 140px; gap: 14px; align-items: center;
  padding: 8px 0; border-bottom: 1px solid var(--grid); color: inherit; text-decoration: none; }}
.map-row:last-of-type {{ border-bottom: 0; }}
a.map-row:hover .map-dst {{ text-decoration: underline; }}
.map-dst {{ font-size: 13.5px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.map-src {{ font-size: 12.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.map-row svg {{ display: block; width: 100%; height: 26px; }}
.map-meta {{ font-size: 12.5px; color: var(--ink-2); text-align: right; }}
.map-meta .tag {{ display: block; color: var(--muted); }}
.map-axis {{ display: grid; grid-template-columns: 230px 1fr 140px; gap: 14px; font-size: 11.5px; color: var(--muted); padding-top: 6px; }}
.map-axis div {{ display: flex; justify-content: space-between; }}

.card {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 20px 22px 18px; margin-bottom: 16px; scroll-margin-top: 16px; }}
.card-head {{ display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; align-items: baseline; }}
.card h3 {{ font-size: 16px; font-weight: 600; margin: 0; }}
.meter {{ display: inline-flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); font-variant-numeric: tabular-nums; }}
.meter .track {{ display: inline-block; width: 96px; height: 6px; border-radius: 3px; background: var(--series-wash); overflow: hidden; }}
.meter .fill {{ display: block; height: 100%; border-radius: 3px; background: var(--series); }}
.meaning {{ background: var(--callout); border-radius: 10px; padding: 12px 14px; margin: 14px 0 4px; }}
.meaning b {{ display: block; font-size: 12.5px; font-weight: 600; color: var(--ink-2); margin-bottom: 2px; letter-spacing: .02em; }}
.meaning p {{ margin: 0; }}
.card ul {{ margin: 12px 0 4px; padding-left: 20px; color: var(--ink-2); }}
.card li {{ margin: 2px 0; }}

.cycle {{ margin: 16px 0 0; }}
.cycle .steps {{ display: flex; gap: 2px; height: 34px; }}
.cycle .step {{ background: var(--series); color: #fff; border-radius: 4px; display: flex; align-items: center;
  justify-content: center; font-size: 12px; font-weight: 600; min-width: 34px; }}
.cycle .repeat {{ font-size: 13px; color: var(--ink-2); margin-top: 6px; }}

figure {{ margin: 18px 0 0; }}
figcaption {{ font-size: 13px; color: var(--ink-2); margin-bottom: 4px; }}
figcaption b {{ color: var(--ink); font-weight: 600; }}
svg.chart {{ display: block; width: 100%; height: auto; overflow: visible; }}
svg.chart text {{ font: 11px system-ui, -apple-system, "Segoe UI", sans-serif; fill: var(--muted); }}
svg.chart text.peak {{ fill: var(--ink-2); font-weight: 600; }}
.hit {{ fill: transparent; }}
.bar {{ fill: var(--series); }}
.bar-group:hover .bar, .bar-group:focus .bar {{ opacity: .75; }}
.bar-group:focus {{ outline: none; }}
.bar-group:focus-visible .bar {{ stroke: var(--ink); stroke-width: 1.5; }}

details {{ margin-top: 6px; font-size: 13px; color: var(--ink-2); }}
summary {{ cursor: pointer; width: max-content; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th {{ text-align: left; font-weight: 600; color: var(--ink-2); border-bottom: 1px solid var(--axis); padding: 6px 8px; }}
td {{ border-bottom: 1px solid var(--grid); padding: 6px 8px; font-variant-numeric: tabular-nums; vertical-align: top; }}
.table-wrap {{ overflow-x: auto; background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 4px 8px; }}

.next {{ margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--grid); }}
.next h4 {{ font-size: 13px; font-weight: 600; margin: 0 0 4px; color: var(--ink-2); }}
.next ol {{ margin: 0; padding-left: 20px; color: var(--ink-2); }}

pre.allow {{ background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 12px 14px;
  overflow-x: auto; font: 13px/1.6 ui-monospace, "Cascadia Mono", Consolas, monospace; }}
.caution {{ color: var(--ink-2); font-size: 13px; }}

footer {{ margin-top: 56px; padding-top: 16px; border-top: 1px solid var(--grid); color: var(--ink-2); font-size: 13px; }}
footer dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 8px 0 0; }}
footer dt {{ color: var(--muted); }}
footer dd {{ margin: 0; }}

#tip {{ position: fixed; pointer-events: none; z-index: 10; background: var(--raised); color: var(--ink);
  border: 1px solid var(--ring); border-radius: 8px; padding: 6px 10px; font-size: 13px;
  box-shadow: 0 4px 16px rgba(0,0,0,.25); display: none; max-width: 280px; }}
#tip strong {{ display: block; font-weight: 600; }}
#tip span {{ color: var(--ink-2); }}
@media (max-width: 640px) {{
  .hero {{ font-size: 48px; }} .verdict {{ gap: 14px; }}
  .map-row, .map-axis {{ grid-template-columns: 1fr; gap: 4px; }}
  .map-meta {{ text-align: left; }} .map-axis > :first-child, .map-axis > :last-child {{ display: none; }}
}}
"""

# Hover readouts and the theme toggle. Text goes in with textContent only;
# nothing from the log is ever parsed as HTML.
SCRIPT = """
(() => {
  const root = document.documentElement, btn = document.getElementById('theme');
  const label = () => { btn.textContent = root.dataset.theme === 'light' ? 'Dark theme' : 'Light theme'; };
  try { const saved = localStorage.getItem('beacon-hunter-theme'); if (saved) root.dataset.theme = saved; } catch (e) {}
  label();
  btn.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('beacon-hunter-theme', root.dataset.theme); } catch (e) {}
    label();
  });

  const tip = document.getElementById('tip');
  const show = (e, strong, rest) => {
    tip.replaceChildren();
    const s = document.createElement('strong'); s.textContent = strong;
    const r = document.createElement('span'); r.textContent = rest;
    tip.append(s, r); tip.style.display = 'block';
    const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + 'px'; tip.style.top = (e.clientY + 14) + 'px';
  };
  const hide = () => { tip.style.display = 'none'; };
  const fmt = s => new Date(s * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const dur = s => { s = Math.round(s); if (s < 60) return s + 's';
    const m = Math.floor(s / 60), r = s % 60; if (m < 60) return m + 'm' + String(r).padStart(2, '0') + 's';
    return Math.floor(m / 60) + 'h' + String(m % 60).padStart(2, '0') + 'm'; };

  document.querySelectorAll('.bar-group').forEach(g => {
    g.addEventListener('pointermove', e => show(e, g.dataset.value, g.dataset.label));
    g.addEventListener('pointerleave', hide);
    g.addEventListener('focus', () => { const b = g.getBoundingClientRect();
      show({ clientX: b.left, clientY: b.bottom }, g.dataset.value, g.dataset.label); });
    g.addEventListener('blur', hide);
  });

  document.querySelectorAll('svg.strip').forEach(svg => {
    const ts = JSON.parse(document.getElementById(svg.dataset.events).textContent);
    const start = +svg.dataset.start, end = +svg.dataset.end;
    const cross = svg.querySelector('.cross');
    svg.addEventListener('pointermove', e => {
      const box = svg.getBoundingClientRect();
      const t = start + (e.clientX - box.left) / box.width * (end - start);
      let lo = 0, hi = ts.length - 1;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (start + ts[mid] < t) lo = mid + 1; else hi = mid; }
      if (lo > 0 && Math.abs(start + ts[lo - 1] - t) < Math.abs(start + ts[lo] - t)) lo--;
      const at = start + ts[lo];
      const x = (at - start) / (end - start) * +svg.dataset.width;
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.style.display = 'block';
      const gap = lo > 0 ? dur(ts[lo] - ts[lo - 1]) + ' after the previous one' : 'first connection';
      show(e, fmt(at), 'connection ' + (lo + 1) + ' of ' + ts.length + ', ' + gap);
    });
    svg.addEventListener('pointerleave', () => { cross.style.display = 'none'; hide(); });
  });
})();
"""

ICON_ATTENTION = ('<svg width="16" height="16" viewBox="0 0 14 14" aria-hidden="true">'
                  '<circle cx="7" cy="7" r="6" fill="var(--serious)"/>'
                  '<rect x="6.2" y="3.3" width="1.6" height="4.6" rx=".8" fill="#fff"/>'
                  '<circle cx="7" cy="10.2" r=".95" fill="#fff"/></svg>')
ICON_CLEAR = ('<svg width="16" height="16" viewBox="0 0 14 14" aria-hidden="true">'
              '<circle cx="7" cy="7" r="6" fill="var(--good)"/>'
              '<path d="M4.3 7.2l1.9 1.9 3.6-3.8" stroke="#fff" stroke-width="1.6" fill="none" '
              'stroke-linecap="round" stroke-linejoin="round"/></svg>')

# Explicit list on purpose: Python's is_private also covers documentation and
# benchmarking ranges, which should be treated as somebody else's network here.
INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def _is_internal(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL if net.version == ip.version)


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") + " UTC"


def _compact(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}K"
    return f"{n:,}"


def _addr(text: str) -> str:
    return f'<span class="addr">{escape(text)}</span>'


def _service(f: Finding) -> str:
    return f.proto if f.dport is None else f"{f.dport}/{f.proto}"


def _anchor(f: Finding) -> str:
    return "f-" + "".join(ch if ch.isalnum() else "-" for ch in f"{f.src}-{f.dst}-{f.dport}-{f.proto}")


def _meter(score: float) -> str:
    return (f'<span class="meter" title="0 = random, 1 = clockwork">score {score:.2f}'
            f'<span class="track"><span class="fill" style="width:{score * 100:.0f}%"></span></span></span>')


def _rounded_column(x: float, y: float, w: float, base: float) -> str:
    """A column with a 4px rounded top and a square foot on the baseline."""
    r = min(4.0, w / 2, base - y)
    return (f'M{x:.1f},{base:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}'
            f'H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{base:.1f}Z')


def _mini_ticks(times: Sequence[float], start: float, end: float, color: str, height: int = 26) -> str:
    """A thin strip of ticks, stretched to its box; strokes stay 1.5px at any width."""
    span = max(end - start, 1e-9)
    lines = "".join(
        f'<line x1="{(t - start) / span * 1000:.1f}" y1="3" x2="{(t - start) / span * 1000:.1f}" y2="{height - 3}"/>'
        for t in times)
    return (f'<svg viewBox="0 0 1000 {height}" preserveAspectRatio="none" aria-hidden="true">'
            f'<line x1="0" y1="{height - 1}" x2="1000" y2="{height - 1}" stroke="var(--axis)" vector-effect="non-scaling-stroke"/>'
            f'<g stroke="{color}" stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linecap="round">{lines}</g></svg>')


# --------------------------------------------------------------------- charts

def heartbeat_strip(f: Finding, uid: str) -> str:
    span = max(f.capture_end - f.capture_start, 1e-9)
    base = STRIP_H - 16
    ticks = "".join(
        f'<line x1="{(ts - f.capture_start) / span * STRIP_W:.1f}" y1="6" '
        f'x2="{(ts - f.capture_start) / span * STRIP_W:.1f}" y2="{base}"/>'
        for ts in f.timestamps
    )
    events = json.dumps([round(ts - f.capture_start, 1) for ts in f.timestamps])
    return f"""
<figure>
  <figcaption><b>Every connection across the capture.</b> One line per connection; evenly spaced lines mean a timer.</figcaption>
  <svg class="chart strip" viewBox="0 0 {STRIP_W} {STRIP_H}" data-events="ev-{uid}"
       data-start="{f.capture_start:.3f}" data-end="{f.capture_end:.3f}" data-width="{STRIP_W}"
       role="img" aria-label="{len(f.timestamps)} connections between {escape(_utc(f.capture_start))} and {escape(_utc(f.capture_end))}">
    <line x1="0" y1="{base}" x2="{STRIP_W}" y2="{base}" stroke="var(--axis)" stroke-width="1"/>
    <g stroke="var(--series)" stroke-width="1">{ticks}</g>
    <line class="cross" y1="2" y2="{base}" stroke="var(--ink)" stroke-width="1" style="display:none"/>
    <text x="0" y="{STRIP_H - 2}">{escape(_utc(f.capture_start))}</text>
    <text x="{STRIP_W}" y="{STRIP_H - 2}" text-anchor="end">{escape(_utc(f.capture_end))}</text>
  </svg>
  <script type="application/json" id="ev-{uid}">{events}</script>
  {_strip_table(f)}
</figure>"""


def zoom_strip(f: Finding) -> str:
    """Busy timers draw as a solid bar at full width; show a run of consecutive connections up close."""
    ts = f.timestamps
    if len(ts) <= 60:
        return ""
    n = 2 * len(f.cycle) + 1 if f.cycle else 10
    start = len(ts) // 2
    if f.cycle:
        longest = max(f.cycle)
        for i in range(start, min(len(ts) - n, start + 10 * len(f.cycle))):
            if abs((ts[i] - ts[i - 1]) - longest) <= 0.25 * longest:
                start = i
                break
    window = ts[start:start + n]
    span = max(window[-1] - window[0], 1e-9)
    W, H, pad = STRIP_W, 74, 14
    X = lambda t: pad + (t - window[0]) / span * (W - 2 * pad)  # noqa: E731
    y = 34
    parts = [f'<line x1="{pad}" y1="{y + 12}" x2="{W - pad}" y2="{y + 12}" stroke="var(--axis)"/>']
    parts += [f'<line x1="{X(t):.1f}" y1="{y - 12}" x2="{X(t):.1f}" y2="{y + 12}" stroke="var(--series)" '
              f'stroke-width="2" stroke-linecap="round"/>' for t in window]
    for a, b in zip(window, window[1:]):
        gap = b - a
        label = f"{gap:.1f}s" if gap < 60 else human_duration(gap)
        parts.append(f'<text x="{(X(a) + X(b)) / 2:.1f}" y="{y + 30}" text-anchor="middle">{escape(label)}</text>')
    if f.cycle:
        k = len(f.cycle)
        for j in range(0, n - 1, k):
            x1, x2 = X(window[j]), X(window[j + k])
            parts.append(f'<path d="M{x1:.1f},{y - 15} V{y - 20} H{x2:.1f} V{y - 15}" fill="none" stroke="var(--muted)"/>'
                         f'<text class="peak" x="{(x1 + x2) / 2:.1f}" y="{y - 25}" text-anchor="middle">'
                         f'{escape(human_duration(window[j + k] - window[j]))}</text>')
    when = _utc(window[0])
    return f"""
<figure>
  <figcaption><b>Zoomed in:</b> {n} connections in a row from {escape(when)}, with the wait before each one.</figcaption>
  <svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="{n} consecutive connections and the waits between them">
    {''.join(parts)}
  </svg>
</figure>"""


def _strip_table(f: Finding) -> str:
    slices = max(f.slices, 1)
    width = max(f.capture_end - f.capture_start, 1e-9) / slices
    counts = [0] * slices
    for ts in f.timestamps:
        counts[min(int((ts - f.capture_start) / width), slices - 1)] += 1
    rows = "".join(
        f"<tr><td>{escape(_utc(f.capture_start + i * width))}</td><td>{c}</td></tr>"
        for i, c in enumerate(counts)
    )
    return (f'<details><summary>Table view: connections per time slice</summary>'
            f'<table><thead><tr><th>Slice starting</th><th>Connections</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></details>')


def gap_histogram(f: Finding) -> str:
    gaps = [b - a for a, b in zip(f.timestamps, f.timestamps[1:])]
    top = 1.4 * max(f.cycle) if f.cycle else HIST_SPAN * f.period
    bin_w = top / HIST_BINS
    counts = [0] * HIST_BINS
    for gap in gaps:
        counts[min(int(gap / bin_w), HIST_BINS - 1)] += 1
    tallest = max(counts) or 1
    base = HIST_H - HIST_AXIS
    plot_h = base - HIST_TOP
    slot = HIST_W / HIST_BINS
    bar_w = min(24.0, slot - 2)      # 2px surface gap between neighbours

    groups, peak_label = [], ""
    for i, c in enumerate(counts):
        lo = i * bin_w
        if i == HIST_BINS - 1:
            label = f"waits of {human_duration(lo)} or more"
        else:
            label = f"waits from {human_duration(lo)} to {human_duration(lo + bin_w)}"
        value = f"{c} connection{'s' if c != 1 else ''}"
        x = i * slot + (slot - bar_w) / 2
        shape = ""
        if c:
            y = base - max(2.0, c / tallest * plot_h)
            shape = f'<path class="bar" d="{_rounded_column(x, y, bar_w, base)}"/>'
            if c == tallest and not peak_label:
                peak_label = f'<text class="peak" x="{x + bar_w / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle">{c}</text>'
        groups.append(
            f'<g class="bar-group" tabindex="0" data-value="{escape(value)}" data-label="{escape(label)}">'
            f'<rect class="hit" x="{i * slot:.1f}" y="{HIST_TOP - 10}" width="{slot:.1f}" height="{plot_h + 10}"/>'
            f'{shape}<title>{escape(value)}, {escape(label)}</title></g>'
        )

    marks = []
    if f.cycle:
        # Mark the cycle's own steps; skip a label that would sit on top of the previous one.
        last_x = -100.0
        for step in sorted(f.cycle):
            x = step / top * HIST_W
            label = f"{step:.1f}s" if step < 60 else human_duration(step)
            marks.append(f'<line x1="{x:.1f}" y1="{base}" x2="{x:.1f}" y2="{base + 5}" stroke="var(--axis)"/>')
            if x - last_x > 34:
                marks.append(f'<text x="{x:.1f}" y="{base + 18}" text-anchor="middle">{escape(label)}</text>')
                last_x = x
    else:
        for k in (1, 2, 3):
            x = k / HIST_SPAN * HIST_W
            marks.append(f'<line x1="{x:.1f}" y1="{base}" x2="{x:.1f}" y2="{base + 5}" stroke="var(--axis)"/>'
                         f'<text x="{x:.1f}" y="{base + 18}" text-anchor="middle">'
                         f'{k}× · {escape(human_duration(k * f.period))}</text>')

    rows = "".join(
        f"<tr><td>{escape(human_duration(i * bin_w))}"
        f"{' +' if i == HIST_BINS - 1 else ' to ' + escape(human_duration((i + 1) * bin_w))}</td><td>{c}</td></tr>"
        for i, c in enumerate(counts) if c
    )
    if f.cycle:
        caption = ("<b>How long it waited between connections.</b> A few tall bars that repeat in the same order: "
                   "the steps of the cycle above.")
    elif f.missed:
        caption = ("<b>How long it waited between connections.</b> The tall bar is the timer; the small bars at 2× "
                   "and 3× are missed check-ins.")
    else:
        caption = ("<b>How long it waited between connections.</b> One tall bar means the same wait every time; "
                   "bars spread out mean irregular traffic.")
    return f"""
<figure>
  <figcaption>{caption}</figcaption>
  <svg class="chart" viewBox="0 0 {HIST_W} {HIST_H}" role="img"
       aria-label="histogram of {len(gaps)} waits between connections">
    <line x1="0" y1="{base}" x2="{HIST_W}" y2="{base}" stroke="var(--axis)" stroke-width="1"/>
    {''.join(marks)}
    {''.join(groups)}
    {peak_label}
  </svg>
  <details><summary>Table view: wait counts</summary>
    <table><thead><tr><th>Wait</th><th>Connections</th></tr></thead><tbody>{rows}</tbody></table>
  </details>
</figure>"""


def cycle_diagram(f: Finding) -> str:
    if not f.cycle:
        return ""
    total = sum(f.cycle)
    steps = "".join(
        f'<div class="step" style="flex:{w / total:.4f}" title="wait {escape(human_duration(w))}">'
        f'{escape(f"{w:.1f}s" if w < 60 else human_duration(w))}</div>'
        for w in f.cycle)
    return f"""
<div class="cycle" role="img" aria-label="repeating cycle of {len(f.cycle)} waits totalling {escape(human_duration(f.period))}">
  <div class="steps">{steps}</div>
  <div class="repeat">↻ the same {len(f.cycle)} waits, then it starts over: one loop every {escape(human_duration(f.period))}</div>
</div>"""


# ------------------------------------------------------------------- sections

def headline(f: Finding) -> str:
    rhythm = (f"in a {len(f.cycle)}-step cycle every {escape(human_duration(f.period))}" if f.cycle
              else f"every {escape(human_duration(f.period))}")
    return f"{_addr(f.src)} checks in with {_addr(f.dst)} on {escape(_service(f))} {rhythm}"


def _dead(f: Finding) -> bool:
    return f.unanswered is not None and f.unanswered >= 0.9


def what_it_means(f: Finding) -> str:
    """The finding as a person would explain it, from the same numbers as the reasons."""
    every = human_duration(f.period)
    if f.cycle:
        steps = ", ".join(f"{w:.0f}s" for w in f.cycle)
        text = (f"Instead of waiting the same time between connections, it repeats the same {len(f.cycle)} waits "
                f"({steps}) over and over, finishing a loop every {every}. Malware retry loops look like this; "
                f"ordinary software rarely does.")
    else:
        when = "around the clock" if f.persistence >= 0.9 else f"in {f.active_slices} of {f.slices} slices of the capture"
        text = f"This machine contacts {f.dst} like clockwork: every {every}, {when}"
        if (f.same_size_share and f.same_size_share >= 0.5 and f.median_bytes is not None
                and 0 < f.median_bytes < 4096):
            text += ", sending the same small message each time"
        text += "."
    if f.missed:
        text += (f" About {f.missed * 100:.0f}% of the expected check-ins never arrived, which is what a machine "
                 f"that sleeps or goes offline looks like, but the rest land right on the timer.")
    if _dead(f):
        text += (" The server never answers, but the attempts keep coming on schedule. That's typical of "
                 "malware whose command server has been taken down or sinkholed: it keeps calling anyway.")
    if f.process:
        text += f" The program making the connections is {f.process}."
    if f.service_hint:
        text += (f" {f.dport}/{f.proto} is normally {f.service_hint}, which runs on a timer by design, so this is "
                 f"probably fine if {f.dst} is a server you run or trust.")
    elif f.cycle or _dead(f):
        text += " Find out which program on the machine is doing it before anything else."
    else:
        text += (" Malware asks its operator for instructions exactly like this, but so do update checkers and "
                 "cloud agents. The job is to find out which program it is.")
    return f'<div class="meaning"><b>WHAT THIS MEANS</b><p>{escape(text)}</p></div>'


def next_steps(f: Finding) -> str:
    first = _utc(f.first_seen)
    allow_line = f.dst if f.dport is None else f"{f.dst}:{f.dport}"
    if _is_internal(f.dst):
        identify = (f"Identify {_addr(f.dst)} in your asset inventory or DHCP leases. "
                    f"Is it a server that should be offering {escape(_service(f))}?")
    else:
        identify = (f"Look up {_addr(f.dst)} in threat intel and passive DNS. Which name resolved to it? "
                    f"Check <span class=\"addr\">dns.log</span> from {_addr(f.src)} just before {escape(first)}.")
    if f.process:
        find_process = (f"Check {_addr(f.process)} on {_addr(f.src)}: is it where it should be, is it signed, and "
                        f"what started it? Sysmon event ID 1 has its command line and parent process.")
    else:
        find_process = (f"Find the process on {_addr(f.src)} making the connection: EDR, Sysmon event ID 3, or "
                        f"<span class=\"addr\">netstat -ano</span> at the next check-in (due every "
                        f"{escape(human_duration(f.period))}).")
    return f"""
<div class="next"><h4>Next steps</h4><ol>
  <li>{identify}</li>
  <li>{find_process}</li>
  <li>If it turns out to be legitimate software, add <span class="addr">{escape(allow_line)}</span> to your allowlist with a comment saying what it is.</li>
</ol></div>"""


def card(f: Finding, uid: str) -> str:
    reasons = "".join(f"<li>{escape(r)}</li>" for r in f.reasons)
    return f"""
<article class="card" id="{_anchor(f)}">
  <div class="card-head"><h3>{headline(f)}</h3>{_meter(f.score)}</div>
  {what_it_means(f)}
  {cycle_diagram(f)}
  <ul>{reasons}</ul>
  {heartbeat_strip(f, uid)}
  {zoom_strip(f)}
  {gap_histogram(f)}
  {next_steps(f)}
</article>"""


def how_to_read(start: float, end: float) -> str:
    timer = [start + (end - start) * (i + 0.5) / 12 for i in range(12)]
    rand = [start + (end - start) * x for x in (0.04, 0.07, 0.09, 0.3, 0.33, 0.52, 0.55, 0.56, 0.81, 0.9)]
    meter = ('<svg viewBox="0 0 200 28" aria-hidden="true"><rect x="0" y="15" width="200" height="6" rx="3" fill="var(--series-wash)"/>'
             '<rect x="0" y="15" width="186" height="6" rx="3" fill="var(--series)"/>'
             '<text x="0" y="10" font-size="10" fill="var(--muted)">0 random</text>'
             '<text x="200" y="10" font-size="10" fill="var(--muted)" text-anchor="end">1 clockwork</text></svg>')
    return f"""
<div class="how">
  <div class="how-item">{_mini_ticks(rand, start, end, "var(--context)", 28)}<b>Each line is one connection</b><span>between the same two machines, across the whole capture.</span></div>
  <div class="how-item">{_mini_ticks(timer, start, end, "var(--series)", 28)}<b>Evenly spaced lines are a timer</b><span>a program checking in on a schedule. That's what malware beacons do.</span></div>
  <div class="how-item">{meter}<b>The score runs from 0 to 1</b><span>how much a pair behaves like a timer. It's a lead, not a verdict.</span></div>
</div>"""


def beacon_map(look: Sequence[Finding], known: Sequence[Finding], fleet: Sequence[Finding],
               others: Sequence[Finding]) -> str:
    rows = []
    for f in look[:MAX_CARDS]:
        rows.append((f"#{_anchor(f)}", f"{f.dst}:{f.dport}" if f.dport is not None else f.dst,
                     f"from {f.src}", f, "var(--series)", "worth a look"))
    for f in known:
        rows.append((None, f"{f.dst}:{f.dport}" if f.dport is not None else f.dst,
                     f"from {f.src}", f, "var(--context)", f.service_hint or "known service"))
    seen = set()
    for f in fleet:
        key = (f.dst, f.dport, f.proto)
        if key in seen:
            continue
        seen.add(key)
        rows.append((None, f"{f.dst}:{f.dport}" if f.dport is not None else f.dst,
                     f"from {f.timer_hosts} hosts (showing {f.src})", f, "var(--context)", "deployed software"))
    for f in others[:2]:
        rows.append((None, f"{f.dst}:{f.dport}" if f.dport is not None else f.dst,
                     f"from {f.src}", f, "var(--context)", "irregular"))
    rows = rows[:MAX_MAP_ROWS]
    if not rows:
        return ""
    start, end = rows[0][3].capture_start, rows[0][3].capture_end
    html_rows = []
    for href, dst, src, f, color, tag in rows:
        tag_name = "a" if href else "div"
        href_attr = f' href="{href}"' if href else ""
        html_rows.append(
            f'<{tag_name} class="map-row"{href_attr}>'
            f'<div><div class="map-dst addr">{escape(dst)}</div><div class="map-src">{escape(src)}</div></div>'
            f'{_mini_ticks(f.timestamps, start, end, color)}'
            f'<div class="map-meta">every {escape(human_duration(f.period))}<span class="tag">{escape(tag)}</span></div>'
            f'</{tag_name}>')
    return f"""
<section>
  <h2>Beacon map</h2>
  <p class="lede">Every timer in the capture, one row per conversation, all on the same timeline. Blue rows are worth a look. Gray rows are known services, fleet-wide agents, and two irregular conversations for contrast: notice the gaps.</p>
  <div class="map">
    {''.join(html_rows)}
    <div class="map-axis"><span></span><div><span>{escape(_utc(start))}</span><span>{escape(_utc(end))}</span></div><span></span></div>
  </div>
</section>"""


def known_section(known: Sequence[Finding]) -> str:
    rows, lines = [], []
    for f in known:
        entry = f.dst if f.dport is None else f"{f.dst}:{f.dport}"
        rows.append(f"<tr><td>{_addr(entry)}/{escape(f.proto)}</td><td>{escape(f.service_hint or '')}</td>"
                    f"<td>{_addr(f.src)}</td><td>{escape(human_duration(f.period))}</td><td>{f.connections:,}</td></tr>")
        lines.append(f"{entry:<24} # {f.service_hint}, every {human_duration(f.period)}")
    return f"""
<section>
  <h2>Known services on a timer</h2>
  <p class="lede">Ports that normally carry services which run on a timer by design. Usually fine, but malware tunnels over DNS and NTP precisely because they look boring, so confirm each destination is one you expect.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Destination</th><th>Usually</th><th>Source</th><th>Every</th><th>Connections</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table></div>
  <p class="caution">Suggested allowlist lines, once confirmed:</p>
  <pre class="allow">{escape(chr(10).join(lines))}</pre>
</section>"""


def fleet_section(fleet: Sequence[Finding]) -> str:
    by_dest: dict[tuple, list[Finding]] = {}
    for f in fleet:
        by_dest.setdefault((f.dst, f.dport, f.proto), []).append(f)
    rows, lines = [], []
    for (dst, dport, proto), members in sorted(by_dest.items(), key=lambda kv: -len(kv[1])):
        period = sorted(m.period for m in members)[len(members) // 2]
        entry = dst if dport is None else f"{dst}:{dport}"
        rows.append(f"<tr><td>{_addr(entry)}/{escape(proto)}</td><td>{len(members)}</td>"
                    f"<td>{escape(human_duration(period))}</td></tr>")
        lines.append(f"{entry:<24} # {len(members)} hosts, every {human_duration(period)}")
    return f"""
<section>
  <h2>Probably deployed software</h2>
  <p class="lede">The same timer on {FLEET} or more hosts is usually an agent you rolled out: SIEM or EDR heartbeats, update checks, time sync.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Destination</th><th>Hosts on the timer</th><th>Every</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table></div>
  <p class="caution">Suggested allowlist lines. Check each one before adding it: malware spread across many hosts looks fleet-wide too.</p>
  <pre class="allow">{escape(chr(10).join(lines))}</pre>
</section>"""


def others_section(others: Sequence[Finding]) -> str:
    rows = "".join(
        f"<tr><td>{_addr(f.src)}</td><td>{_addr(destination(f))}</td><td>{f.connections:,}</td>"
        f"<td>{escape(human_duration(f.period))}</td><td>{f.timing:.2f}</td><td>{_meter(f.score)}</td></tr>"
        for f in others[:MAX_OTHERS]
    )
    more = len(others) - MAX_OTHERS
    tail = f'<p class="caution">{more} more not shown; use <span class="addr">--json</span> for all of them.</p>' if more > 0 else ""
    return f"""
<section>
  <h2>No clear timer</h2>
  <p class="lede">Scored because they talk often, but the waits are irregular: people browsing, chatty apps, DNS. Highest scores first.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Source</th><th>Destination</th><th>Connections</th><th>Typical wait</th><th>Timing</th><th>Score</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
  {tail}
</section>"""


def verdict(look: Sequence[Finding], known: Sequence[Finding]) -> str:
    if not look:
        title = "No unexplained timers" if known else "No single-host timers found"
        detail = (f"The only single-host timers are {len(known)} known services (NTP, DNS and the like), listed below."
                  if known else "Nothing in this capture checks in on a timer from just one or two hosts. "
                                "Fleet-wide timers and irregular traffic are listed below.")
        return f"""
<div class="verdict"><div class="hero">0</div><div>
  <h2>{ICON_CLEAR} {title}</h2>
  <p>{escape(detail)}</p>
</div></div>"""
    top = look[0]
    plural = "pair" if len(look) == 1 else "pairs"
    rhythm = (f"repeating a {len(top.cycle)}-step cycle every {escape(human_duration(top.period))}" if top.cycle
              else f"every {escape(human_duration(top.period))}")
    lead = f"Strongest: {_addr(top.src)} contacts {_addr(top.dst)} on {escape(_service(top))} {rhythm}"
    if _dead(top):
        lead += ", and the server never answers"
    elif top.same_size_share and top.same_size_share >= 0.5 and top.median_bytes:
        lead += f", sending exactly {top.median_bytes:.0f} bytes {top.same_size_share * 100:.0f}% of the time"
    lead += (". No other host does this." if top.timer_hosts <= 1 else ".")
    if known:
        lead += f" Plus {len(known)} known service{'s' if len(known) != 1 else ''} on a timer, listed separately."
    return f"""
<div class="verdict"><div class="hero">{len(look)}</div><div>
  <h2>{ICON_ATTENTION} {plural} worth a look</h2>
  <p>{lead}</p>
</div></div>"""


def tiles(rows: int, scored: int, timers: int, fleet_dests: int) -> str:
    items = [("Connections read", _compact(rows)), ("Pairs scored", f"{scored:,}"),
             ("On a timer", f"{timers:,}"), ("Fleet-wide timers", f"{fleet_dests:,}")]
    return '<div class="tiles">' + "".join(
        f'<div class="tile"><div class="label">{label}</div><div class="value">{value}</div></div>'
        for label, value in items) + "</div>"


def render(findings: Sequence[Finding], sources: Sequence[str], rows: int, skipped: int,
           settings: Optional[Settings] = None) -> str:
    settings = settings or Settings()
    timers = [f for f in findings if f.timing >= ON_A_TIMER]
    # Single-host timers split in two: unexplained ones get full cards, known timer
    # services (NTP, DNS, agents) get a compact table.
    single = [f for f in timers if f.timer_hosts < FLEET]
    look = sorted((f for f in single if not f.service_hint), key=lambda f: -f.score)
    known = sorted((f for f in single if f.service_hint), key=lambda f: -f.score)
    fleet = [f for f in timers if f.timer_hosts >= FLEET]
    others = [f for f in findings if f.timing < ON_A_TIMER]
    fleet_dests = len({(f.dst, f.dport, f.proto) for f in fleet})

    if findings:
        start, end = findings[0].capture_start, findings[0].capture_end
        window = (f"{escape(_utc(start))} to {escape(_utc(end))} "
                  f"({escape(human_duration(end - start))})")
    else:
        start, end = 0.0, 1.0
        window = "no pairs had enough connections to score"

    cards = "".join(card(f, str(n)) for n, f in enumerate(look[:MAX_CARDS]))
    look_section = ""
    if look:
        extra = len(look) - MAX_CARDS
        more = f'<p class="caution">{extra} more single-host timers not shown; use <span class="addr">--json</span>.</p>' if extra > 0 else ""
        look_section = f"""
<section>
  <h2>Worth a look</h2>
  <p class="lede">Timers on one or two hosts. Most will turn out to be legitimate software nobody has allowlisted yet; the point is to know which.</p>
  {cards}{more}
</section>"""

    fold = "on" if settings.fold else "off"
    cycles = "on" if settings.cycles else "off"
    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beacon hunt report</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <header>
    <div>
      <div class="kicker">beacon-hunter report</div>
      <h1>Beacon hunt</h1>
      <div class="scope">{window}<br>{escape(', '.join(sources))}</div>
    </div>
    <button class="toggle" id="theme" type="button">Light theme</button>
  </header>
  {verdict(look, known)}
  {tiles(rows, len(findings), len(timers), fleet_dests)}
  {how_to_read(start, end)}
  {beacon_map(look, known, fleet, others)}
  {look_section}
  {known_section(known) if known else ''}
  {fleet_section(fleet) if fleet else ''}
  {others_section(others) if others else ''}
  <footer>
    Scores rank how much a pair behaves like a timer. They are leads, not verdicts.
    <dl>
      <dt>Connections</dt><dd>{rows:,} read, {skipped:,} skipped as malformed</dd>
      <dt>Scored when</dt><dd>{settings.min_events}+ connections; connections under {settings.merge_window:g}s apart count as one</dd>
      <dt>Persistence</dt><dd>capture split into {settings.slices} slices</dd>
      <dt>Missed check-ins</dt><dd>folding {fold}</dd>
      <dt>Repeating cycles</dt><dd>detection {cycles}</dd>
      <dt>Allowlist</dt><dd>{len(settings.allow)} entries</dd>
    </dl>
  </footer>
</main>
<div id="tip" role="status"></div>
<script>{SCRIPT}</script>
</body>
</html>
"""
