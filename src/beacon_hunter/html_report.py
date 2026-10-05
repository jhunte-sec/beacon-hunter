"""A single self-contained HTML report that reads like a triage note.

It leads with the answer (how many pairs are worth a look), then sorts every
finding the way an analyst would:

  Worth a look           timers on one or two hosts, with next steps
  Probably deployed      the same timer on many hosts, with allowlist lines
  No clear timer         everything else that was scored

Each "worth a look" card has a heartbeat strip (one tick per check-in across
the capture) and a histogram of the gaps between check-ins. Both have a table
view underneath. The file has no external dependencies, so it can be attached
to a ticket as is; the small script only adds hover readouts.
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

STRIP_W, STRIP_H = 760, 44
HIST_W, HIST_H, HIST_BINS, HIST_SPAN = 760, 150, 42, 3.5
HIST_TOP, HIST_AXIS = 18, 26       # room for the peak label above, axis labels below

CSS = """
.bh { color-scheme: light;
  --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,0.10);
  --series:#2a78d6; --series-wash:#cde2fb; --serious:#ec835a; --good:#0ca30c; --good-text:#006300; }
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .bh { color-scheme: dark;
    --page:#0d0d0d; --surface:#1a1a19; --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,0.10);
    --series:#3987e5; --series-wash:#184f95; --good-text:#0ca30c; }
}
:root[data-theme="dark"] .bh { color-scheme: dark;
  --page:#0d0d0d; --surface:#1a1a19; --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,0.10);
  --series:#3987e5; --series-wash:#184f95; --good-text:#0ca30c; }

* { box-sizing: border-box; }
html, body { margin: 0; }
body.bh { background: var(--page); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 880px; margin: 0 auto; padding: 40px 16px 64px; }
.addr { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 0.93em; white-space: nowrap; }

header .kicker { color: var(--muted); font-size: 13px; letter-spacing: .02em; }
header h1 { font-size: 22px; font-weight: 600; margin: 2px 0 6px; }
header .scope { color: var(--ink-2); font-size: 13px; overflow-wrap: anywhere; }

.verdict { margin: 32px 0 8px; display: flex; gap: 20px; align-items: flex-start; }
.hero { font-size: 64px; font-weight: 600; line-height: 1; }
.verdict h2 { font-size: 20px; font-weight: 600; margin: 4px 0 6px; }
.verdict p { margin: 0; color: var(--ink-2); max-width: 62ch; }

.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 28px 0 40px; }
.tile { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; }
.tile .label { color: var(--ink-2); font-size: 13px; }
.tile .value { font-size: 26px; font-weight: 600; margin-top: 2px; }

section > h2 { font-size: 17px; font-weight: 600; margin: 44px 0 4px; }
section > .lede { color: var(--ink-2); margin: 0 0 16px; max-width: 70ch; }

.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 12px; padding: 20px 22px 18px; margin-bottom: 16px; }
.card-head { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; align-items: baseline; }
.card h3 { font-size: 16px; font-weight: 600; margin: 0; }
.status { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--ink-2); }
.status svg { flex: none; }
.meter { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); font-variant-numeric: tabular-nums; }
.meter .track { display: inline-block; width: 96px; height: 6px; border-radius: 3px; background: var(--series-wash); overflow: hidden; }
.meter .fill { display: block; height: 100%; border-radius: 3px; background: var(--series); }
.card ul { margin: 12px 0 4px; padding-left: 20px; }
.card li { margin: 2px 0; }

figure { margin: 18px 0 0; }
figcaption { font-size: 13px; color: var(--ink-2); margin-bottom: 4px; }
svg.chart { display: block; width: 100%; height: auto; overflow: visible; }
svg.chart text { font: 11px system-ui, -apple-system, "Segoe UI", sans-serif; fill: var(--muted); }
svg.chart text.peak { fill: var(--ink-2); font-weight: 600; }
.hit { fill: transparent; }
.bar { fill: var(--series); }
.bar-group:hover .bar, .bar-group:focus .bar { opacity: .75; }
.bar-group:focus { outline: none; }
.bar-group:focus-visible .bar { stroke: var(--ink); stroke-width: 1.5; }

details { margin-top: 6px; font-size: 13px; color: var(--ink-2); }
summary { cursor: pointer; width: max-content; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; font-weight: 600; color: var(--ink-2); border-bottom: 1px solid var(--axis); padding: 6px 8px; }
td { border-bottom: 1px solid var(--grid); padding: 6px 8px; font-variant-numeric: tabular-nums; vertical-align: top; }
.table-wrap { overflow-x: auto; background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 4px 8px; }

.next { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--grid); }
.next h4 { font-size: 13px; font-weight: 600; margin: 0 0 4px; color: var(--ink-2); }
.next ol { margin: 0; padding-left: 20px; color: var(--ink-2); }

pre.allow { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 12px 14px;
  overflow-x: auto; font: 13px/1.6 ui-monospace, "Cascadia Mono", Consolas, monospace; }
.caution { color: var(--ink-2); font-size: 13px; }
.empty { color: var(--ink-2); }

footer { margin-top: 56px; padding-top: 16px; border-top: 1px solid var(--grid); color: var(--ink-2); font-size: 13px; }
footer dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 8px 0 0; }
footer dt { color: var(--muted); }
footer dd { margin: 0; }

#tip { position: fixed; pointer-events: none; z-index: 10; background: var(--surface); color: var(--ink);
  border: 1px solid var(--ring); border-radius: 8px; padding: 6px 10px; font-size: 13px;
  box-shadow: 0 4px 16px rgba(0,0,0,.12); display: none; max-width: 280px; }
#tip strong { display: block; font-weight: 600; }
#tip span { color: var(--ink-2); }
@media (max-width: 560px) { .hero { font-size: 48px; } .verdict { gap: 14px; } }
"""

# Hover readouts. Text goes in with textContent only; nothing from the log is
# ever parsed as HTML.
SCRIPT = """
(() => {
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
    const on = e => show(e, g.dataset.value, g.dataset.label);
    g.addEventListener('pointermove', on);
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
      const gap = lo > 0 ? dur(ts[lo] - ts[lo - 1]) + ' after the previous one' : 'first check-in';
      show(e, fmt(at), 'check-in ' + (lo + 1) + ' of ' + ts.length + ', ' + gap);
    });
    svg.addEventListener('pointerleave', () => { cross.style.display = 'none'; hide(); });
  });
})();
"""

ICON_ATTENTION = ('<svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">'
                  '<circle cx="7" cy="7" r="6" fill="var(--serious)"/>'
                  '<rect x="6.2" y="3.3" width="1.6" height="4.6" rx=".8" fill="#fff"/>'
                  '<circle cx="7" cy="10.2" r=".95" fill="#fff"/></svg>')
ICON_CLEAR = ('<svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">'
              '<circle cx="7" cy="7" r="6" fill="var(--good)"/>'
              '<path d="M4.3 7.2l1.9 1.9 3.6-3.8" stroke="#fff" stroke-width="1.6" fill="none" '
              'stroke-linecap="round" stroke-linejoin="round"/></svg>')


def _utc(ts: float, seconds: bool = False) -> str:
    fmt = "%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(fmt) + " UTC"


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


def _meter(score: float) -> str:
    return (f'<span class="meter" title="beacon score">score {score:.2f}'
            f'<span class="track"><span class="fill" style="width:{score * 100:.0f}%"></span></span></span>')


def _rounded_column(x: float, y: float, w: float, base: float) -> str:
    """A column with a 4px rounded top and a square foot on the baseline."""
    r = min(4.0, w / 2, base - y)
    return (f'M{x:.1f},{base:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}'
            f'H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{base:.1f}Z')


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
  <figcaption>Every check-in across the capture</figcaption>
  <svg class="chart strip" viewBox="0 0 {STRIP_W} {STRIP_H}" data-events="ev-{uid}"
       data-start="{f.capture_start:.3f}" data-end="{f.capture_end:.3f}" data-width="{STRIP_W}"
       role="img" aria-label="{len(f.timestamps)} check-ins between {escape(_utc(f.capture_start))} and {escape(_utc(f.capture_end))}">
    <line x1="0" y1="{base}" x2="{STRIP_W}" y2="{base}" stroke="var(--axis)" stroke-width="1"/>
    <g stroke="var(--series)" stroke-width="1">{ticks}</g>
    <line class="cross" y1="2" y2="{base}" stroke="var(--ink)" stroke-width="1" style="display:none"/>
    <text x="0" y="{STRIP_H - 2}">{escape(_utc(f.capture_start))}</text>
    <text x="{STRIP_W}" y="{STRIP_H - 2}" text-anchor="end">{escape(_utc(f.capture_end))}</text>
  </svg>
  <script type="application/json" id="ev-{uid}">{events}</script>
  {_strip_table(f)}
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
    return (f'<details><summary>Table view: check-ins per time slice</summary>'
            f'<table><thead><tr><th>Slice starting</th><th>Check-ins</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></details>')


def gap_histogram(f: Finding) -> str:
    gaps = [b - a for a, b in zip(f.timestamps, f.timestamps[1:])]
    top = HIST_SPAN * f.period
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
            label = f"gaps of {human_duration(lo)} or more"
        else:
            label = f"gaps from {human_duration(lo)} to {human_duration(lo + bin_w)}"
        value = f"{c} gap{'s' if c != 1 else ''}"
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
    caption = "Gaps between check-ins, marked at multiples of the period"
    if f.missed:
        caption += "; bars at 2× and 3× are missed check-ins"
    return f"""
<figure>
  <figcaption>{escape(caption)}</figcaption>
  <svg class="chart" viewBox="0 0 {HIST_W} {HIST_H}" role="img"
       aria-label="histogram of {len(gaps)} gaps between check-ins">
    <line x1="0" y1="{base}" x2="{HIST_W}" y2="{base}" stroke="var(--axis)" stroke-width="1"/>
    {''.join(marks)}
    {''.join(groups)}
    {peak_label}
  </svg>
  <details><summary>Table view: gap counts</summary>
    <table><thead><tr><th>Gap</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>
  </details>
</figure>"""


# ------------------------------------------------------------------- sections

def headline(f: Finding) -> str:
    return (f"{_addr(f.src)} checks in with {_addr(f.dst)} on {escape(_service(f))} "
            f"every {escape(human_duration(f.period))}")


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


def next_steps(f: Finding) -> str:
    first = _utc(f.first_seen)
    allow_line = f.dst if f.dport is None else f"{f.dst}:{f.dport}"
    if _is_internal(f.dst):
        identify = (f"Identify {_addr(f.dst)} in your asset inventory or DHCP leases. "
                    f"Is it a server that should be offering {escape(_service(f))}?")
    else:
        identify = (f"Look up {_addr(f.dst)} in threat intel and passive DNS. Which name resolved to it? "
                    f"Check <span class=\"addr\">dns.log</span> from {_addr(f.src)} just before {escape(first)}.")
    return f"""
<div class="next"><h4>Next steps</h4><ol>
  <li>{identify}</li>
  <li>Find the process on {_addr(f.src)} making the connection: EDR, Sysmon event ID 3, or <span class="addr">netstat -ano</span> at the next check-in (due every {escape(human_duration(f.period))}).</li>
  <li>If it turns out to be legitimate software, add <span class="addr">{escape(allow_line)}</span> to your allowlist with a comment saying what it is.</li>
</ol></div>"""


def card(f: Finding, uid: str) -> str:
    reasons = "".join(f"<li>{escape(r)}</li>" for r in f.reasons[1:])
    return f"""
<article class="card">
  <div class="card-head"><h3>{headline(f)}</h3>{_meter(f.score)}</div>
  <ul><li>{escape(f.reasons[0])}</li>{reasons}</ul>
  {heartbeat_strip(f, uid)}
  {gap_histogram(f)}
  {next_steps(f)}
</article>"""


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
  <p class="lede">Scored because they talk often, but the gaps are irregular: people browsing, chatty apps, DNS. Highest scores first.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Source</th><th>Destination</th><th>Connections</th><th>Typical gap</th><th>Timing</th><th>Score</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
  {tail}
</section>"""


def verdict(look: Sequence[Finding]) -> str:
    if not look:
        return f"""
<div class="verdict"><div class="hero">0</div><div>
  <h2><span class="status">{ICON_CLEAR}</span> No single-host timers found</h2>
  <p>Nothing in this capture checks in on a timer from just one or two hosts. Fleet-wide timers and irregular traffic are listed below.</p>
</div></div>"""
    top = look[0]
    plural = "pair" if len(look) == 1 else "pairs"
    lead = (f"Strongest: {_addr(top.src)} contacts {_addr(top.dst)} on {escape(_service(top))} "
            f"every {escape(human_duration(top.period))}")
    if top.same_size_share and top.same_size_share >= 0.5 and top.median_bytes is not None:
        lead += f", sending exactly {top.median_bytes:.0f} bytes {top.same_size_share * 100:.0f}% of the time"
    lead += (". No other host does this." if top.timer_hosts <= 1 else ".")
    return f"""
<div class="verdict"><div class="hero">{len(look)}</div><div>
  <h2><span class="status">{ICON_ATTENTION}</span> {plural} worth a look</h2>
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
    # Unknown services first; known timer services (NTP, DNS...) after them.
    look = sorted((f for f in timers if f.timer_hosts < FLEET),
                  key=lambda f: (f.service_hint is not None, -f.score))
    fleet = [f for f in timers if f.timer_hosts >= FLEET]
    others = [f for f in findings if f.timing < ON_A_TIMER]
    fleet_dests = len({(f.dst, f.dport, f.proto) for f in fleet})

    if findings:
        window = (f"{escape(_utc(findings[0].capture_start))} to {escape(_utc(findings[0].capture_end))} "
                  f"({escape(human_duration(findings[0].capture_end - findings[0].capture_start))})")
    else:
        window = "no pairs had enough check-ins to score"

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
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beacon hunt report</title>
<style>{CSS}</style>
</head>
<body class="bh">
<main>
  <header>
    <div class="kicker">beacon-hunter report</div>
    <h1>Beacon hunt</h1>
    <div class="scope">{window}<br>{escape(', '.join(sources))}</div>
  </header>
  {verdict(look)}
  {tiles(rows, len(findings), len(timers), fleet_dests)}
  {look_section}
  {fleet_section(fleet) if fleet else ''}
  {others_section(others) if others else ''}
  <footer>
    Scores rank how much a pair behaves like a timer. They are leads, not verdicts.
    <dl>
      <dt>Connections</dt><dd>{rows:,} read, {skipped:,} skipped as malformed</dd>
      <dt>Scored when</dt><dd>{settings.min_events}+ check-ins; connections under {settings.merge_window:g}s apart count as one</dd>
      <dt>Persistence</dt><dd>capture split into {settings.slices} slices</dd>
      <dt>Missed check-ins</dt><dd>folding {fold}</dd>
      <dt>Allowlist</dt><dd>{len(settings.allow)} entries</dd>
    </dl>
  </footer>
</main>
<div id="tip" role="status"></div>
<script>{SCRIPT}</script>
</body>
</html>
"""
