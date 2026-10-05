"""Score groups of connections for beacon-like behaviour.

A beacon is a host checking in with the same destination on a timer. Three
things give it away, and each gets a score between 0 and 1:

  timing       the gaps between check-ins are nearly the same every time
  size         the check-ins send roughly the same number of bytes
  persistence  it keeps going for the whole capture, not just one burst

The final score is a weighted average. See docs/how-it-works.md for the
reasoning and worked numbers.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import median, quantiles
from typing import Iterable, Optional, Sequence

from . import allowlist
from .zeek import Conn

WEIGHTS = {"timing": 0.5, "size": 0.2, "persistence": 0.3}


@dataclass
class Settings:
    min_events: int = 10        # check-ins needed before a pair is scored
    merge_window: float = 1.0   # connections closer than this count as one check-in
    slices: int = 24            # persistence: split the capture into this many slices
    by_port: bool = True        # group by destination port as well as host
    include_multicast: bool = False
    allow: list[allowlist.Entry] = field(default_factory=list)


@dataclass
class Finding:
    src: str
    dst: str
    dport: Optional[int]
    proto: str
    connections: int
    events: int
    first_seen: float
    last_seen: float
    median_interval: float
    jitter: float               # median absolute deviation / median interval
    median_bytes: Optional[float]
    timing: float
    size: Optional[float]
    persistence: float
    score: float


def mad(values: Sequence[float], center: float) -> float:
    """Median absolute deviation around center."""
    return median(abs(v - center) for v in values)


def bowley_skew(values: Sequence[float]) -> float:
    """Quartile skewness in [-1, 1]. 0 means the spread is symmetric."""
    if len(values) < 3:
        return 0.0
    q1, q2, q3 = quantiles(values, n=4, method="inclusive")
    iqr = q3 - q1
    if iqr == 0:
        return 0.0
    return (q3 + q1 - 2 * q2) / iqr


def regularity(values: Sequence[float]) -> float:
    """1.0 when every value is the same, falling toward 0 as they scatter."""
    m = median(values)
    spread = mad(values, m)
    if spread == 0:
        return 1.0
    if m <= 0:
        return 0.0
    return max(0.0, 1.0 - spread / m)


def merge_events(timestamps: Sequence[float], window: float) -> list[float]:
    """Collapse bursts: a new check-in starts only after a gap of `window` seconds.

    Some implants open two or three connections per check-in. Without this the
    gaps would alternate between tiny and large and the timer would be hidden.
    """
    events: list[float] = []
    previous = None
    for ts in sorted(timestamps):
        if previous is None or ts - previous >= window:
            events.append(ts)
        previous = ts
    return events


def timing_score(intervals: Sequence[float]) -> float:
    return 0.7 * regularity(intervals) + 0.3 * (1.0 - abs(bowley_skew(intervals)))


def size_score(sizes: Sequence[int], connections: int) -> Optional[float]:
    """None when too few connections carry a byte count to judge."""
    if len(sizes) < 3 or len(sizes) < connections / 2:
        return None
    mode_share = Counter(sizes).most_common(1)[0][1] / len(sizes)
    return 0.5 * regularity(sizes) + 0.5 * mode_share


def persistence_score(events: Sequence[float], start: float, end: float, slices: int) -> float:
    """Share of the capture's time slices in which the pair was active."""
    if end <= start or slices <= 1:
        return 1.0
    width = (end - start) / slices
    active = {min(int((ts - start) / width), slices - 1) for ts in events}
    return len(active) / slices


def combine(timing: float, size: Optional[float], persistence: float) -> float:
    parts = {"timing": timing, "persistence": persistence}
    if size is not None:
        parts["size"] = size
    total_weight = sum(WEIGHTS[name] for name in parts)
    return sum(WEIGHTS[name] * value for name, value in parts.items()) / total_weight


def _is_broadcast_or_multicast(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_multicast or address == "255.255.255.255"


def analyze(conns: Iterable[Conn], settings: Optional[Settings] = None) -> list[Finding]:
    """Group connections by (src, dst, port, proto), score each group, best first."""
    settings = settings or Settings()
    groups: dict[tuple, list[Conn]] = defaultdict(list)
    start = end = None

    for conn in conns:
        start = conn.ts if start is None else min(start, conn.ts)
        end = conn.ts if end is None else max(end, conn.ts)
        if not settings.include_multicast and _is_broadcast_or_multicast(conn.dst):
            continue
        if settings.allow and allowlist.is_allowed(settings.allow, conn.dst, conn.dport):
            continue
        port = conn.dport if settings.by_port else None
        groups[(conn.src, conn.dst, port, conn.proto)].append(conn)

    findings = []
    for (src, dst, port, proto), members in groups.items():
        events = merge_events([c.ts for c in members], settings.merge_window)
        if len(events) < settings.min_events:
            continue
        intervals = [b - a for a, b in zip(events, events[1:])]
        sizes = [c.orig_bytes for c in members if c.orig_bytes is not None]

        timing = timing_score(intervals)
        size = size_score(sizes, len(members))
        persistence = persistence_score(events, start, end, settings.slices)
        m = median(intervals)

        findings.append(Finding(
            src=src, dst=dst, dport=port, proto=proto,
            connections=len(members),
            events=len(events),
            first_seen=events[0],
            last_seen=events[-1],
            median_interval=m,
            jitter=mad(intervals, m) / m if m > 0 else 0.0,
            median_bytes=median(sizes) if sizes else None,
            timing=timing,
            size=size,
            persistence=persistence,
            score=combine(timing, size, persistence),
        ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
