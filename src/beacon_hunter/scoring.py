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
from .timefmt import human_duration
from .zeek import Conn

WEIGHTS = {"timing": 0.5, "size": 0.2, "persistence": 0.3}

ON_A_TIMER = 0.8        # timing score at which we call it a timer in the reasons

# Services that run on a timer by design. A hint, never an exemption: malware
# tunnels over DNS and NTP precisely because these ports look boring.
KNOWN_TIMERS = {
    (53, "udp"): "DNS", (53, "tcp"): "DNS",
    (67, "udp"): "DHCP", (123, "udp"): "NTP time sync",
    (161, "udp"): "SNMP polling", (514, "udp"): "syslog",
    (1514, "tcp"): "the Wazuh agent", (1514, "udp"): "the Wazuh agent",
    (9997, "tcp"): "the Splunk forwarder", (8220, "tcp"): "Elastic Agent (Fleet)",
}

# Folding missed check-ins back onto the timer (see fold_onto_period).
MAX_MULTIPLE = 4        # a gap of up to 4 periods can be explained as missed beats
MIN_GAPS_TO_FOLD = 8


@dataclass
class Settings:
    min_events: int = 10        # check-ins needed before a pair is scored
    merge_window: float = 1.0   # connections closer than this count as one check-in
    slices: int = 24            # persistence: split the capture into this many slices
    by_port: bool = True        # group by destination port as well as host
    include_multicast: bool = False
    fold: bool = True           # forgive missed check-ins (see fold_onto_period)
    allow: list[allowlist.Entry] = field(default_factory=list)


@dataclass
class Timing:
    score: float
    period: float               # the timer we think it's on, in seconds
    jitter: float               # spread of the gaps around the period, as a fraction
    missed: Optional[float]     # share of expected check-ins that never showed up (folded only)


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
    period: float
    jitter: float
    missed: Optional[float]
    median_bytes: Optional[float]
    same_size_share: Optional[float]
    active_slices: int
    slices: int
    timing: float
    size: Optional[float]
    persistence: float
    score: float
    hosts: int = 1              # sources with a scored pair to the same destination
    timer_hosts: int = 0        # of those, how many are on a timer
    service_hint: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list, repr=False)
    capture_start: float = 0.0
    capture_end: float = 0.0


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


def fold_onto_period(intervals: Sequence[float]) -> Optional[Timing]:
    """Score the timer while forgiving missed check-ins.

    A laptop that sleeps, a dropped packet or a busy implant turns a 60 s timer
    into gaps of 60, 60, 120, 60, 180. Taken at face value that looks irregular.
    Here the base period is estimated from the shortest gaps, every gap that is
    close to a whole multiple of it is divided back down, and the timing score
    is multiplied by the share of gaps that fit. Random traffic rarely lines up
    on whole multiples, so it gains nothing from this; the simulations behind
    the thresholds are described in docs/how-it-works.md.
    """
    if len(intervals) < MIN_GAPS_TO_FOLD:
        return None
    ordered = sorted(intervals)
    q1 = ordered[len(ordered) // 4]
    shortest = [g for g in ordered if g <= 1.5 * q1]
    base = median(shortest)
    if base <= 0:
        return None
    # Allow more slack when the timer itself is jittery, within sane bounds.
    tolerance = min(0.35, max(0.15, 2.5 * mad(shortest, base) / base))

    folded, beats = [], 0
    for gap in intervals:
        k = round(gap / base)
        if 1 <= k <= MAX_MULTIPLE and abs(gap / base - k) <= tolerance:
            folded.append(gap / k)
            beats += k
    if len(folded) < 3:
        return None

    fit = len(folded) / len(intervals)
    period = median(folded)
    return Timing(
        score=timing_score(folded) * fit,
        period=period,
        jitter=mad(folded, period) / period,
        missed=(beats - len(folded)) / beats,
    )


def analyze_timing(intervals: Sequence[float], fold: bool = True) -> Timing:
    m = median(intervals)
    plain = Timing(timing_score(intervals), m, mad(intervals, m) / m if m > 0 else 0.0, None)
    folded = fold_onto_period(intervals) if fold else None
    if folded is not None and folded.score > plain.score:
        return folded
    return plain


def size_score(sizes: Sequence[int], connections: int) -> Optional[float]:
    """None when too few connections carry a byte count to judge."""
    if len(sizes) < 3 or len(sizes) < connections / 2:
        return None
    return 0.5 * regularity(sizes) + 0.5 * _mode_share(sizes)


def _mode_share(sizes: Sequence[int]) -> float:
    return Counter(sizes).most_common(1)[0][1] / len(sizes)


def active_slices(events: Sequence[float], start: float, end: float, slices: int) -> int:
    if end <= start or slices <= 1:
        return slices
    width = (end - start) / slices
    return len({min(int((ts - start) / width), slices - 1) for ts in events})


def persistence_score(events: Sequence[float], start: float, end: float, slices: int) -> float:
    """Share of the capture's time slices in which the pair was active."""
    return active_slices(events, start, end, slices) / max(slices, 1)


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

        timing = analyze_timing(intervals, settings.fold)
        size = size_score(sizes, len(members))
        active = active_slices(events, start, end, settings.slices)
        persistence = active / settings.slices

        findings.append(Finding(
            src=src, dst=dst, dport=port, proto=proto,
            connections=len(members),
            events=len(events),
            first_seen=events[0],
            last_seen=events[-1],
            period=timing.period,
            jitter=timing.jitter,
            missed=timing.missed,
            median_bytes=median(sizes) if sizes else None,
            same_size_share=_mode_share(sizes) if size is not None else None,
            active_slices=active,
            slices=settings.slices,
            timing=timing.score,
            size=size,
            persistence=persistence,
            score=combine(timing.score, size, persistence),
            timestamps=events,
            capture_start=start,
            capture_end=end,
            service_hint=KNOWN_TIMERS.get((port, proto)) if port is not None else None,
        ))

    # How many sources reach the same destination, and how many on a timer? A
    # timer on every host is usually software you deployed; on one host it stands out.
    sources: dict[tuple, set[str]] = defaultdict(set)
    timed: dict[tuple, set[str]] = defaultdict(set)
    for f in findings:
        key = (f.dst, f.dport, f.proto)
        sources[key].add(f.src)
        if f.timing >= ON_A_TIMER:
            timed[key].add(f.src)
    for f in findings:
        key = (f.dst, f.dport, f.proto)
        f.hosts = len(sources[key])
        f.timer_hosts = len(timed[key])
        f.reasons = explain(f)

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


def explain(f: Finding) -> list[str]:
    """Plain-English reasons, the way you'd write them in a triage note."""
    reasons = []
    every = human_duration(f.period)
    # jitter is the median absolute deviation, so "half the gaps" is exact, not a guess.
    spread = f"half the gaps are within {f.jitter * 100:.0f}% of that"
    if f.timing >= ON_A_TIMER:
        line = f"checks in every {every}; " + ("almost exactly" if f.jitter < 0.01 else spread)
    elif f.timing >= 0.6:
        line = f"loosely periodic around {every}; {spread}"
    else:
        line = f"no clear timer: typical gap {every}, but half the gaps are more than {f.jitter * 100:.0f}% off"
    if f.missed:
        line += f"; about {f.missed * 100:.0f}% of expected check-ins are missing, but the rest stay on the timer"
    reasons.append(line)

    if f.same_size_share is not None and f.median_bytes is not None:
        if f.same_size_share >= 0.5:
            reasons.append(f"sends exactly {f.median_bytes:.0f} bytes in {f.same_size_share * 100:.0f}% of check-ins")
        elif f.size is not None and f.size >= 0.6:
            reasons.append(f"sends a similar amount each time (around {f.median_bytes:.0f} bytes)")
        else:
            reasons.append("the amount sent changes a lot between check-ins")

    reasons.append(f"active in {f.active_slices} of {f.slices} time slices of the capture")

    if f.timing >= ON_A_TIMER:
        if f.timer_hosts >= 3:
            reasons.append(f"{f.timer_hosts} hosts check in here on a timer, which usually means deployed software")
        elif f.timer_hosts == 2:
            reasons.append("one other host checks in here on a timer too")
        else:
            reasons.append("no other host checks in here on a timer")
    elif f.hosts > 1:
        reasons.append(f"{f.hosts} hosts talk to this destination")

    if f.service_hint:
        reasons.append(f"{f.dport}/{f.proto} is usually {f.service_hint}, which runs on a timer by design; "
                       f"confirm {f.dst} is a server you expect")
    return reasons
