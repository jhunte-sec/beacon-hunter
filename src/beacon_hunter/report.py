"""Turn findings into a terminal table or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional, Sequence

from .scoring import Finding


def human_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _fmt_score(value: Optional[float]) -> str:
    return "  -" if value is None else f"{value:.2f}"


def _fmt_dst(f: Finding) -> str:
    port = "" if f.dport is None else f":{f.dport}"
    return f"{f.dst}{port}/{f.proto}"


def table(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No pairs had enough check-ins to score."
    header = ("score", "source", "destination", "conns", "every", "jitter", "bytes", "timing", "size", "persist")
    rows = [header]
    for f in findings:
        rows.append((
            f"{f.score:.2f}",
            f.src,
            _fmt_dst(f),
            str(f.connections),
            human_duration(f.median_interval),
            f"{f.jitter * 100:.0f}%",
            "-" if f.median_bytes is None else f"{f.median_bytes:.0f}",
            _fmt_score(f.timing),
            _fmt_score(f.size),
            _fmt_score(f.persistence),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines = []
    for n, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def to_json(findings: Sequence[Finding]) -> str:
    out = []
    for f in findings:
        item = asdict(f)
        item["first_seen"] = _iso(f.first_seen)
        item["last_seen"] = _iso(f.last_seen)
        for key in ("score", "timing", "size", "persistence", "jitter", "median_interval"):
            if item[key] is not None:
                item[key] = round(item[key], 4)
        out.append(item)
    return json.dumps(out, indent=2)
