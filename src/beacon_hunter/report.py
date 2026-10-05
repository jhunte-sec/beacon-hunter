"""Turn findings into a terminal table or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional, Sequence

from .scoring import Finding
from .timefmt import human_duration, iso

# Fields that only matter inside the program (the HTML report uses them).
_INTERNAL = ("timestamps", "capture_start", "capture_end")


def _fmt_score(value: Optional[float]) -> str:
    return "  -" if value is None else f"{value:.2f}"


def destination(f: Finding) -> str:
    port = "" if f.dport is None else f":{f.dport}"
    return f"{f.dst}{port}/{f.proto}"


def table(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No pairs had enough check-ins to score."
    header = ("score", "source", "destination", "conns", "every", "jitter", "missed",
              "bytes", "hosts", "timing", "size", "persist")
    rows = [header]
    for f in findings:
        rows.append((
            f"{f.score:.2f}",
            f.src,
            destination(f),
            str(f.connections),
            human_duration(f.period),
            f"{f.jitter * 100:.0f}%",
            "-" if f.missed is None else f"{f.missed * 100:.0f}%",
            "-" if f.median_bytes is None else f"{f.median_bytes:.0f}",
            str(f.hosts),
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


def explained(findings: Sequence[Finding]) -> str:
    """The table's top rows written out as triage notes."""
    blocks = []
    for f in findings:
        lines = [f"{f.score:.2f}  {f.src} -> {destination(f)}"]
        lines += [f"      - {reason}" for reason in f.reasons]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def to_json(findings: Sequence[Finding]) -> str:
    out = []
    for f in findings:
        item = asdict(f)
        for key in _INTERNAL:
            item.pop(key)
        item["first_seen"] = iso(f.first_seen)
        item["last_seen"] = iso(f.last_seen)
        for key in ("score", "timing", "size", "persistence", "jitter", "period", "missed", "same_size_share"):
            if item[key] is not None:
                item[key] = round(item[key], 4)
        out.append(item)
    return json.dumps(out, indent=2)
