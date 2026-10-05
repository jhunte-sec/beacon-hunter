"""Read connections from Suricata's eve.json.

Only flow records are used (event_type "flow", or "netflow" if that output is
enabled). Two details that are easy to get wrong:

  * The record's own "timestamp" is when Suricata *wrote* it, usually when the
    flow ended or timed out. The connection started at flow.start, which is the
    time that matters for check-in timing.
  * src_ip is the side that sent the first packet, so it is the initiator,
    which matches Zeek's id.orig_h.
"""

from __future__ import annotations

import json
from typing import Iterable, Iterator, Optional

from .timefmt import parse_time
from .zeek import Conn, ReadStats

FLOW_TYPES = {"flow", "netflow"}


def read(lines: Iterable[str], stats: ReadStats) -> Iterator[Conn]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            stats.rows += 1
            stats.skipped += 1
            continue
        if not isinstance(event, dict) or event.get("event_type") not in FLOW_TYPES:
            continue  # alerts, dns, http...: not connection records
        stats.rows += 1
        conn = to_conn(event)
        if conn is None:
            stats.skipped += 1
        else:
            yield conn


def to_conn(event: dict) -> Optional[Conn]:
    flow = event.get("flow") or event.get("netflow") or {}
    ts = parse_time(flow.get("start")) or parse_time(event.get("timestamp"))
    src, dst = event.get("src_ip"), event.get("dest_ip")
    if ts is None or not src or not dst:
        return None
    sent = flow.get("bytes_toserver", flow.get("bytes"))
    port = event.get("dest_port")
    return Conn(
        ts=ts,
        src=str(src),
        dst=str(dst),
        dport=_port(port),
        proto=str(event.get("proto") or "?").lower(),
        orig_bytes=int(sent) if isinstance(sent, (int, float)) else None,
        sport=_port(event.get("src_port")),
        answered=(flow["pkts_toclient"] > 0) if isinstance(flow.get("pkts_toclient"), (int, float)) else None,
    )


def _port(value) -> Optional[int]:
    return int(value) if isinstance(value, (int, float)) or str(value).isdigit() else None


def looks_like(first: dict) -> bool:
    return "event_type" in first and ("src_ip" in first or "flow_id" in first)
