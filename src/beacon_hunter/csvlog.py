"""Read connections from CSV exports: firewalls, proxies, SIEM searches.

Every vendor names its columns differently, so the columns are matched by
name. Common spellings are recognised on their own (Palo Alto's "Receive
Time" / "Source address" / "Destination Port", generic "src_ip", "dst_port",
and so on); anything else is mapped on the command line:

    beacon-hunter fw.csv --csv-map "ts=Log Time,src=Client,dst=Server,dport=Svc Port"

Fields: ts, src and dst are required; dport, proto, bytes (sent by the
source), process and sport (the source port) are optional.
"""

from __future__ import annotations

import csv
import re
from typing import Iterable, Iterator, Optional

from .timefmt import parse_time
from .zeek import Conn, ReadStats

FIELDS = ("ts", "src", "dst", "dport", "proto", "bytes", "process", "sport")
REQUIRED = ("ts", "src", "dst")

KNOWN = {
    "ts": ("ts", "time", "timestamp", "date", "datetime", "start time", "receive time", "generated time",
           "event time", "@timestamp", "starttime", "first seen", "_time", "time generated"),
    "src": ("src", "source", "src ip", "srcip", "source ip", "source address", "src addr", "sourceip",
            "client ip", "src address", "id.orig h", "srcaddr"),
    "dst": ("dst", "dest", "destination", "dst ip", "dest ip", "dstip", "destination ip",
            "destination address", "dst addr", "destinationip", "server ip", "dst address", "id.resp h", "dstaddr"),
    "dport": ("dport", "dst port", "dest port", "dstport", "destination port", "dpt", "id.resp p",
              "destinationport", "server port"),
    "proto": ("proto", "protocol", "ip protocol", "transport"),
    "bytes": ("orig bytes", "bytes sent", "sent bytes", "bytes out", "sentbytes", "src bytes",
              "bytes toserver", "client bytes", "bytes_sent"),
    "process": ("process", "image", "application", "process name", "app"),
    "sport": ("sport", "src port", "source port", "srcport", "spt", "id.orig p", "sourceport", "client port"),
}


def _norm(name: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[_\-]+", " ", name.strip().lower()))


def parse_map(text: Optional[str]) -> dict[str, str]:
    """'ts=Log Time,src=Client' -> {'ts': 'Log Time', 'src': 'Client'}"""
    mapping = {}
    for part in (text or "").split(","):
        if not part.strip():
            continue
        field, sep, column = part.partition("=")
        field = field.strip().lower()
        if not sep or field not in FIELDS:
            raise ValueError(f"--csv-map entry {part.strip()!r}: use field=Column with field one of {', '.join(FIELDS)}")
        mapping[field] = column.strip()
    return mapping


def resolve_columns(header: list[str], override: dict[str, str]) -> dict[str, str]:
    by_norm = {_norm(h): h for h in header}
    columns = {}
    for field in FIELDS:
        if field in override:
            if override[field] not in header:
                raise ValueError(f"--csv-map: no column named {override[field]!r}; columns are: {', '.join(header)}")
            columns[field] = override[field]
            continue
        for name in KNOWN[field]:
            if _norm(name) in by_norm:
                columns[field] = by_norm[_norm(name)]
                break
    missing = [f for f in REQUIRED if f not in columns]
    if missing:
        raise ValueError(f"CSV: couldn't find a column for {', '.join(missing)}. Columns are: {', '.join(header)}. "
                         f"Map them with --csv-map, e.g. --csv-map \"ts=Log Time,src=Client,dst=Server\"")
    return columns


def read(lines: Iterable[str], stats: ReadStats, override: Optional[dict[str, str]] = None) -> Iterator[Conn]:
    lines = iter(lines)
    head = next(lines, "")
    try:
        dialect = csv.Sniffer().sniff(head, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(_chain(head, lines), dialect)
    header = next(reader, None)
    if not header:
        return
    header = [h.strip().lstrip("﻿") for h in header]
    columns = resolve_columns(header, override or {})
    index = {field: header.index(col) for field, col in columns.items()}

    for row in reader:
        if not row or all(not cell.strip() for cell in row):
            continue
        stats.rows += 1
        conn = _to_conn(row, index)
        if conn is None:
            stats.skipped += 1
        else:
            yield conn


def _chain(first: str, rest: Iterable[str]) -> Iterator[str]:
    yield first
    yield from rest


def _cell(row: list[str], index: dict[str, int], field: str) -> Optional[str]:
    i = index.get(field)
    if i is None or i >= len(row):
        return None
    value = row[i].strip()
    return value if value not in ("", "-") else None


def _to_conn(row: list[str], index: dict[str, int]) -> Optional[Conn]:
    ts = parse_time(_cell(row, index, "ts"))
    src, dst = _cell(row, index, "src"), _cell(row, index, "dst")
    if ts is None or not src or not dst:
        return None
    port = _cell(row, index, "dport")
    sent = (_cell(row, index, "bytes") or "").replace(",", "")
    return Conn(
        ts=ts,
        src=src,
        dst=dst,
        dport=int(float(port)) if port and port.replace(".", "", 1).isdigit() else None,
        proto=(_cell(row, index, "proto") or "?").lower(),
        orig_bytes=int(float(sent)) if sent.replace(".", "", 1).isdigit() else None,
        process=_cell(row, index, "process"),
        sport=int(float(sp)) if (sp := _cell(row, index, "sport")) and sp.replace(".", "", 1).isdigit() else None,
    )
