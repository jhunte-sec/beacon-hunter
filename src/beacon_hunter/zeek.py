"""Read Zeek conn.log files.

Handles the default tab-separated format and JSON lines, plain or gzipped.
Rotated logs are usually gzipped, so both are supported without unpacking.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO

from .timefmt import parse_time

UNSET = {"-", "(empty)", ""}

# Pipelines like Wazuh or Logstash often flatten "id.orig_h" to "id_orig_h",
# so look fields up under both spellings.
FIELD_NAMES = {
    "src": ("id.orig_h", "id_orig_h"),
    "dst": ("id.resp_h", "id_resp_h"),
    "dport": ("id.resp_p", "id_resp_p"),
    "sport": ("id.orig_p", "id_orig_p"),
}


@dataclass(frozen=True)
class Conn:
    ts: float
    src: str
    dst: str
    dport: Optional[int]
    proto: str
    orig_bytes: Optional[int]
    process: Optional[str] = None   # only sources that know it (Sysmon) fill this in
    sport: Optional[int] = None     # the originator's port: retries of one connection share it
    answered: Optional[bool] = None # did the other side reply at all? None when the log doesn't say


@dataclass
class ReadStats:
    rows: int = 0        # connection records read (or rebuilt, for packet captures)
    skipped: int = 0     # records that couldn't be used
    packets: int = 0     # packets read, for packet captures


def read_conn_logs(paths: Iterable[str | Path], stats: Optional[ReadStats] = None) -> Iterator[Conn]:
    """Yield connections from one or more conn.log files, in file order."""
    for path in paths:
        yield from read_conn_log(path, stats)


def read_conn_log(path: str | Path, stats: Optional[ReadStats] = None) -> Iterator[Conn]:
    stats = stats if stats is not None else ReadStats()
    with _open_text(Path(path)) as fh:
        first = fh.readline()
        while first and not first.strip():
            first = fh.readline()
        if not first:
            return
        rows = _iter_json(first, fh) if first.lstrip().startswith("{") else _iter_tsv(first, fh)
        for row in rows:
            stats.rows += 1
            conn = _to_conn(row)
            if conn is None:
                stats.skipped += 1
            else:
                yield conn


def _open_text(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _iter_tsv(first: str, rest: TextIO) -> Iterator[dict]:
    sep = "\t"
    fields: Optional[list[str]] = None
    for line in _chain(first, rest):
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#separator"):
                sep = _decode_separator(line.split(" ", 1)[1])
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            continue
        if fields is None:
            raise ValueError("conn.log has no #fields header; is it really a Zeek TSV log?")
        yield dict(zip(fields, line.split(sep)))


def _iter_json(first: str, rest: TextIO) -> Iterator[dict]:
    for line in _chain(first, rest):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            yield {}  # counted as skipped
            continue
        if isinstance(row, dict):
            yield row
        else:
            yield {}


def _chain(first: str, rest: TextIO) -> Iterator[str]:
    yield first
    yield from rest


def _decode_separator(raw: str) -> str:
    # Zeek writes the separator escaped, e.g. "#separator \x09".
    return raw.strip().encode("utf-8").decode("unicode_escape")


def _get(row: dict, key: str):
    for name in FIELD_NAMES.get(key, (key,)):
        if name in row:
            value = row[name]
            if isinstance(value, str) and value in UNSET:
                return None
            return value
    return None


def _to_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_conn(row: dict) -> Optional[Conn]:
    ts = parse_time(_get(row, "ts"))
    src = _get(row, "src")
    dst = _get(row, "dst")
    if ts is None or not src or not dst:
        return None
    return Conn(
        ts=ts,
        src=str(src),
        dst=str(dst),
        dport=_to_int(_get(row, "dport")),
        proto=str(_get(row, "proto") or "?"),
        orig_bytes=_to_int(_get(row, "orig_bytes")),
        sport=_to_int(_get(row, "sport")),
        answered=_answered(_get(row, "conn_state")),
    )


def _answered(state) -> Optional[bool]:
    # S0: the originator's packets were the only ones seen. Every other state
    # involves something coming back (a SYN-ACK, a reset, data).
    if not state:
        return None
    return str(state) != "S0"
