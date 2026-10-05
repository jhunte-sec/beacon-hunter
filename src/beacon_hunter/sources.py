"""Work out what kind of log each file is and read it with the right reader.

Detection looks at the content, not the file name:

  pcap / pcapng magic bytes      -> pcap
  "ElfFile" (.evtx)              -> sysmon
  a "#separator" header          -> zeek (tab-separated)
  JSON with "event_type"         -> suricata
  JSON with Sysmon event fields  -> sysmon
  other JSON                     -> zeek (JSON logs)
  XML                            -> sysmon (wevtutil / Event Viewer export)
  anything with a delimited header row -> csv
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Optional, TextIO

from . import csvlog, pcap, suricata, sysmon, zeek
from .zeek import Conn, ReadStats

FORMATS = ("auto", "zeek", "suricata", "sysmon", "csv", "pcap")


def _open_binary(path: Path) -> BinaryIO:
    return gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")


def _open_text(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return path.open("r", encoding="utf-8-sig", errors="replace")


def detect(path: Path) -> str:
    with _open_binary(path) as fh:
        head = fh.read(4096)
    if pcap.is_capture(head):
        return "pcap"
    if head.startswith(sysmon.EVTX_MAGIC):
        return "sysmon"
    text = head.decode("utf-8-sig", errors="replace")
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first:
        return "zeek"   # empty file: any reader yields nothing
    if first.startswith("#"):
        return "zeek"
    if first.startswith("<"):
        return "sysmon"
    if first.startswith("{"):
        try:
            obj = json.loads(first)
        except json.JSONDecodeError:
            return "zeek"   # let the reader count it as malformed
        if suricata.looks_like(obj):
            return "suricata"
        if sysmon.looks_like(obj):
            return "sysmon"
        return "zeek"
    if any(sep in first for sep in ",;\t|"):
        return "csv"
    raise ValueError(f"{path}: can't tell what kind of log this is; pass --format")


def read(path: Path, fmt: str, stats: ReadStats, csv_map: Optional[dict] = None) -> Iterator[Conn]:
    fmt = detect(path) if fmt == "auto" else fmt
    if fmt == "pcap":
        with _open_binary(path) as fh:
            yield from pcap.connections(fh, stats)
        return
    if fmt == "zeek":
        yield from zeek.read_conn_log(path, stats)
        return
    if fmt == "sysmon":
        with _open_binary(path) as fh:
            magic = fh.read(8)
        if magic.startswith(sysmon.EVTX_MAGIC):
            yield from sysmon.read_evtx(path, stats)
            return
        with _open_text(path) as fh:
            text = fh.read()
        if text.lstrip().startswith("<"):
            yield from sysmon.read_xml(text, stats)
        else:
            yield from sysmon.read_json(text.splitlines(), stats)
        return
    with _open_text(path) as fh:
        if fmt == "suricata":
            yield from suricata.read(fh, stats)
        elif fmt == "csv":
            yield from csvlog.read(fh, stats, csv_map)
        else:
            raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def read_all(paths: Iterable[str | Path], fmt: str = "auto", stats: Optional[ReadStats] = None,
             csv_map: Optional[dict] = None) -> Iterator[Conn]:
    stats = stats if stats is not None else ReadStats()
    for path in paths:
        yield from read(Path(path), fmt, stats, csv_map)
