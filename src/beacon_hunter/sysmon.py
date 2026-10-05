"""Read network connections from Sysmon (Event ID 3).

Sysmon logs every outbound connection a Windows process makes, with the
process's image path. That is the one thing network logs can't tell you, and
it turns "this IP is beaconing" into "rundll32.exe is beaconing".

Accepted forms, all detected automatically:

  * JSON lines as exported by Winlogbeat/Elastic (winlog.event_data), Wazuh
    alerts (data.win.eventdata), or flat exports such as the OTRF Security
    Datasets (EventID, UtcTime, SourceIp... at the top level)
  * XML from `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml` or
    Event Viewer's "Save as XML"
  * .evtx files, if the optional python-evtx package is installed

Only Event ID 3 with Initiated=true is used: connections the local process
started. Sysmon doesn't record byte counts, so the size score is left out.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .timefmt import parse_time
from .zeek import Conn, ReadStats

EVTX_MAGIC = b"ElfFile\x00"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# -------------------------------------------------------------- normalising

def _lower_keys(d: dict) -> dict:
    return {str(k).lower(): v for k, v in d.items()}


def _event_parts(event: dict) -> tuple[Optional[str], dict]:
    """(event id, event data) from any of the JSON shapes, keys lower-cased."""
    if isinstance(event.get("winlog"), dict):                       # Winlogbeat / Elastic
        w = event["winlog"]
        return str(w.get("event_id", "")), _lower_keys(w.get("event_data") or {})
    win = (event.get("data") or {}).get("win") if isinstance(event.get("data"), dict) else None
    if isinstance(win, dict):                                        # Wazuh
        system = win.get("system") or {}
        return str(system.get("eventID", "")), _lower_keys(win.get("eventdata") or {})
    flat = _lower_keys(event)                                        # flat exports
    eid = flat.get("eventid", flat.get("event_id", flat.get("eventcode", "")))
    return str(eid), flat


def to_conn(event_id: Optional[str], data: dict) -> Optional[Conn]:
    if str(event_id).strip() != "3":
        return None
    if str(data.get("initiated", "true")).lower() not in ("true", "1"):
        return None  # inbound: someone else connected to this process
    ts = parse_time(data.get("utctime"))
    src, dst = data.get("sourceip"), data.get("destinationip")
    if ts is None or not src or not dst:
        return None
    port = str(data.get("destinationport", "")).strip()
    sport = str(data.get("sourceport", "")).strip()
    image = data.get("image")
    return Conn(
        ts=ts,
        src=str(src),
        dst=str(dst),
        dport=int(port) if port.isdigit() else None,
        proto=str(data.get("protocol") or "?").lower(),
        orig_bytes=None,
        process=str(image) if image else None,
        sport=int(sport) if sport.isdigit() else None,
    )


# ------------------------------------------------------------------- readers

def read_json(lines: Iterable[str], stats: ReadStats) -> Iterator[Conn]:
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
        if not isinstance(event, dict):
            continue
        event_id, data = _event_parts(event)
        if event_id != "3":
            continue  # other Sysmon or Windows events: not connections
        stats.rows += 1
        conn = to_conn(event_id, data)
        if conn is None:
            stats.skipped += 1
        else:
            yield conn


def read_xml(text: str, stats: ReadStats) -> Iterator[Conn]:
    # Event logs never need a DTD; refusing one rules out entity-expansion tricks.
    if "<!DOCTYPE" in text[:4096].upper() or "<!ENTITY" in text.upper():
        raise ValueError("refusing XML with a DOCTYPE or ENTITY declaration")
    body = text.strip()
    if body.startswith("<?xml"):
        body = body.split("?>", 1)[1]
    root = ET.fromstring(f"<Events>{body}</Events>") if not body.lstrip().startswith("<Events") else ET.fromstring(body)
    for event in root.iter(f"{NS}Event"):
        yield from _from_xml_event(event, stats)
    for event in root.iter("Event"):                       # exports without the namespace
        yield from _from_xml_event(event, stats, ns="")


def _from_xml_event(event, stats: ReadStats, ns: str = NS) -> Iterator[Conn]:
    eid = event.findtext(f"{ns}System/{ns}EventID")
    if (eid or "").strip() != "3":
        return
    data = {d.get("Name", "").lower(): (d.text or "") for d in event.iter(f"{ns}Data")}
    stats.rows += 1
    conn = to_conn(eid, data)
    if conn is None:
        stats.skipped += 1
    else:
        yield conn


def read_evtx(path: Path, stats: ReadStats) -> Iterator[Conn]:
    try:
        from Evtx.Evtx import Evtx  # optional: pip install python-evtx
    except ImportError:
        raise ValueError(f"{path}: reading .evtx needs the optional python-evtx package "
                         f"(pip install python-evtx), or export the log to XML with "
                         f"wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml") from None
    with Evtx(str(path)) as log:
        for record in log.records():
            yield from read_xml(record.xml(), stats)


def looks_like(first: dict) -> bool:
    event_id, data = _event_parts(first)
    return bool(event_id) and any(k in data for k in ("utctime", "image", "sourceip", "destinationip"))
