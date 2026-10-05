import json
import struct

import pytest

from beacon_hunter import csvlog, pcap, sources, suricata, sysmon
from beacon_hunter.cli import main
from beacon_hunter.scoring import analyze, merge_retries
from beacon_hunter.timefmt import parse_time
from beacon_hunter.zeek import Conn, ReadStats


def _read(path, fmt="auto", csv_map=None):
    stats = ReadStats()
    return list(sources.read_all([path], fmt, stats, csv_map)), stats


# ------------------------------------------------------------------ Suricata

FLOW = {"timestamp": "2026-10-04T12:05:00.000000+0000", "flow_id": 1, "event_type": "flow",
        "src_ip": "10.0.0.5", "src_port": 51000, "dest_ip": "203.0.113.50", "dest_port": 443, "proto": "TCP",
        "flow": {"start": "2026-10-04T12:00:00.250000+0000", "end": "2026-10-04T12:00:01.000000+0000",
                 "bytes_toserver": 412, "bytes_toclient": 1200, "pkts_toserver": 5, "pkts_toclient": 4}}


def test_suricata_uses_flow_start_not_the_record_time(tmp_path):
    path = tmp_path / "eve.json"
    alert = {"timestamp": "2026-10-04T12:00:00+0000", "event_type": "alert", "src_ip": "10.0.0.5"}
    path.write_text(json.dumps(alert) + "\n" + json.dumps(FLOW) + "\n", encoding="utf-8")
    (conn,), stats = _read(path)
    assert sources.detect(path) == "suricata"
    assert conn.ts == parse_time("2026-10-04T12:00:00.25Z")       # flow.start, 5 minutes before "timestamp"
    assert (conn.src, conn.dst, conn.dport, conn.proto) == ("10.0.0.5", "203.0.113.50", 443, "tcp")
    assert (conn.orig_bytes, conn.sport, conn.answered) == (412, 51000, True)
    assert stats.rows == 1                                       # the alert isn't a connection record


# -------------------------------------------------------------------- Sysmon

FLAT = {"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "UtcTime": "2026-10-04 12:00:00.123",
        "Image": r"C:\Users\bob\AppData\Roaming\svc.exe", "Protocol": "tcp", "Initiated": "true",
        "SourceIp": "10.0.0.5", "SourcePort": "51000", "DestinationIp": "203.0.113.50", "DestinationPort": "443"}


@pytest.mark.parametrize("event", [
    FLAT,
    {"@timestamp": "x", "winlog": {"event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational",
                                   "event_data": {k: v for k, v in FLAT.items() if k not in ("EventID", "Channel")}}},
    {"data": {"win": {"system": {"eventID": "3"},
                      "eventdata": {k[0].lower() + k[1:]: v for k, v in FLAT.items() if k not in ("EventID", "Channel")}}}},
], ids=["flat", "winlogbeat", "wazuh"])
def test_sysmon_json_shapes(tmp_path, event):
    path = tmp_path / "sysmon.json"
    other = dict(FLAT, EventID=1)                                # process creation: not a connection
    path.write_text(json.dumps(other) + "\n" + json.dumps(event) + "\n", encoding="utf-8")
    (conn,), _ = _read(path)
    assert sources.detect(path) == "sysmon"
    assert conn.process == r"C:\Users\bob\AppData\Roaming\svc.exe"
    assert (conn.dst, conn.dport, conn.sport, conn.orig_bytes) == ("203.0.113.50", 443, 51000, None)
    assert conn.ts == parse_time("2026-10-04T12:00:00.123Z")


def _xml_event(eid, **data):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<EventID>{eid}</EventID></System><EventData>{fields}</EventData></Event>')


def test_sysmon_xml_from_wevtutil_skips_inbound(tmp_path):
    data = {k: v for k, v in FLAT.items() if k not in ("EventID", "Channel")}
    path = tmp_path / "sysmon.xml"     # wevtutil prints events back to back, with no root element
    path.write_text(_xml_event(3, **data) + _xml_event(3, **dict(data, Initiated="false")) + _xml_event(1, **data),
                    encoding="utf-8")
    conns, stats = _read(path)
    assert len(conns) == 1 and conns[0].process.endswith("svc.exe")
    assert (stats.rows, stats.skipped) == (2, 1)                 # the inbound one is read, then set aside


def test_sysmon_xml_with_a_doctype_is_refused(tmp_path):
    path = tmp_path / "evil.xml"
    path.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><Events>&a;</Events>', encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE"):
        _read(path, "sysmon")


def test_programs_are_scored_separately():
    malware = [Conn(i * 60.0, "10.0.0.5", "203.0.113.50", 443, "tcp", None, process="svc.exe") for i in range(40)]
    browser = [Conn(i * 61.7 + 5, "10.0.0.5", "203.0.113.50", 443, "tcp", None, process="chrome.exe") for i in range(40)]
    findings = {f.process: f for f in analyze(malware + browser)}
    assert set(findings) == {"svc.exe", "chrome.exe"}
    assert "made by svc.exe" in findings["svc.exe"].reasons


# ----------------------------------------------------------------------- CSV

def test_csv_recognises_palo_alto_columns(tmp_path):
    path = tmp_path / "traffic.csv"
    path.write_text(
        "Receive Time,Start Time,Source address,Destination address,Source Port,Destination Port,IP Protocol,Bytes Sent\n"
        "2026/10/04 12:00:09,2026/10/04 12:00:00,10.0.0.5,203.0.113.50,51000,443,tcp,412\n", encoding="utf-8")
    (conn,), _ = _read(path)
    assert sources.detect(path) == "csv"
    assert conn.ts == parse_time("2026-10-04T12:00:00Z")          # Start Time, not Receive Time
    assert (conn.src, conn.dst, conn.dport, conn.sport, conn.orig_bytes) == ("10.0.0.5", "203.0.113.50", 443, 51000, 412)


def test_csv_custom_mapping_and_helpful_errors(tmp_path):
    path = tmp_path / "proxy.csv"
    path.write_text("Logged;Client;Server;Svc\n1790000000;10.0.0.5;203.0.113.50;8443\n", encoding="utf-8")
    with pytest.raises(ValueError, match="couldn't find a column for ts, src, dst"):
        _read(path)
    (conn,), _ = _read(path, csv_map=csvlog.parse_map("ts=Logged,src=Client,dst=Server,dport=Svc"))
    assert (conn.ts, conn.dport) == (1790000000.0, 8443)
    with pytest.raises(ValueError, match="no column named"):
        _read(path, csv_map=csvlog.parse_map("ts=Nope,src=Client,dst=Server"))


# ---------------------------------------------------------------------- PCAP

def _ip4(a): return bytes(int(x) for x in a.split("."))


def _frame(src, dst, proto, sport, dport, flags=0, payload=b""):
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, _ip4(src), _ip4(dst)) + l4
    return b"\x00" * 12 + b"\x08\x00" + ip                          # Ethernet, IPv4


C, S = ("10.0.0.5", 51000), ("203.0.113.50", 443)
PACKETS = [
    (0.0, _frame(C[0], S[0], 6, C[1], S[1], 0x02)),                 # SYN
    (1.0, _frame(C[0], S[0], 6, C[1], S[1], 0x02)),                 # SYN retransmitted: same attempt
    (1.1, _frame(S[0], C[0], 6, S[1], C[1], 0x12)),                 # SYN-ACK
    (1.2, _frame(C[0], S[0], 6, C[1], S[1], 0x18, b"x" * 100)),     # data from the client
    (1.3, _frame(C[0], S[0], 6, C[1], S[1], 0x11)),                 # FIN
    (1.4, _frame(S[0], C[0], 6, S[1], C[1], 0x11)),                 # FIN
    (60.0, _frame(C[0], S[0], 6, 51004, S[1], 0x02)),               # a new attempt, never answered
    (5.0, b"\xff" * 14 + b"ARP!"),                                   # not IP: ignored
    (10.0, _frame(C[0], "10.0.0.1", 17, 123, 123, payload=b"n" * 48)),
    (10.1, _frame("10.0.0.1", C[0], 17, 123, 123, payload=b"n" * 48)),
    (200.0, _frame(C[0], "10.0.0.1", 17, 123, 123, payload=b"n" * 48)),  # > 60 s idle: a new UDP connection
]


def _write_pcap(path):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in sorted(PACKETS, key=lambda p: p[0]):
        out += struct.pack("<IIII", int(ts), int(round(ts % 1 * 1e6)), len(frame), len(frame)) + frame
    path.write_bytes(out)


def _write_pcapng(path):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HHB3x", 9, 1, 3) + struct.pack("<HH", 0, 0))
    for ts, frame in sorted(PACKETS, key=lambda p: p[0]):
        ticks = int(round(ts * 1000))                               # if_tsresol 3: milliseconds
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    path.write_bytes(out)


@pytest.mark.parametrize("writer", [_write_pcap, _write_pcapng], ids=["pcap", "pcapng"])
def test_capture_is_rebuilt_into_connections(tmp_path, writer):
    path = tmp_path / "capture.bin"
    writer(path)
    conns, stats = _read(path)
    assert sources.detect(path) == "pcap"
    assert stats.packets == len(PACKETS)
    tcp = [c for c in conns if c.proto == "tcp"]
    udp = [c for c in conns if c.proto == "udp"]
    assert [(c.ts, c.sport, c.orig_bytes, c.answered) for c in tcp] == [(0.0, 51000, 100, True), (60.0, 51004, 0, False)]
    assert [c.ts for c in udp] == [10.0, 200.0]
    assert all((c.src, c.dport) == (C[0], 123) for c in udp)


# ------------------------------------------------------- retries and the CLI

def test_tcp_retries_from_one_port_count_once_but_udp_is_left_alone():
    retries = [Conn(t, "a", "b", 50, "tcp", 0, sport=34144, answered=False) for t in (0, 7.2, 15.3, 32.0)]
    next_try = [Conn(80.0, "a", "b", 50, "tcp", 0, sport=34148, answered=False)]
    kept, merged = merge_retries(retries + next_try)
    assert [c.ts for c in kept] == [0, 80.0] and merged == 3
    ntp = [Conn(t, "a", "ntp", 123, "udp", 48, sport=123) for t in (0, 64, 128)]
    assert merge_retries(ntp) == (ntp, 0)


def test_cli_reads_mixed_formats_and_reports_packets(tmp_path, capsys):
    eve = tmp_path / "eve.json"
    eve.write_text("\n".join(json.dumps(dict(FLOW, flow=dict(FLOW["flow"], start=f"2026-10-04T12:{m:02d}:00+0000"),
                                             src_port=50000 + m)) for m in range(30)) + "\n", encoding="utf-8")
    cap = tmp_path / "capture.pcap"
    _write_pcap(cap)
    assert main([str(eve), str(cap), "--json"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)[0]["dst"] == "203.0.113.50"
    assert main([str(cap)]) == 0
    assert "rebuilt from 11 packets" in capsys.readouterr().err
