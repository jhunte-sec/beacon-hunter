"""Rebuild connections from a packet capture (.pcap or .pcapng).

This is a small connection tracker in pure Python, built to produce the same
connections Zeek's conn.log would for beacon timing:

  * TCP: a connection starts with the first packet of a new conversation (a
    SYN, normally), and the side that sent the SYN is the originator. SYN
    retransmissions stay part of the same attempt. FIN from both sides or a
    RST closes it; 5 minutes of silence also ends it (Zeek's default).
  * UDP and ICMP have no handshake: a conversation is one connection until it
    has been idle for a minute (Zeek's default), and whoever spoke first is
    the originator. As in Zeek, ICMP's "port" is the ICMP code.
  * orig_bytes counts the payload the originator sent.

Supported link types: Ethernet (with VLAN tags), Linux cooked capture (v1 and
v2), raw IP and BSD loopback. IPv4 and IPv6, including extension headers.
Fragments after the first are skipped. Everything else is counted as skipped.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from .zeek import Conn, ReadStats

TCP_IDLE = 300.0
UDP_IDLE = 60.0

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

ETHERNET, RAW, RAW_ALT, LOOP, LINUX_SLL, LINUX_SLL2, IPV4_LT, IPV6_LT = 1, 101, 12, 0, 113, 276, 228, 229


def is_capture(head: bytes) -> bool:
    return head[:4] in PCAP_MAGIC or head[:4] == PCAPNG_MAGIC


# ------------------------------------------------------------ file formats

def packets(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    """(timestamp, link type, frame bytes) for every packet in the file."""
    head = fh.read(4)
    if head in PCAP_MAGIC:
        yield from _pcap(fh, head)
    elif head == PCAPNG_MAGIC:
        yield from _pcapng(fh, head)
    else:
        raise ValueError("not a pcap or pcapng file")


def _pcap(fh: BinaryIO, magic: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian, unit = PCAP_MAGIC[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        return
    linktype = struct.unpack(endian + "I", rest[16:20])[0] & 0x0FFFFFFF
    record = struct.Struct(endian + "IIII")
    while True:
        hdr = fh.read(16)
        if len(hdr) < 16:
            return
        sec, frac, caplen, _ = record.unpack(hdr)
        data = fh.read(caplen)
        if len(data) < caplen:
            return  # truncated file: stop cleanly
        yield sec + frac * unit, linktype, data


def _pcapng(fh: BinaryIO, first: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []   # (link type, seconds per tick)
    block_type = first
    while True:
        if len(block_type) < 4:
            return
        raw_len = fh.read(4)
        if len(raw_len) < 4:
            return
        if block_type == PCAPNG_MAGIC:
            body_start = fh.read(4)
            endian = "<" if body_start == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", raw_len)[0]
            fh.read(length - 12)
            interfaces = []                     # a new section starts a new interface list
        else:
            btype = struct.unpack(endian + "I", block_type)[0]
            length = struct.unpack(endian + "I", raw_len)[0]
            if length < 12:
                return
            body = fh.read(length - 12)
            fh.read(4)                          # trailing length
            if btype == 1:                      # Interface Description Block
                linktype = struct.unpack(endian + "H", body[:2])[0]
                interfaces.append((linktype, _tsresol(body[8:], endian)))
            elif btype in (6, 2) and len(body) >= 20:   # Enhanced / obsolete Packet Block
                if btype == 6:
                    iface, hi, lo, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
                else:
                    iface, _, hi, lo, caplen, _ = struct.unpack(endian + "HHIIII", body[:20])
                if iface < len(interfaces):
                    linktype, tick = interfaces[iface]
                    yield ((hi << 32) | lo) * tick, linktype, body[20:20 + caplen]
            # Simple Packet Blocks carry no timestamp, so they are no use for timing.
        block_type = fh.read(4)


def _tsresol(options: bytes, endian: str) -> float:
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[i:i + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + ((length + 3) & ~3)
    return 1e-6


# ---------------------------------------------------------------- decoding

@dataclass
class Packet:
    src: str
    dst: str
    proto: str
    sport: Optional[int]
    dport: Optional[int]
    flags: int
    payload: int


def decode(linktype: int, frame: bytes) -> Optional[Packet]:
    ip = _strip_link(linktype, frame)
    if ip is None or len(ip) < 1:
        return None
    version = ip[0] >> 4
    if version == 4:
        return _ipv4(ip)
    if version == 6:
        return _ipv6(ip)
    return None


def _strip_link(linktype: int, frame: bytes) -> Optional[bytes]:
    if linktype == ETHERNET:
        if len(frame) < 14:
            return None
        ethertype, off = struct.unpack("!H", frame[12:14])[0], 14
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
            ethertype, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        return frame[off:] if ethertype in (0x0800, 0x86DD) else None
    if linktype == LINUX_SLL:
        return frame[16:] if len(frame) >= 16 and frame[14:16] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == LINUX_SLL2:
        return frame[20:] if len(frame) >= 20 and frame[0:2] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype in (RAW, RAW_ALT, IPV4_LT, IPV6_LT):
        return frame
    if linktype == LOOP:
        return frame[4:]
    return None


def _ipv4(ip: bytes) -> Optional[Packet]:
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0] or len(ip)   # 0 in captures taken with TCP offload
    frag = struct.unpack("!H", ip[6:8])[0]
    if frag & 0x1FFF:
        return None  # not the first fragment: no transport header
    src, dst = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
    return _transport(ip[9], src, dst, ip[ihl:], max(0, total - ihl))


def _ipv6(ip: bytes) -> Optional[Packet]:
    if len(ip) < 40:
        return None
    payload_len = struct.unpack("!H", ip[4:6])[0]
    nxt, off = ip[6], 40
    src, dst = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
    while nxt in (0, 43, 44, 51, 60) and len(ip) >= off + 8:
        if nxt == 44:                                   # fragment header
            if struct.unpack("!H", ip[off + 2:off + 4])[0] & 0xFFF8:
                return None
            ext = 8
        elif nxt == 51:                                 # authentication header
            ext = (ip[off + 1] + 2) * 4
        else:
            ext = (ip[off + 1] + 1) * 8
        nxt, off = ip[off], off + ext
    return _transport(nxt, src, dst, ip[off:], max(0, payload_len - (off - 40)))


def _transport(proto: int, src: str, dst: str, l4: bytes, l4_len: int) -> Optional[Packet]:
    if proto == 6 and len(l4) >= 14:
        sport, dport = struct.unpack("!HH", l4[:4])
        header = (l4[12] >> 4) * 4
        return Packet(src, dst, "tcp", sport, dport, l4[13], max(0, l4_len - header))
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return Packet(src, dst, "udp", sport, dport, 0, max(0, l4_len - 8))
    if proto in (1, 58) and len(l4) >= 2:
        return Packet(src, dst, "icmp", l4[0], l4[1], 0, max(0, l4_len - 8))
    return None


# ------------------------------------------------------------- connections

@dataclass
class _Conn:
    start: float
    last: float
    orig: tuple
    resp: tuple
    proto: str
    sent: int = 0
    replies: int = 0
    fin_orig: bool = False
    fin_resp: bool = False
    closed: bool = False

    def to_conn(self) -> Conn:
        sport = self.orig[1] if self.proto != "icmp" else None
        return Conn(self.start, self.orig[0], self.resp[0], self.resp[1], self.proto, self.sent, sport=sport,
                    answered=self.replies > 0)


def connections(fh: BinaryIO, stats: ReadStats) -> list[Conn]:
    active: dict[tuple, _Conn] = {}
    done: list[Conn] = []
    for ts, linktype, frame in packets(fh):
        stats.packets += 1
        pkt = decode(linktype, frame)
        if pkt is None:
            continue  # ARP, other protocols, later fragments: not connection traffic
        a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        if pkt.proto == "icmp":
            a, b = (pkt.src, None), (pkt.dst, None)   # ICMP pairs by host, not type/code
        key = (pkt.proto,) + tuple(sorted([a, b], key=str))
        conn = active.get(key)

        idle = TCP_IDLE if pkt.proto == "tcp" else UDP_IDLE
        syn_only = pkt.proto == "tcp" and pkt.flags & 0x02 and not pkt.flags & 0x10
        if conn is not None and (conn.closed or ts - conn.last > idle
                                 or (syn_only and conn.fin_orig and conn.fin_resp)):
            done.append(conn.to_conn())
            conn = None
        if conn is None:
            # The originator is whoever starts; a SYN-ACK seen first means we missed the SYN.
            synack = pkt.proto == "tcp" and pkt.flags & 0x12 == 0x12
            orig, resp = (b, a) if synack else (a, b)
            # No handshake seen (the capture started mid-conversation): as Zeek does,
            # assume the side on a well-known port is the server.
            if not syn_only and not synack and pkt.proto != "icmp" and \
                    pkt.sport is not None and pkt.dport is not None and pkt.sport < 1024 <= pkt.dport:
                orig, resp = b, a
            if pkt.proto == "icmp":
                resp = (pkt.dst, pkt.dport)            # as in Zeek: resp_p is the ICMP code
            conn = active[key] = _Conn(ts, ts, orig, resp, pkt.proto)

        conn.last = ts
        from_orig = pkt.src == conn.orig[0] and (pkt.proto == "icmp" or pkt.sport == conn.orig[1])
        if from_orig:
            conn.sent += pkt.payload
        else:
            conn.replies += 1
        if pkt.proto == "tcp":
            if pkt.flags & 0x04:
                conn.closed = True
            if pkt.flags & 0x01:
                if from_orig:
                    conn.fin_orig = True
                else:
                    conn.fin_resp = True
    done.extend(c.to_conn() for c in active.values())
    done.sort(key=lambda c: c.ts)
    stats.rows += len(done)
    return done


def read(path: Path, stats: ReadStats) -> Iterator[Conn]:
    with open(path, "rb") as fh:
        yield from connections(fh, stats)
