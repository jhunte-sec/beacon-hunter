"""Destinations you already know are fine (NTP, your SIEM, update servers).

One entry per line, matched against the destination of each connection:

    10.0.0.53            a single host, any port
    10.0.0.0/8           a network, any port
    10.0.0.20:1514       a host on one port
    10.0.0.0/8:1514      a network on one port
    *:123                any host on one port
    # comments and blank lines are ignored
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class Entry:
    network: Optional[Network]   # None means any host
    port: Optional[int]          # None means any port

    def matches(self, dst: str, dport: Optional[int]) -> bool:
        if self.port is not None and dport != self.port:
            return False
        if self.network is None:
            return True
        try:
            return ipaddress.ip_address(dst) in self.network
        except ValueError:
            return False


def parse_entry(text: str) -> Entry:
    text = text.strip()
    host, port = text, None
    # Only treat a trailing ":N" as a port when the host part isn't bare IPv6.
    if text.count(":") == 1 or (text.startswith("[") and "]:" in text):
        host, _, port_text = text.rpartition(":")
        host = host.strip("[]")
        port = int(port_text)
    network = None if host == "*" else ipaddress.ip_network(host, strict=False)
    return Entry(network, port)


def load(path: Union[str, Path]) -> list[Entry]:
    entries = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            entries.append(parse_entry(line))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: can't read allowlist entry {line!r} ({exc})") from None
    return entries


def is_allowed(entries: Iterable[Entry], dst: str, dport: Optional[int]) -> bool:
    return any(entry.matches(dst, dport) for entry in entries)
