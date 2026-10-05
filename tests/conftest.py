"""Helpers for building small synthetic conn.logs in tests."""

import random

import pytest

from beacon_hunter.zeek import Conn

FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "conn_state"]


def beacon(src, dst, port, start, interval, jitter, count, size=320, rng=None):
    """A host checking in every `interval` seconds, +/- `jitter` as a fraction."""
    rng = rng or random.Random(1)
    ts, out = start, []
    for _ in range(count):
        out.append(Conn(ts, src, dst, port, "tcp", size))
        ts += interval * (1 + rng.uniform(-jitter, jitter))
    return out


def random_traffic(src, dst, port, start, mean_gap, count, rng=None):
    """Human-ish traffic: random gaps and random sizes."""
    rng = rng or random.Random(2)
    ts, out = start, []
    for _ in range(count):
        out.append(Conn(ts, src, dst, port, "tcp", rng.randint(200, 40000)))
        ts += rng.expovariate(1 / mean_gap)
    return out


def write_tsv(path, conns):
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#path\tconn",
        "#fields\t" + "\t".join(FIELDS),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring",
    ]
    for n, c in enumerate(conns):
        size = "-" if c.orig_bytes is None else str(c.orig_bytes)
        port = "-" if c.dport is None else str(c.dport)
        sport = str(c.sport) if c.sport is not None else str(49152 + n % 16000)  # fresh port, as real clients use
        lines.append("\t".join([f"{c.ts:.6f}", f"C{n}", c.src, sport, c.dst, port, c.proto,
                                "-", "0.1", size, "100", "SF"]))
    lines.append("#close\t2026-10-04-00-00-00")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def rng():
    return random.Random(42)
