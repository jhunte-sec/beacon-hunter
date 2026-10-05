"""Write a synthetic 24-hour Zeek conn.log for trying beacon-hunter out.

Everything in it is made up. It contains one planted beacon plus the kind of
regular-but-harmless traffic that causes false positives on real networks:

  10.0.20.15 -> 203.0.113.50:443   the planted beacon, every ~5 min with 15% jitter
  10.0.20.15 -> 10.0.0.1:123       NTP sync, every 1024 s
  every host -> 10.0.0.20:1514     SIEM agent keepalive, every 60 s
  10.0.20.22 -> 192.0.2.80:443     hourly software update check
  10.0.20.30 -> 198.51.100.99:445  a two-minute burst, then nothing
  plus random web browsing and DNS lookups

Usage:  python examples/make_demo_log.py demo-conn.log
"""

import random
import sys

START = 1_790_000_000.0  # an arbitrary day
DAY = 86_400
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "conn_state"]
HOSTS = ["10.0.20.15", "10.0.20.22", "10.0.20.30", "10.0.20.41"]


def timer(src, dst, port, proto, interval, jitter, size, rng, start=START, end=START + DAY):
    ts = start + rng.uniform(0, interval)
    while ts < end:
        yield ts, src, dst, port, proto, size(rng)
        ts += interval * (1 + rng.uniform(-jitter, jitter))


def random_arrivals(src, dst, port, proto, mean_gap, size, rng, start=START, end=START + DAY):
    ts = start + rng.expovariate(1 / mean_gap)
    while ts < end:
        yield ts, src, dst, port, proto, size(rng)
        ts += rng.expovariate(1 / mean_gap)


def build(rng):
    rows = []
    rows += timer("10.0.20.15", "203.0.113.50", 443, "tcp", 300, 0.15, lambda r: r.choice([412, 412, 412, 428]), rng)
    rows += timer("10.0.20.15", "10.0.0.1", 123, "udp", 1024, 0.0, lambda r: 48, rng)
    for host in HOSTS:
        rows += timer(host, "10.0.0.20", 1514, "tcp", 60, 0.02, lambda r: r.randint(60, 90), rng)
        rows += random_arrivals(host, "10.0.0.53", 53, "udp", 45, lambda r: r.randint(30, 70), rng)
    rows += timer("10.0.20.22", "192.0.2.80", 443, "tcp", 3600, 0.01, lambda r: 1830, rng)

    burst_start = START + 9 * 3600
    rows += timer("10.0.20.30", "198.51.100.99", 445, "tcp", 1.2, 0.3, lambda r: 0, rng,
                  start=burst_start, end=burst_start + 120)

    sites = [f"198.51.100.{n}" for n in range(10, 40)]
    for host in HOSTS:
        for site in rng.sample(sites, 12):
            rows += random_arrivals(host, site, 443, "tcp", rng.choice([600, 1800, 5400]),
                                    lambda r: r.randint(300, 60000), rng)
    rows.sort()
    return rows


def main(path):
    rng = random.Random(2026)
    rows = build(rng)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(FIELDS) + "\n")
        fh.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n")
        for n, (ts, src, dst, port, proto, size) in enumerate(rows):
            fh.write("\t".join([f"{ts:.6f}", f"CDEMO{n:06d}", src, str(rng.randint(49152, 65535)),
                                dst, str(port), proto, "-", f"{rng.uniform(0.01, 2):.3f}",
                                str(size), str(rng.randint(0, 5000)), "SF"]) + "\n")
    print(f"wrote {len(rows)} connections to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-conn.log")
