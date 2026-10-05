"""Check the pcap reader against Zeek on the same capture.

IoT-23 publishes both the raw packets and Zeek's conn.log for each capture,
so beacon-hunter's own connection tracker can be compared with Zeek's output
conversation by conversation.

    python eval/pcap_vs_zeek.py eval/data/CTU-IoT-Malware-Capture-8-1.pcap \\
        eval/data/CTU-IoT-Malware-Capture-8-1.conn.log.labeled
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_hunter import pcap  # noqa: E402
from beacon_hunter.scoring import analyze, merge_retries  # noqa: E402
from beacon_hunter.zeek import ReadStats, read_conn_log  # noqa: E402


def by_pair(conns):
    groups = defaultdict(list)
    for c in conns:
        groups[(c.src, c.dst, c.dport, c.proto)].append(c)
    return groups


def main(capture: str, conn_log: str) -> int:
    stats = ReadStats()
    rebuilt = list(pcap.read(Path(capture), stats))
    logged = list(read_conn_log(Path(conn_log)))
    ours, zeek = by_pair(rebuilt), by_pair(logged)

    print(f"{stats.packets:,} packets -> {len(rebuilt):,} connections rebuilt; "
          f"Zeek logged {len(logged):,} records.\n")
    print("| conversation | Zeek records | Zeek attempts (retries merged) | pcap reader | match |")
    print("|---|---|---|---|---|")
    matched = 0
    for key in sorted(set(ours) | set(zeek), key=lambda k: -len(zeek.get(k, []))):
        records = len(zeek.get(key, []))
        attempts = len(merge_retries(zeek[key])[0]) if key in zeek else 0
        mine = len(merge_retries(ours[key])[0]) if key in ours else 0
        same = attempts == mine
        matched += same
        src, dst, port, proto = key
        print(f"| {src} → {dst}:{port}/{proto} | {records:,} | {attempts:,} | {mine:,} | {'yes' if same else 'NO'} |")
    total = len(set(ours) | set(zeek))
    print(f"\n{matched} of {total} conversations match.")

    print("\nTop findings from each source:\n")
    for name, conns in (("Zeek conn.log", logged), ("pcap reader", rebuilt)):
        for f in analyze(conns)[:3]:
            print(f"  {name:13s}  {f.dst}:{f.dport}/{f.proto}  every {f.period:.1f}s  timing {f.timing:.2f}")
    return 0 if matched == total else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(*sys.argv[1:3]))
