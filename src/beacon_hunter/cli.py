"""Command line entry point: beacon-hunter conn.log [more logs...]"""

from __future__ import annotations

import argparse
import sys

from . import __version__, allowlist
from .report import table, to_json
from .scoring import Settings, analyze
from .zeek import ReadStats, read_conn_logs


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="beacon-hunter",
        description="Rank host pairs in Zeek conn.log files by how much they look like C2 beaconing.",
    )
    p.add_argument("logs", nargs="+", help="conn.log files (TSV or JSON, .gz is fine)")
    p.add_argument("--top", type=int, default=20, help="show this many results (default 20, 0 for all)")
    p.add_argument("--min-score", type=float, default=0.0, help="hide results below this score")
    p.add_argument("--min-events", type=int, default=10, help="check-ins needed before a pair is scored (default 10)")
    p.add_argument("--merge-window", type=float, default=1.0,
                   help="connections closer than this many seconds count as one check-in (default 1.0)")
    p.add_argument("--slices", type=int, default=24,
                   help="persistence: split the capture into this many time slices (default 24)")
    p.add_argument("--no-port", action="store_true", help="group by host pair only, ignoring destination port")
    p.add_argument("--allowlist", help="file of destinations to ignore (see examples/allowlist.txt)")
    p.add_argument("--include-multicast", action="store_true", help="also score multicast and broadcast destinations")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    settings = Settings(
        min_events=args.min_events,
        merge_window=args.merge_window,
        slices=args.slices,
        by_port=not args.no_port,
        include_multicast=args.include_multicast,
    )
    if args.allowlist:
        try:
            settings.allow = allowlist.load(args.allowlist)
        except (OSError, ValueError) as exc:
            print(f"beacon-hunter: {exc}", file=sys.stderr)
            return 2

    stats = ReadStats()
    try:
        findings = analyze(read_conn_logs(args.logs, stats), settings)
    except (OSError, ValueError) as exc:
        print(f"beacon-hunter: {exc}", file=sys.stderr)
        return 2

    findings = [f for f in findings if f.score >= args.min_score]
    if args.top > 0:
        findings = findings[: args.top]

    if args.json:
        print(to_json(findings))
    else:
        print(table(findings))
        print(f"\n{stats.rows} connections read, {stats.skipped} skipped as malformed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
