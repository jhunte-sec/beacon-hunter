"""Command line entry point: beacon-hunter LOG [more logs...]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, allowlist, csvlog
from . import html_report
from .report import explained, table, to_json
from .scoring import Settings, analyze
from .sources import FORMATS, read_all
from .zeek import ReadStats


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="beacon-hunter",
        description="Find machines that check in with the same server on a timer (C2 beaconing).",
        epilog="Reads Zeek conn.log, Suricata eve.json, Sysmon network events (JSON, XML or .evtx), "
               "CSV exports and pcap/pcapng captures. The format is detected from each file's content.",
    )
    p.add_argument("logs", nargs="+", help="log files or packet captures (.gz is fine)")
    p.add_argument("--format", choices=FORMATS, default="auto", help="skip detection and read every file as this")
    p.add_argument("--csv-map", metavar="MAP",
                   help='CSV column names, e.g. "ts=Log Time,src=Client,dst=Server,dport=Port"')
    p.add_argument("--top", type=int, default=20, help="show this many results (default 20, 0 for all)")
    p.add_argument("--min-score", type=float, default=0.0, help="hide results below this score")
    p.add_argument("--min-events", type=int, default=10, help="check-ins needed before a pair is scored (default 10)")
    p.add_argument("--merge-window", type=float, default=1.0,
                   help="connections closer than this many seconds count as one check-in (default 1.0)")
    p.add_argument("--slices", type=int, default=24,
                   help="persistence: split the capture into this many time slices (default 24)")
    p.add_argument("--no-port", action="store_true", help="group by host pair only, ignoring destination port")
    p.add_argument("--allowlist", help="file of destinations to ignore (see examples/allowlist.txt)")
    p.add_argument("--no-retry-merge", action="store_true",
                   help="count every log record, instead of counting retries of one TCP connection once")
    p.add_argument("--no-fold", action="store_true",
                   help="score gaps at face value instead of forgiving missed check-ins")
    p.add_argument("--no-cycles", action="store_true",
                   help="don't look for repeating multi-step patterns")
    p.add_argument("--include-multicast", action="store_true", help="also score multicast and broadcast destinations")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.add_argument("--explain", action="store_true", help="after the table, write out the reasons for each result")
    p.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report to FILE")
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
        fold=not args.no_fold,
        cycles=not args.no_cycles,
        merge_retries=not args.no_retry_merge,
    )
    try:
        if args.allowlist:
            settings.allow = allowlist.load(args.allowlist)
        csv_map = csvlog.parse_map(args.csv_map)
        stats = ReadStats()
        findings = analyze(read_all(args.logs, args.format, stats, csv_map), settings)
    except (OSError, ValueError) as exc:
        print(f"beacon-hunter: {exc}", file=sys.stderr)
        return 2

    findings = [f for f in findings if f.score >= args.min_score]

    # The HTML report sorts everything into sections itself, so it gets the lot.
    if args.html:
        page = html_report.render(findings, args.logs, stats.rows, stats.skipped, settings)
        Path(args.html).write_text(page, encoding="utf-8")

    if args.top > 0:
        findings = findings[: args.top]

    if args.json:
        print(to_json(findings))
    else:
        print(table(findings))
        if args.explain and findings:
            print("\n" + explained(findings))
        if args.html:
            print(f"\nHTML report written to {args.html}")
        sys.stdout.flush()
        source = f" rebuilt from {stats.packets:,} packets" if stats.packets else " read"
        print(f"\n{stats.rows:,} connections{source}, {stats.skipped:,} skipped as malformed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
