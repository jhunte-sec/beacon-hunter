"""Measure beacon-hunter against the labeled IoT-23 Zeek logs.

IoT-23 (Stratosphere Laboratory, CTU Prague, CC BY) labels every connection in
real malware captures. Labels starting with "C&C" mark command-and-control
traffic, which is what a beacon detector should rank near the top.

For each scenario this prints how the C&C pairs ranked among every pair that
had enough check-ins to be scored, with and without missed-check-in folding.

    python eval/iot23.py eval/data/*.labeled
    python eval/iot23.py eval/data/*.labeled --show 8     # also list the top 8 pairs

Download the logs first; see eval/README.md.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_hunter.html_report import FLEET  # noqa: E402
from beacon_hunter.report import destination  # noqa: E402
from beacon_hunter.scoring import ON_A_TIMER, Settings, analyze  # noqa: E402
from beacon_hunter.zeek import Conn  # noqa: E402


def read_labeled(path: Path):
    """IoT-23 appends 'label' and 'detailed-label' after the normal fields, but
    separates those last columns with spaces instead of tabs."""
    fields = None
    conns, labels = [], defaultdict(set)
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.startswith("#fields"):
                names = line.split("\t")[1:]
                fields = names[:-1] + names[-1].split()
                continue
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            row = dict(zip(fields, cols[:-1] + cols[-1].split()))
            try:
                ts = float(row["ts"])
                dport = int(row["id.resp_p"])
            except (KeyError, ValueError):
                continue
            size = row.get("orig_bytes", "-")
            conn = Conn(ts, row["id.orig_h"], row["id.resp_h"], dport, row["proto"],
                        int(size) if size.isdigit() else None)
            conns.append(conn)
            # The 2019 files call it "detailed-label"; scenario 34-1, re-published in 2023, says "det_label".
            detail = row.get("detailed-label", row.get("det_label", "-"))
            if row.get("label", "").lower() == "malicious" and detail.startswith("C&C"):
                labels[(conn.src, conn.dst, conn.dport, conn.proto)].add(detail)
    return conns, labels


FAMILY = {
    "CTU-IoT-Malware-Capture-3-1": "Muhstik", "CTU-IoT-Malware-Capture-8-1": "Hakai",
    "CTU-IoT-Malware-Capture-20-1": "Torii", "CTU-IoT-Malware-Capture-21-1": "Torii",
    "CTU-IoT-Malware-Capture-34-1": "Mirai", "CTU-IoT-Malware-Capture-42-1": "Trojan",
    "CTU-IoT-Malware-Capture-44-1": "Mirai", "CTU-Honeypot-Capture-4-1": "Philips Hue (benign)",
    "CTU-Honeypot-Capture-5-1": "Amazon Echo (benign)",
}


def key(f):
    return (f.src, f.dst, f.dport, f.proto)


def report_order(findings):
    """Unknown services before known timer services, as the HTML report lists them."""
    return sorted(findings, key=lambda f: (f.service_hint is not None, -f.score))


def worth_a_look(findings):
    """Exactly the HTML report's "Worth a look" section, in its order."""
    return report_order([f for f in findings if f.timing >= ON_A_TIMER and f.timer_hosts < FLEET])


def best_rank(order, labels):
    ranks = [n for n, f in enumerate(order, 1) if key(f) in labels]
    return str(ranks[0]) if ranks else "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--show", type=int, default=0, help="list the top N pairs of each scenario")
    args = parser.parse_args()

    runs = []
    for path in args.logs:
        conns, labels = read_labeled(path)
        name = path.name.split(".")[0]
        full = analyze(conns, Settings())
        plain = {key(f): f for f in analyze(conns, Settings(fold=False, cycles=False))}
        runs.append((name, conns, labels, full, plain))

    print("| scenario | family | connections | pairs scored | C&C pairs | C&C pairs scorable | "
          "best C&C rank by raw score | C&C called a timer | place in \"worth a look\" |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, conns, labels, full, _ in runs:
        scorable = sum(key(f) in labels for f in full)
        timers = sum(key(f) in labels and f.timing >= ON_A_TIMER for f in full)
        look = worth_a_look(full)
        print(f"| {name} | {FAMILY.get(name, '?')} | {len(conns):,} | {len(full)} | {len(labels)} | {scorable} | "
              f"{best_rank(full, labels)} | {timers} of {scorable} | "
              f"{best_rank(look, labels)}{f' of {len(look)}' if timers else ''} |")

    print()
    print("| scenario | C&C destination | connections | timing, plain | timing, beacon-hunter | what the report says |")
    print("|---|---|---|---|---|---|")
    for name, _, labels, full, plain in runs:
        for f in full:
            if key(f) in labels:
                p = plain.get(key(f))
                print(f"| {name} ({FAMILY.get(name, '?')}) | {destination(f)} | {f.connections:,} | "
                      f"{p.timing:.2f} | **{f.timing:.2f}** | {f.reasons[0]} |")

    for name, _, labels, full, _ in runs:
        if args.show <= 0:
            break
        print(f"\n{name} ({FAMILY.get(name, '?')}): top {args.show} in report order")
        for f in report_order(full)[: args.show]:
            tag = ", ".join(sorted(labels.get(key(f), ()))) or "not C&C"
            hint = f" ({f.service_hint})" if f.service_hint else ""
            print(f"  {f.score:.2f}  {f.src} -> {destination(f)}{hint}  every {f.period:.0f}s  "
                  f"timing {f.timing:.2f}  [{tag}]")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
