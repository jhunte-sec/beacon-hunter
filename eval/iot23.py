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
            sport = row.get("id.orig_p", "-")
            state = row.get("conn_state", "-")
            conn = Conn(ts, row["id.orig_h"], row["id.resp_h"], dport, row["proto"],
                        int(size) if size.isdigit() else None,
                        sport=int(sport) if sport.isdigit() else None,
                        answered=None if state in ("-", "") else state != "S0")
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
    """Exactly the HTML report's "Worth a look" section: unexplained single-host timers, best first."""
    return sorted((f for f in findings if f.timing >= ON_A_TIMER and f.timer_hosts < FLEET and not f.service_hint),
                  key=lambda f: -f.score)


def best_rank(order, labels):
    ranks = [n for n, f in enumerate(order, 1) if key(f) in labels]
    return str(ranks[0]) if ranks else "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--show", type=int, default=0, help="list the top N pairs of each scenario")
    args = parser.parse_args()

    variants = {
        "plain": Settings(fold=False, cycles=False, merge_retries=False),
        "retries": Settings(fold=False, cycles=False, merge_retries=True),
        "cycles": Settings(fold=False, cycles=True, merge_retries=False),
    }
    runs = []
    for path in args.logs:
        conns, labels = read_labeled(path)
        name = path.name.split(".")[0]
        full = analyze(conns, Settings())
        others = {v: {key(f): f for f in analyze(conns, s)} for v, s in variants.items()}
        runs.append((name, conns, labels, full, others))

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
    print("Timing score of every scorable C&C pair with each technique alone, then all together.")
    print()
    print("| scenario | C&C destination | log records | attempts | plain | retry merging only | "
          "cycle detection only | beacon-hunter | what the report says |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, _, labels, full, others in runs:
        for f in full:
            if key(f) in labels:
                plain = others["plain"].get(key(f))
                cells = [f"{others[v][key(f)].timing:.2f}" if key(f) in others[v] else "-"
                         for v in ("plain", "retries", "cycles")]
                print(f"| {name} ({FAMILY.get(name, '?')}) | {destination(f)} | {plain.connections:,} | "
                      f"{f.connections:,} | {' | '.join(cells)} | **{f.timing:.2f}** | {f.reasons[0]} |")

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
