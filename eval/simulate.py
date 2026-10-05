"""Do folding and cycle detection help, and do they cost false positives?

Simulates beacons with different amounts of jitter and missed check-ins,
beacons that repeat a multi-step pattern, and several kinds of non-beacon
traffic. Counts how often each is called a timer (timing score >= 0.8) with
plain scoring and with beacon-hunter's full timing analysis. Seeded, so the
numbers in docs/evaluation.md come out the same every run.

    python eval/simulate.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beacon_hunter.scoring import ON_A_TIMER, analyze_timing  # noqa: E402

TRIALS = 500
CHECKINS = 200          # about 17 hours of a 5 minute beacon
PERIOD = 300.0


def beacon(rng, jitter, missed):
    times, t = [], 0.0
    for _ in range(CHECKINS):
        t += PERIOD * (1 + rng.uniform(-jitter, jitter))
        if rng.random() >= missed:
            times.append(t)
    return [b - a for a, b in zip(times, times[1:])]


def cyclic(rng, pattern, jitter=0.05):
    return [pattern[i % len(pattern)] * (1 + rng.uniform(-jitter, jitter)) for i in range(CHECKINS)]


def poisson(rng):
    return [rng.expovariate(1 / PERIOD) for _ in range(CHECKINS)]


def sessions(rng):
    """Bursts of quick requests separated by long idle stretches."""
    gaps = []
    while len(gaps) < CHECKINS:
        gaps += [rng.uniform(2, 30) for _ in range(rng.randint(2, 8))]
        gaps.append(rng.expovariate(1 / 1800))
    return gaps[:CHECKINS]


def uniform(rng):
    return [rng.uniform(10, 600) for _ in range(CHECKINS)]


def rate(gen, full, rng):
    hits = sum(analyze_timing(gen(rng), fold=full, cycles=full).score >= ON_A_TIMER for _ in range(TRIALS))
    return hits / TRIALS


def main():
    print(f"Share of {TRIALS} trials called a timer (timing >= {ON_A_TIMER}), "
          f"{CHECKINS} check-ins at {PERIOD:.0f}s.\n")
    print("| traffic | jitter | missed check-ins | plain | beacon-hunter |")
    print("|---|---|---|---|---|")
    for jitter in (0.1, 0.2, 0.3):
        for missed in (0.0, 0.15, 0.3, 0.45):
            plain = rate(lambda r: beacon(r, jitter, missed), False, random.Random(1))
            folded = rate(lambda r: beacon(r, jitter, missed), True, random.Random(1))
            print(f"| beacon | ±{jitter:.0%} | {missed:.0%} | {plain:.0%} | **{folded:.0%}** |")
    for name, pattern, jitter in (("cycle 7 / 8.5 / 17 / 48 s", [7.2, 8.5, 16.6, 47.9], 0.05),
                                  ("cycle 7 / 8.5 / 17 / 48 s", [7.2, 8.5, 16.6, 47.9], 0.15),
                                  ("cycle 3 / 7 s", [3.0, 7.0], 0.10),
                                  ("cycle 5 / 5 / 50 s", [5.0, 5.0, 50.0], 0.10)):
        plain = rate(lambda r: cyclic(r, pattern, jitter), False, random.Random(3))
        full = rate(lambda r: cyclic(r, pattern, jitter), True, random.Random(3))
        print(f"| {name} | ±{jitter:.0%} | 0% | {plain:.0%} | **{full:.0%}** |")
    for name, gen in (("random (Poisson)", poisson), ("browsing sessions", sessions),
                      ("uniform 10 to 600 s", uniform)):
        plain = rate(gen, False, random.Random(2))
        folded = rate(gen, True, random.Random(2))
        print(f"| {name} | - | - | {plain:.0%} | **{folded:.0%}** |")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
