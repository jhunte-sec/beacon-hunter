# How the scoring works

beacon-hunter groups connections by **source, destination, destination port and protocol**, then asks three questions about each group. Each answer is a number from 0 to 1.

## 1. Timing: does it check in on a timer?

Take the time between each check-in and the next. A person browsing produces gaps all over the place. An implant on a timer produces nearly the same gap every time, even when its operator adds random jitter.

Two measurements, both chosen because a few odd gaps (a laptop going to sleep, a dropped packet) don't throw them off the way an average would:

- **Regularity** = `1 - MAD / median`, where MAD is the median absolute deviation of the gaps.
  - A perfect 60-second timer: every gap is 60, MAD is 0, regularity is **1.0**.
  - 60 seconds with ±20% random jitter: gaps spread evenly between 48 and 72. Half of them sit within 6 s of 60, so MAD is about 6 and regularity is `1 - 6/60` = **0.9**.
  - Random human-like traffic (exponential gaps): MAD is about 0.69 of the median, so regularity is about **0.31**.
- **Symmetry** = `1 - |Bowley skew|`. Bowley skew compares the quartiles: `(Q3 + Q1 - 2·Q2) / (Q3 - Q1)`. Jitter added by an implant is usually symmetric around the interval (skew near 0). Random traffic has a long tail of big gaps (skew around 0.26). On a near-perfect timer the quartiles sit milliseconds apart and their skew is rounding noise, so the penalty is phased in as the middle half of the gaps widens, reaching full weight at 10% of the median.

`timing = 0.7 × regularity + 0.3 × symmetry`

### Bursts count as one check-in

Some implants open two or three connections per check-in. Counted separately, the gaps would alternate tiny, large, tiny, large, and the timer would disappear. So connections less than `--merge-window` seconds apart (default 1 s) are merged into a single check-in first.

### Missed check-ins are folded back onto the timer

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/missed-checkins-dark.svg">
  <img alt="A one-minute timer that missed three check-ins: the gaps are whole multiples of one minute" src="img/missed-checkins-light.svg" width="760">
</picture>

Real beacons miss beats: a laptop sleeps, a packet drops. A 60-second timer then produces gaps like 60, 60, 120, 60, 180, and the regularity measure above reads that as irregular. So beacon-hunter also tries this:

1. **Estimate the base period** from the shortest gaps: the median of every gap up to 1.5 × the lower quartile.
2. **Fold** every gap that sits close to a whole multiple of it (up to 4×) back down: 120 becomes 2 × 60, 180 becomes 3 × 60. "Close" is ±15% of the period, widened up to ±35% when the shortest gaps are themselves jittery.
3. **Score the folded gaps** with the same timing formula, then multiply by the share of gaps that fit. Traffic that only half lines up gets only half the credit.

The higher of the plain and folded scores wins. The report then says roughly what share of expected check-ins was missing.

Why this doesn't flag random traffic: random gaps rarely land near whole multiples of anything, so few of them fold and the multiplier keeps the score down. In the simulation study (docs/evaluation.md) it raised detection of beacons with 30% missed check-ins from under 10% to 78 to 100%, and added zero false positives across 1,500 non-beacon trials. `--no-fold` turns it off.

### Repeating cycles are found as a whole

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/cycle-dark.svg">
  <img alt="Hakai malware's real retry loop: waits of 7, 8, 17 and 48 seconds repeat every 80 seconds" src="img/cycle-light.svg" width="760">
</picture>

Some implants don't wait a fixed time; they repeat a fixed *sequence*. Hakai's C2 in the IoT-23 captures waits 7.2, 8.5, 16.6 and 47.9 seconds, then starts over, 1,027 times. Each gap on its own looks scattered (timing 0.65), but two things give it away:

- **Every gap matches the one k places later.** Compare each gap with the gap 2, 3, ... 6 places further on. For a cycle of k steps, they match: the median relative difference is close to 0. Random gaps don't match their neighbours at any distance (for random traffic the median relative difference is around 0.5 to 0.67).
- **Every k-th connection lands a constant time after the last.** The sum of k consecutive gaps is the cycle length, 80 s for Hakai, and those sums are as regular as an ordinary timer.

beacon-hunter needs the first test to pass (median relative difference ≤ 0.15) before it scores the k-step sums as the timer. The order matters: sums of random gaps also get smoother as k grows, so scoring the sums on their own would flag random traffic. The recurrence test doesn't have that problem. A cycle is only claimed with at least 30 gaps, a pattern that genuinely varies (the longest step at least 1.3× the shortest), and a cycle steady enough to score as a timer. The report then spells it out: "repeats a 4-connection cycle every 1m20s (waits 7s, 8s, 17s, 48s, then starts over)". `--no-cycles` turns it off.

## 2. Size: does each check-in send about the same amount?

A check-in that has nothing new to report sends the same small request every time. Using the bytes the source sent (`orig_bytes`):

`size = 0.5 × regularity(bytes) + 0.5 × share of check-ins that sent the single most common size`

If fewer than half the connections have a byte count (some protocols and some logs don't record it), this score is left out instead of guessed.

## 3. Persistence: does it keep going?

The capture is cut into `--slices` equal time slices (default 24, so hours for a day of logs). Persistence is the share of slices in which the pair was active. A beacon runs all day, so it scores 1.0. A two-minute burst scores 1/24.

This is measured against the whole capture, not just the pair's own lifetime. A beacon that started halfway through the day scores 0.5. That's on purpose: it keeps one-off bursts from looking persistent. The trade-off is that a fresh infection late in the capture ranks lower than it should.

## Final score

A weighted average: **timing 0.5, persistence 0.3, size 0.2**. When the size score is missing, the other two are re-weighted so they still add up to 1.

The number is for ranking, not a verdict. Always read the three parts. A high timing score with a low size score means "regular, but different amounts each time", which looks more like polling an API than an implant asking for orders.

## What it will flag that isn't malicious

Plenty of legitimate software runs on a timer. Expect to see:

- NTP time sync, DNS resolvers, SIEM and EDR agent heartbeats
- update checkers, licence checks, cloud sync clients
- monitoring and health checks, and IoT devices calling home

This is what the allowlist is for. Building one for your own network is part of using the tool, the same way tuning is part of any detection.

## What it will miss

- **Beacons with very long sleeps.** Ten check-ins (the default `--min-events`) at a 6-hour interval needs more than two days of logs.
- **Heavy jitter plus missed check-ins.** At ±30% jitter with 45% of check-ins missed, the multiples blur together and only about a fifth are recovered (see docs/evaluation.md).
- **Domain fronting and shared infrastructure.** Grouping is by IP. A beacon to a big CDN shares its destination IP with legitimate traffic, which blurs the timing.
- **One long-lived connection.** C2 that holds a session open instead of checking in is a single log line.
- **Anything not in conn.log.** It sees timing and sizes only. No payloads, no TLS details, no DNS names.
