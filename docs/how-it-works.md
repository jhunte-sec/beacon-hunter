# How the scoring works

beacon-hunter groups connections by **source, destination, destination port and protocol**, then asks three questions about each group. Each answer is a number from 0 to 1.

## 1. Timing: does it check in on a timer?

Take the time between each check-in and the next. A person browsing produces gaps all over the place. An implant on a timer produces nearly the same gap every time, even when its operator adds random jitter.

Two measurements, both chosen because a few odd gaps (a laptop going to sleep, a dropped packet) don't throw them off the way an average would:

- **Regularity** = `1 - MAD / median`, where MAD is the median absolute deviation of the gaps.
  - A perfect 60-second timer: every gap is 60, MAD is 0, regularity is **1.0**.
  - 60 seconds with ±20% random jitter: gaps spread evenly between 48 and 72. Half of them sit within 6 s of 60, so MAD is about 6 and regularity is `1 - 6/60` = **0.9**.
  - Random human-like traffic (exponential gaps): MAD is about 0.69 of the median, so regularity is about **0.31**.
- **Symmetry** = `1 - |Bowley skew|`. Bowley skew compares the quartiles: `(Q3 + Q1 - 2·Q2) / (Q3 - Q1)`. Jitter added by an implant is usually symmetric around the interval (skew near 0). Random traffic has a long tail of big gaps (skew around 0.26).

`timing = 0.7 × regularity + 0.3 × symmetry`

### Bursts count as one check-in

Some implants open two or three connections per check-in. Counted separately, the gaps would alternate tiny, large, tiny, large, and the timer would disappear. So connections less than `--merge-window` seconds apart (default 1 s) are merged into a single check-in first.

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
- **Heavy jitter.** At ±50% jitter regularity drops to about 0.75. It still ranks above browsing, but the gap is smaller.
- **Domain fronting and shared infrastructure.** Grouping is by IP. A beacon to a big CDN shares its destination IP with legitimate traffic, which blurs the timing.
- **Anything not in conn.log.** It sees timing and sizes only. No payloads, no TLS details, no DNS names.
