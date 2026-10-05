# Evaluation

Two questions, answered separately:

1. **Does the missed-check-in folding actually help, and what does it cost?** Answered by simulation, where the ground truth is known exactly.
2. **Does it find real command-and-control traffic?** Answered on IoT-23, a public dataset of real malware captures with every connection labeled.

## 1. Simulation: folding missed check-ins

Real beacons don't hit every beat. Laptops sleep, packets drop, implants stall. A 5-minute beacon that misses some check-ins produces gaps of 5, 5, 10, 5, 15 minutes, and the usual regularity measure (median absolute deviation of the gaps) reads that as irregular.

`eval/simulate.py` generates 500 beacons per row (200 check-ins every 300 s, with uniform jitter and a share of check-ins dropped at random) and three kinds of traffic that is *not* a beacon. Each row is the share of trials scored as a timer (timing score ≥ 0.8), with folding off ("plain") and on.


| traffic | jitter | missed check-ins | plain | with folding |
|---|---|---|---|---|
| beacon | ±10% | 0% | 100% | **100%** |
| beacon | ±10% | 15% | 100% | **100%** |
| beacon | ±10% | 30% | 7% | **100%** |
| beacon | ±10% | 45% | 0% | **93%** |
| beacon | ±20% | 0% | 100% | **100%** |
| beacon | ±20% | 15% | 100% | **100%** |
| beacon | ±20% | 30% | 8% | **92%** |
| beacon | ±20% | 45% | 0% | **49%** |
| beacon | ±30% | 0% | 100% | **100%** |
| beacon | ±30% | 15% | 99% | **100%** |
| beacon | ±30% | 30% | 8% | **78%** |
| beacon | ±30% | 45% | 0% | **22%** |
| random (Poisson) | - | - | 0% | **0%** |
| browsing sessions | - | - | 0% | **0%** |
| uniform 10 to 600 s | - | - | 0% | **0%** |

**What this shows**

- Plain scoring falls off a cliff between 15% and 30% missed check-ins. Below about a quarter, the doubled gaps are outliers and the median ignores them. Above it, they *become* the spread, and detection drops from ~100% to under 10%.
- Folding holds detection at 92 to 100% for jitter up to ±20% with 30% of check-ins missing, and still catches about half at ±20% with 45% missing.
- **No false positives were added:** none of the 1,500 non-beacon trials was called a timer, with or without folding. Random gaps rarely land near whole multiples of a base period, so they gain nothing from being folded.
- The honest limit: at ±30% jitter *and* 45% missed, the multiples blur into each other and folding only recovers 22%. That combination is where this approach stops working.

Run it yourself: `python eval/simulate.py` (seeded, about two seconds).

## 2. IoT-23: real malware traffic

*Results pending: the dataset logs are downloaded separately, see `eval/README.md`.*
