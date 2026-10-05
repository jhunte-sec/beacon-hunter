# Evaluation

Three questions, answered separately:

1. **Do the timing improvements help, and what do they cost?** Answered by simulation, where the ground truth is known exactly.
2. **Do they find real command-and-control traffic?** Answered on IoT-23, a public dataset of real malware captures with every connection labeled.
3. **Can the packet-capture reader be trusted?** Answered by comparing it with Zeek on the same capture.

Everything is reproducible: `python eval/simulate.py` (seeded, a couple of seconds), and after downloading the data (see `eval/README.md`) `python eval/iot23.py eval/data/*.labeled` and `python eval/pcap_vs_zeek.py`. `python eval/plot.py` redraws the figures.

## A correction first

An earlier version of this project said Hakai's command-and-control traffic was a retry loop that waits 7, 8.5, 17 and 48 seconds, and built cycle detection around that. **That was wrong.** The raw packets show something simpler: Hakai opens one new connection every 80 seconds and the server never answers. The operating system retransmits each unanswered SYN, and Zeek starts a new log record once an unanswered SYN is over 5 seconds old, so one attempt became four records. Mirai's "3 s / 7 s" pattern turned out to be the same thing on a 10-second timer.

What changed as a result: retries of one connection are now counted once (they share a source port), the report says when a server never answers, and the results below show what each technique does on its own. The correction is in the commit history too.

## 1. Simulation

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/simulation-dark.svg?v=418b2d15">
  <img alt="As more check-ins go missing, the standard method stops catching beacons while beacon-hunter keeps catching most of them" src="img/simulation-light.svg?v=b7c87afa" width="760">
</picture>

`eval/simulate.py` generates 500 trials per row: beacons with 200 check-ins every 300 s, uniform jitter, and a share of check-ins dropped at random; timers that repeat a multi-step pattern; and three kinds of traffic that is *not* a beacon. Each row is the share of trials scored as a timer (timing score ≥ 0.8) by plain scoring (median absolute deviation and skew of the gaps, the textbook approach) and by beacon-hunter (plus missed-check-in folding and cycle detection; retry merging works on log records, so it has no role here).

| traffic | jitter | missed check-ins | plain | beacon-hunter |
|---|---|---|---|---|
| beacon | ±10% | 0% | 100% | **100%** |
| beacon | ±10% | 15% | 100% | **100%** |
| beacon | ±10% | 30% | 10% | **100%** |
| beacon | ±10% | 45% | 0% | **98%** |
| beacon | ±20% | 0% | 100% | **100%** |
| beacon | ±20% | 15% | 100% | **100%** |
| beacon | ±20% | 30% | 8% | **95%** |
| beacon | ±20% | 45% | 0% | **57%** |
| beacon | ±30% | 0% | 100% | **100%** |
| beacon | ±30% | 15% | 99% | **100%** |
| beacon | ±30% | 30% | 8% | **78%** |
| beacon | ±30% | 45% | 0% | **24%** |
| cycle 7 / 8.5 / 17 / 48 s | ±5% | 0% | 0% | **100%** |
| cycle 7 / 8.5 / 17 / 48 s | ±15% | 0% | 0% | **100%** |
| cycle 3 / 7 s | ±10% | 0% | 0% | **100%** |
| cycle 5 / 5 / 50 s | ±10% | 0% | 0% | **100%** |
| random (Poisson) | - | - | 0% | **0%** |
| browsing sessions | - | - | 0% | **0%** |
| uniform 10 to 600 s | - | - | 0% | **0%** |

**What this shows**

- Plain scoring falls off a cliff between 15% and 30% missed check-ins. Below about a quarter, the doubled gaps are outliers and the median ignores them. Above it, they *are* the spread, and detection drops to under 10%.
- Folding holds detection at 95 to 100% for jitter up to ±20% with 30% of check-ins missing, and still catches more than half at ±20% with 45% missing.
- A timer that repeats a pattern of different gaps is invisible to plain scoring (0%) and found every time with cycle detection (100%).
- **No false positives:** none of the 1,500 non-beacon trials was called a timer either way.
- The honest limit: at ±30% jitter *and* 45% missed, the multiples blur into each other and only about a quarter are recovered.

## 2. IoT-23: real malware traffic

[IoT-23](https://www.stratosphereips.org/datasets-iot23) (Stratosphere Laboratory, CTU Prague, CC BY) contains Zeek logs of real malware running on a Raspberry Pi, with every connection labeled. Labels starting with `C&C` are the ground truth here. I used the seven malware captures and two benign devices whose logs are small enough to download individually.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/results-dark.svg?v=72384968">
  <img alt="Real command-and-control traffic: the standard method misses the Mirai and Hakai channels, beacon-hunter flags both; a one-off download stays unflagged" src="img/results-light.svg?v=414def6f" width="760">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="img/retries-dark.svg?v=aac39bd2">
  <img alt="Hakai malware makes one connection attempt every 80 seconds to a server that never answers; Zeek logs the operating system's retries as separate connections" src="img/retries-light.svg?v=2ee0f138" width="760">
</picture>

### Per capture

"Scorable" means the channel had the 10+ attempts needed to judge timing at all. "Worth a look" is the section of the HTML report for unexplained timers on one or two hosts (known services like NTP have their own table).

| scenario | family | connections | pairs scored | C&C pairs | C&C pairs scorable | best C&C rank by raw score | C&C called a timer | place in "worth a look" |
|---|---|---|---|---|---|---|---|---|
| CTU-Honeypot-Capture-4-1 | Philips Hue (benign) | 452 | 9 | 0 | 0 | - | 0 of 0 | - |
| CTU-Honeypot-Capture-5-1 | Amazon Echo (benign) | 1,374 | 12 | 0 | 0 | - | 0 of 0 | - |
| CTU-IoT-Malware-Capture-20-1 | Torii | 3,209 | 11 | 1 | 0 | - | 0 of 0 | - |
| CTU-IoT-Malware-Capture-21-1 | Torii | 3,286 | 26 | 1 | 0 | - | 0 of 0 | - |
| CTU-IoT-Malware-Capture-3-1 | Muhstik | 156,103 | 97 | 5 | 0 | - | 0 of 0 | - |
| CTU-IoT-Malware-Capture-34-1 | Mirai | 23,145 | 12 | 1 | 1 | 4 | 1 of 1 | 1 of 1 |
| CTU-IoT-Malware-Capture-42-1 | Trojan | 4,426 | 11 | 1 | 0 | - | 0 of 0 | - |
| CTU-IoT-Malware-Capture-44-1 | Mirai | 237 | 7 | 2 | 1 | 7 | 0 of 1 | - |
| CTU-IoT-Malware-Capture-8-1 | Hakai | 10,403 | 8 | 2 | 2 | 2 | 2 of 2 | 1 of 2 |

### Every scorable C&C channel, technique by technique

Timing score with nothing, with each technique on its own, and with everything. "Attempts" is log records after retries are counted once.

| scenario | C&C destination | log records | attempts | plain | retry merging only | cycle detection only | beacon-hunter | what the report says |
|---|---|---|---|---|---|---|---|---|
| CTU-IoT-Malware-Capture-34-1 (Mirai) | 185.244.25.235:6667/tcp | 6,706 | 4,055 | 0.35 | 1.00 | 1.00 | **1.00** | checks in every 10s for 57% of gaps; almost exactly; the rest are shorter or longer |
| CTU-IoT-Malware-Capture-44-1 (Mirai) | 46.101.251.172:80/tcp | 24 | 11 | 0.28 | 0.59 | 0.28 | **0.59** | no clear timer: typical gap 2s, but half the gaps are more than 16% off |
| CTU-IoT-Malware-Capture-8-1 (Hakai) | 128.185.250.50:50/tcp | 4,110 | 1,028 | 0.67 | 1.00 | 1.00 | **1.00** | checks in every 1m20s; almost exactly |
| CTU-IoT-Malware-Capture-8-1 (Hakai) | 178.128.185.250:50/tcp | 4,112 | 1,028 | 0.65 | 1.00 | 1.00 | **1.00** | checks in every 1m20s; almost exactly |

### What this shows

- **Two C&C channels that plain scoring misses become clear timers.** Hakai's command servers score 0.65 to 0.67 plainly and 1.00 with retry merging: one attempt every 80 seconds, never answered. Mirai's IRC channel scores 0.35 plainly and 1.00: an attempt every 10 seconds, and the report says honestly that the timer covers 57% of the gaps. Unlike Hakai's, this server answered about a third of the attempts (1,400 of 4,055). In both captures the C&C channels are the top of the report's "Worth a look" list, and the list holds nothing else.
- **Retry merging does the work on real data.** Cycle detection alone reaches the same scores from the raw records, because the retry artifact *looks* like a cycle, but retry merging explains it correctly. Cycle detection's own value is shown in simulation, not here.
- **How the scoring was tuned matters for reading these numbers.** Retry merging came from studying the Hakai packets. Adding it exposed a flaw in the skew term on Mirai's channel (a spike of identical gaps was penalised as if it were skewed), which I fixed after looking at that capture. So neither capture is an independent test any more; the false-positive check is the simulation and the benign devices below.
- **Ranked by raw score alone, NTP wins.** These devices poll NTP servers on a timer. That is why the report lists known timer services separately, and why the first thing to allowlist on any network is your own time servers.
- **Most C&C traffic in these captures can't be judged by timing at all.** 9 of the 13 C&C channels had too few attempts: one-off file downloads, Muhstik's C2 (a handful of long-lived connections), and Torii, whose 14 and 16 log records turn out to be 7 attempts each plus their retries. One long connection is one log line; no timing method sees it.
- **The benign devices show the cost.** The Philips Hue checks in with Akamai every 15 minutes and AWS every hour (timing 0.92 to 1.00); the Amazon Echo pings its router and fetches over HTTP every 5 minutes. Timing alone can't tell that from an implant, so they land in "Worth a look" until someone confirms and allowlists them. That is the job the report's next steps are written for.
- **A caveat on the easy part:** these captures contain little besides the malware, NTP and DNS, so heading "Worth a look" here is a lower bar than it would be on an office network with hundreds of hosts.

## 3. The pcap reader against Zeek

IoT-23 also publishes the raw packets for each capture, so the built-in connection tracker can be checked against Zeek's own output for capture 8-1 (Hakai). 23,623 packets -> 4,237 connections rebuilt; Zeek logged 10,403 records.

| conversation | Zeek records | Zeek attempts (retries merged) | pcap reader | match |
|---|---|---|---|---|
| 192.168.100.113 → 178.128.185.250:50/tcp | 4,112 | 1,028 | 1,028 | yes |
| 192.168.100.113 → 128.185.250.50:50/tcp | 4,110 | 1,028 | 1,028 | yes |
| 192.168.100.113 → 147.231.100.5:123/udp | 1,319 | 1,319 | 1,319 | yes |
| 192.168.100.113 → 31.31.74.35:123/udp | 204 | 204 | 204 | yes |
| 192.168.100.113 → 37.157.198.150:123/udp | 204 | 204 | 204 | yes |
| 192.168.100.113 → 81.2.254.224:123/udp | 180 | 180 | 180 | yes |
| 192.168.100.113 → 147.251.48.140:123/udp | 148 | 148 | 148 | yes |
| 192.168.100.113 → 80.79.25.111:123/udp | 124 | 124 | 124 | yes |
| 192.168.100.102 → 192.168.100.113:22/tcp | 2 | 2 | 2 | yes |

After counting retries once, the two agree exactly on every conversation, and the top findings are identical from either source: both Hakai servers every 80.1 s with timing 1.00. The only design difference is deliberate: the pcap reader keeps a retransmitted SYN in the same connection (as the operating system does), while Zeek splits it after 5 seconds, which is what retry merging undoes.

Dataset citation: Stratosphere Laboratory. *A labeled dataset with malicious and benign IoT network traffic.* Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga. https://www.stratosphereips.org/datasets-iot23
