import random

from beacon_hunter import allowlist
from beacon_hunter.scoring import (
    Settings, analyze, bowley_skew, merge_events, persistence_score,
    regularity, size_score, timing_score,
)
from beacon_hunter.zeek import Conn

from conftest import beacon, random_traffic

DAY = 86400


def test_perfect_timer_gets_full_timing_score():
    assert timing_score([60.0] * 50) == 1.0


def test_jittered_beacon_scores_well_above_random_traffic(rng):
    jittered = [60 * (1 + rng.uniform(-0.2, 0.2)) for _ in range(300)]
    random_gaps = [rng.expovariate(1 / 60) for _ in range(300)]
    assert timing_score(jittered) > 0.85
    assert timing_score(random_gaps) < 0.6


def test_regularity_of_uniform_jitter_matches_the_maths():
    # Uniform +/-20% around 60s has a MAD of about 6s, so regularity ~ 1 - 6/60.
    gaps = [48 + 24 * i / 999 for i in range(1000)]
    assert abs(regularity(gaps) - 0.9) < 0.01


def test_bowley_skew_is_zero_when_quartiles_collapse():
    assert bowley_skew([5, 5, 5, 5, 5, 9]) == 0.0


def test_merge_events_collapses_bursts_into_one_check_in():
    assert merge_events([0, 0.2, 0.4, 60, 60.3, 120], window=1.0) == [0, 60, 120]


def test_size_score_needs_byte_counts():
    assert size_score([], connections=50) is None
    assert size_score([300, 300, 300], connections=50) is None  # too few of the 50
    assert size_score([300] * 40, connections=50) == 1.0


def test_persistence_rewards_activity_across_the_whole_capture():
    spread = [i * 3600 + 10 for i in range(24)]
    burst = [i * 60 for i in range(60)]  # one busy hour
    assert persistence_score(spread, 0, DAY, 24) == 1.0
    assert persistence_score(burst, 0, DAY, 24) == 1 / 24


def test_beacon_ranks_first_among_mixed_traffic():
    rng = random.Random(7)
    conns = []
    conns += beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=300, jitter=0.15, count=288, rng=rng)
    conns += random_traffic("10.0.0.5", "198.51.100.7", 443, 0, mean_gap=240, count=350, rng=rng)
    conns += random_traffic("10.0.0.9", "198.51.100.8", 80, 0, mean_gap=200, count=400, rng=rng)

    findings = analyze(conns)

    assert findings[0].dst == "203.0.113.50"
    assert findings[0].score > 0.85
    assert all(f.score < findings[0].score - 0.2 for f in findings[1:])


def test_pairs_below_min_events_are_not_scored():
    conns = beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=60, jitter=0, count=5)
    assert analyze(conns, Settings(min_events=10)) == []


def test_multicast_is_ignored_unless_asked_for():
    conns = beacon("10.0.0.5", "224.0.0.251", 5353, 0, interval=60, jitter=0, count=50)
    assert analyze(conns) == []
    assert len(analyze(conns, Settings(include_multicast=True))) == 1


def test_allowlisted_destination_is_skipped():
    conns = beacon("10.0.0.5", "10.0.0.20", 1514, 0, interval=10, jitter=0, count=100)
    settings = Settings(allow=[allowlist.parse_entry("10.0.0.20:1514")])
    assert analyze(conns, settings) == []


def test_missing_ports_still_group():
    conns = [Conn(i * 60.0, "10.0.0.5", "203.0.113.9", None, "icmp", None) for i in range(30)]
    findings = analyze(conns)
    assert len(findings) == 1
    assert findings[0].size is None
