import json
import random

from beacon_hunter.cli import main

from conftest import beacon, random_traffic, write_tsv


def _sample_log(tmp_path):
    rng = random.Random(3)
    conns = beacon("10.0.0.5", "203.0.113.50", 8443, 0, interval=120, jitter=0.1, count=200, rng=rng)
    conns += random_traffic("10.0.0.7", "198.51.100.20", 443, 0, mean_gap=90, count=250, rng=rng)
    conns.sort(key=lambda c: c.ts)
    return write_tsv(tmp_path / "conn.log", conns)


def test_json_output_ranks_the_beacon_first(tmp_path, capsys):
    log = _sample_log(tmp_path)
    assert main([str(log), "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert results[0]["dst"] == "203.0.113.50"
    assert results[0]["dport"] == 8443
    assert results[0]["first_seen"].endswith("Z")


def test_table_output_and_allowlist(tmp_path, capsys):
    log = _sample_log(tmp_path)
    allow = tmp_path / "allow.txt"
    allow.write_text("203.0.113.50\n", encoding="utf-8")

    assert main([str(log)]) == 0
    assert "203.0.113.50:8443/tcp" in capsys.readouterr().out

    assert main([str(log), "--allowlist", str(allow)]) == 0
    assert "203.0.113.50" not in capsys.readouterr().out


def test_bad_allowlist_exits_with_error(tmp_path, capsys):
    log = _sample_log(tmp_path)
    allow = tmp_path / "allow.txt"
    allow.write_text("nonsense\n", encoding="utf-8")
    assert main([str(log), "--allowlist", str(allow)]) == 2
    assert "allow.txt:1" in capsys.readouterr().err
