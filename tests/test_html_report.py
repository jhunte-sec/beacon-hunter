from beacon_hunter.cli import main
from beacon_hunter.html_report import render
from beacon_hunter.scoring import analyze

from conftest import beacon, write_tsv


def test_report_is_self_contained_and_escapes_input():
    conns = beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=60, jitter=0.05, count=60)
    page = render(analyze(conns), ["<script>alert(1)</script>.log"], rows=60, skipped=0)
    assert page.startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert page.count('class="chart') == 2   # heartbeat strip + gap histogram
    assert "1</div>" in page and "pair worth a look" in page
    assert "http" not in page.split("<style>")[0]  # nothing loaded from elsewhere


def test_cli_writes_html_and_explains(tmp_path, capsys):
    log = write_tsv(tmp_path / "conn.log",
                    beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=60, jitter=0.05, count=60))
    out = tmp_path / "report.html"
    assert main([str(log), "--explain", "--html", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "checks in every 1m00s" in printed
    assert out.read_text(encoding="utf-8").count('class="card"') == 1


def test_fleet_wide_timers_get_their_own_section_with_allowlist_lines():
    conns = []
    for n in range(4):
        conns += beacon(f"10.0.0.{n + 1}", "10.0.0.20", 1514, n, interval=60, jitter=0.01, count=50)
    page = render(analyze(conns), ["conn.log"], rows=200, skipped=0)
    assert "Probably deployed software" in page
    assert "10.0.0.20:1514" in page and "# 4 hosts, every 1m00s" in page
    assert "No single-host timers found" in page


def test_next_steps_depend_on_whether_the_destination_is_internal():
    from beacon_hunter.html_report import _is_internal
    assert _is_internal("10.1.2.3") and _is_internal("192.168.0.9") and _is_internal("fd00::1")
    assert not _is_internal("203.0.113.50")   # documentation range: treat as external
    assert not _is_internal("8.8.8.8")
