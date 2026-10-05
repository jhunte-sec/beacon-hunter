from beacon_hunter.cli import main
from beacon_hunter.html_report import render
from beacon_hunter.scoring import analyze

from conftest import beacon, write_tsv


def test_report_is_self_contained_and_escapes_input():
    conns = beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=60, jitter=0.05, count=60)
    page = render(analyze(conns), ["<script>alert(1)</script>.log"], rows=60, skipped=0)
    assert page.startswith("<!doctype html>")
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert page.count("<svg") == 2          # heartbeat strip + gap histogram
    assert "http" not in page.split("<style>")[0]  # nothing loaded from elsewhere


def test_cli_writes_html_and_explains(tmp_path, capsys):
    log = write_tsv(tmp_path / "conn.log",
                    beacon("10.0.0.5", "203.0.113.50", 443, 0, interval=60, jitter=0.05, count=60))
    out = tmp_path / "report.html"
    assert main([str(log), "--explain", "--html", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "checks in every 1m00s" in printed
    assert out.read_text(encoding="utf-8").count('class="card"') == 1
