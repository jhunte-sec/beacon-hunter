import pytest

from beacon_hunter.allowlist import is_allowed, load, parse_entry


@pytest.mark.parametrize("entry, dst, port, expected", [
    ("10.0.0.53", "10.0.0.53", 53, True),
    ("10.0.0.53", "10.0.0.54", 53, False),
    ("10.0.0.0/8", "10.9.9.9", 443, True),
    ("10.0.0.20:1514", "10.0.0.20", 1514, True),
    ("10.0.0.20:1514", "10.0.0.20", 1515, False),
    ("*:123", "162.159.200.1", 123, True),
    ("*:123", "162.159.200.1", 443, False),
    ("2001:db8::1", "2001:db8::1", 443, True),
    ("[2001:db8::1]:443", "2001:db8::1", 443, True),
    ("[2001:db8::1]:443", "2001:db8::1", 80, False),
])
def test_entries_match_as_documented(entry, dst, port, expected):
    assert parse_entry(entry).matches(dst, port) is expected


def test_load_skips_comments_and_reports_bad_lines(tmp_path):
    good = tmp_path / "ok.txt"
    good.write_text("# NTP\n*:123\n\n10.0.0.20:1514  # SIEM\n", encoding="utf-8")
    entries = load(good)
    assert len(entries) == 2
    assert is_allowed(entries, "10.0.0.20", 1514)

    bad = tmp_path / "bad.txt"
    bad.write_text("*:123\nnot-an-ip\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bad.txt:2"):
        load(bad)
