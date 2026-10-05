import gzip
import json

import pytest

from beacon_hunter.zeek import Conn, ReadStats, read_conn_log, read_conn_logs

from conftest import write_tsv


def test_reads_tsv_and_treats_dash_as_unset(tmp_path):
    path = write_tsv(tmp_path / "conn.log", [
        Conn(1.5, "10.0.0.1", "10.0.0.2", 443, "tcp", 120),
        Conn(2.5, "10.0.0.1", "10.0.0.2", 443, "tcp", None),
    ])
    conns = list(read_conn_log(path))
    assert conns[0] == Conn(1.5, "10.0.0.1", "10.0.0.2", 443, "tcp", 120, sport=49152, answered=True)
    assert conns[1].orig_bytes is None
    assert conns[1].sport == 49153


def test_reads_json_with_dotted_or_flattened_names(tmp_path):
    rows = [
        {"ts": 1700000000.25, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.resp_p": 53,
         "proto": "udp", "orig_bytes": 40},
        {"ts": "2023-11-14T22:13:21Z", "id_orig_h": "10.0.0.3", "id_resp_h": "10.0.0.4", "id_resp_p": 80,
         "proto": "tcp"},
    ]
    path = tmp_path / "conn.json"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    conns = list(read_conn_log(path))

    assert conns[0] == Conn(1700000000.25, "10.0.0.1", "10.0.0.2", 53, "udp", 40)
    assert conns[1].src == "10.0.0.3" and conns[1].dport == 80
    assert conns[1].ts == 1700000001.0


def test_reads_gzipped_logs(tmp_path):
    plain = write_tsv(tmp_path / "conn.log", [Conn(1.0, "10.0.0.1", "10.0.0.2", 22, "tcp", 10)])
    gz = tmp_path / "conn.00-00-00.log.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(plain.read_text(encoding="utf-8"))
    assert len(list(read_conn_log(gz))) == 1


def test_malformed_rows_are_counted_not_fatal(tmp_path):
    path = tmp_path / "conn.json"
    path.write_text('{"ts": 1, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"}\nnot json\n{"ts": 2}\n',
                    encoding="utf-8")
    stats = ReadStats()
    assert len(list(read_conn_logs([path], stats))) == 1
    assert (stats.rows, stats.skipped) == (3, 2)


def test_tsv_without_fields_header_is_rejected(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("#path\tconn\n1.0\tC1\t10.0.0.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="#fields"):
        list(read_conn_log(path))


def test_empty_file_yields_nothing(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("\n\n", encoding="utf-8")
    assert list(read_conn_log(path)) == []
