import json
import tempfile
from pathlib import Path

from forensic import build, db, ingest


def test_build_stats_and_fts():
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s1"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)

        # auth.log with valid, invalid, blank, and encoding error
        auth_log = src_dir / "auth.log"
        # we write raw bytes to include invalid utf-8
        auth_log.write_bytes(
            b"Oct  3 02:14:07 web01 sshd[1234]: Failed password for admin from 203.0.113.50 port 51122 ssh2\n"
            b"\n"
            b"Garbage line\n"
            b"Oct  3 02:15:00 web01 bad utf8 \xff\n"
        )

        sources_json = src_dir / "sources.json"
        sources_json.write_text(json.dumps({
            "case_id": "s1",
            "year_hint": 2026,
            "sources": [
                {"path": "auth.log", "host": "web01", "source_type": "auth_log", "declared_tz": "UTC"}
            ]
        }))

        ingest.ingest(case_dir, sources_json, "test_collector")

        stats_list = build.build(case_dir)

        assert len(stats_list) == 1
        stats = stats_list[0]

        assert stats["total_lines"] == 4
        assert stats["parsed"] == 1
        assert stats["gaps"] == 3
        # parsed_pct ignores empty_line -> 1 parsed, 2 other gaps -> 1/3 = 33.3%
        assert stats["parsed_pct"] == 33.3

        assert stats["gap_reasons"]["empty_line"] == 1
        assert stats["gap_reasons"]["no_regex_match"] == 1
        assert stats["gap_reasons"]["encoding_error"] == 1

        # Test FTS index
        conn = db.connect(case_dir)
        fts_rows = conn.execute("SELECT * FROM events_fts WHERE events_fts MATCH 'password'").fetchall()
        assert len(fts_rows) == 1

        # Check DB gap reasons
        db_gaps = conn.execute("SELECT reason, raw_line FROM parse_gaps").fetchall()
        reasons = [r["reason"] for r in db_gaps]
        assert sorted(reasons) == ["empty_line", "encoding_error", "no_regex_match"]
        conn.close()
