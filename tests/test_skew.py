import tempfile
from datetime import datetime, timezone
from pathlib import Path

from forensic import db, skew
from forensic.models import Event


def _setup_db_with_events(conn, ref_host, test_host, offset_s, num_anchors):
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO evidence (id, filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz) VALUES (1, 'ref.log', 'path1', 'hash1', 1, 1, 'now', 'test', ?, 'nginx', 'UTC')",
        (ref_host,),
    )
    conn.execute(
        "INSERT INTO evidence (id, filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz) VALUES (2, 'test.log', 'path2', 'hash2', 1, 1, 'now', 'test', ?, 'nginx', 'UTC')",
        (test_host,),
    )

    events = []
    base_ts = 1600000000  # some arbitrary time

    # Add anchors
    for i in range(num_anchors):
        # Reference event
        ts_ref = datetime.fromtimestamp(base_ts + i * 10, timezone.utc)
        events.append(
            Event(
                line_no=i + 1,
                byte_offset=0,
                ts_original="ref",
                ts_utc=ts_ref,
                host=ref_host,
                source_type="nginx",
                event_type="web_request",
                src_ip="1.1.1.1",
                detail=f"/path{i}",
            )
        )

        # Test host event (fast by offset_s, so its timestamp is HIGHER)
        ts_test = datetime.fromtimestamp(base_ts + i * 10 + offset_s, timezone.utc)
        events.append(
            Event(
                line_no=i + 1,
                byte_offset=0,
                ts_original="test",
                ts_utc=ts_test,
                host=test_host,
                source_type="nginx",
                event_type="web_request",
                src_ip="1.1.1.1",
                detail=f"/path{i}",
            )
        )

    db.insert_events(conn, 1, [e for e in events if e.host == ref_host])
    db.insert_events(conn, 2, [e for e in events if e.host == test_host])


def test_skew_anchor_median():
    with tempfile.TemporaryDirectory() as td:
        case_dir = Path(td)
        conn = db.connect(case_dir)
        _setup_db_with_events(conn, "web01", "db01", offset_s=420, num_anchors=5)
        conn.close()

        returned_rows = skew.skew(case_dir, reference_host="web01")
        assert len(returned_rows) == 2

        # Check corrections from DB
        conn = db.connect(case_dir)
        rows = conn.execute("SELECT * FROM skew_corrections ORDER BY host").fetchall()
        assert len(rows) == 2

        for r in rows:
            if r["host"] == "db01":
                assert r["method"] == "anchor_median"
                assert r["offset_s"] == -420.0
            else:
                assert r["host"] == "web01"
                assert r["method"] == "none"
                assert r["offset_s"] == 0.0

        # Check events
        db_events = conn.execute("SELECT * FROM events WHERE host='db01'").fetchall()
        for e in db_events:
            assert e["skew_offset_s"] == -420.0
            ts_utc = skew.parse_utc(e["ts_utc"])
            ts_corr = skew.parse_utc(e["ts_utc_corrected"])
            assert (ts_corr - ts_utc).total_seconds() == -420.0
            assert e["ts_original"] == "test"
        conn.close()


def test_skew_insufficient_anchors():
    with tempfile.TemporaryDirectory() as td:
        case_dir = Path(td)
        conn = db.connect(case_dir)
        _setup_db_with_events(conn, "web01", "db01", offset_s=420, num_anchors=2)
        conn.close()

        returned = skew.skew(case_dir, reference_host="web01")
        assert len(returned) == 2

        conn = db.connect(case_dir)
        row = conn.execute("SELECT * FROM skew_corrections WHERE host='db01'").fetchone()
        assert row["method"] == "none"
        assert row["offset_s"] == 0.0
        conn.close()


def test_skew_manual_offset():
    with tempfile.TemporaryDirectory() as td:
        case_dir = Path(td)
        conn = db.connect(case_dir)
        _setup_db_with_events(conn, "web01", "db01", offset_s=0, num_anchors=1)
        conn.execute(
            "INSERT INTO evidence (id, filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz) VALUES (3, 'app.log', 'path3', 'hash3', 1, 1, 'now', 'test', 'app01', 'nginx', 'UTC')"
        )
        ts_test = datetime.fromtimestamp(1600000000, timezone.utc)
        db.insert_events(
            conn,
            3,
            [
                Event(
                    line_no=1,
                    byte_offset=0,
                    ts_original="app",
                    ts_utc=ts_test,
                    host="app01",
                    source_type="nginx",
                    event_type="web_request",
                )
            ],
        )
        conn.close()

        returned = skew.skew(
            case_dir, reference_host="web01", manual_offsets=["db01=-420", "app01=30"]
        )
        assert len(returned) == 3

        conn = db.connect(case_dir)
        db01_row = conn.execute("SELECT * FROM skew_corrections WHERE host='db01'").fetchone()
        assert db01_row["method"] == "manual"
        assert db01_row["offset_s"] == -420.0

        app01_row = conn.execute("SELECT * FROM skew_corrections WHERE host='app01'").fetchone()
        assert app01_row["method"] == "manual"
        assert app01_row["offset_s"] == 30.0
        conn.close()


def test_skew_offsets_alias():
    with tempfile.TemporaryDirectory() as td:
        case_dir = Path(td)
        conn = db.connect(case_dir)
        _setup_db_with_events(conn, "web01", "db01", offset_s=0, num_anchors=1)
        conn.close()

        # Test offsets= alias keyword argument
        returned = skew.skew(case_dir, reference_host="web01", offsets=["db01=-420"])
        assert len(returned) == 2
        db01_item = next(r for r in returned if r["host"] == "db01")
        assert db01_item["method"] == "manual"
        assert db01_item["offset_s"] == -420.0
