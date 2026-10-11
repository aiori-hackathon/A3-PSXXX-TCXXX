import pytest
import sqlite3
import json
import csv
from pathlib import Path
from forensic.timeline import Filters, query_events, summary_stats, gap_summary
from forensic.report import generate_report
from forensic import db

def make_case(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    conn = db.connect(case_dir)
    db.init_schema(conn)
    
    # insert 2 evidence rows with ALL NOT NULL columns of the evidence table
    conn.execute("INSERT INTO evidence (filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ("auth.log", "evidence/web01__auth.log", "abcdef123456", 1024, 100, "2026-10-01T10:00:00Z", "admin", "web01", "auth_log", "UTC"))
    conn.execute("INSERT INTO evidence (filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ("nginx.log", "evidence/db01__nginx.log", "deadbeef0000", 2048, 200, "2026-10-01T11:00:00Z", "admin", "db01", "nginx", "UTC"))
    
    # insert 3 events with all NOT NULL columns of events
    conn.execute("INSERT INTO events (evidence_id, line_no, byte_offset, ts_original, ts_utc, ts_utc_corrected, skew_offset_s, host, source_type, event_type, severity, message, raw_line, src_ip, username, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (1, 1, 0, "Oct 1 10:00:00", "2026-10-01T10:00:00Z", "2026-10-01T10:00:00Z", 0, "web01", "auth_log", "ssh_login", "info", "normal request", "raw log 1", "10.0.0.1", "root", "login"))
    conn.execute("INSERT INTO events (evidence_id, line_no, byte_offset, ts_original, ts_utc, ts_utc_corrected, skew_offset_s, host, source_type, event_type, severity, message, raw_line, src_ip, username, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (2, 1, 0, "Oct 1 11:00:00", "2026-10-01T11:00:00Z", "2026-10-01T11:00:00Z", 0, "db01", "nginx", "web_request", "info", "attack ' quote", "raw log 2", "10.0.0.2", None, None))
    conn.execute("INSERT INTO events (evidence_id, line_no, byte_offset, ts_original, ts_utc, ts_utc_corrected, skew_offset_s, host, source_type, event_type, severity, message, raw_line, src_ip, username, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (2, 2, 50, "Oct 1 11:05:00", "2026-10-01T11:05:00Z", "2026-10-01T11:05:00Z", 0, "db01", "nginx", "web_request", "high", 'attack " quote', "raw log 3", "10.0.0.3", None, None))
    
    # insert 1 parse_gaps row
    conn.execute("INSERT INTO parse_gaps (evidence_id, line_no, reason, raw_line) VALUES (?, ?, ?, ?)", (1, 2, "no_regex_match", "bad line"))
    
    # insert 1 skew_corrections row
    conn.execute("INSERT INTO skew_corrections (host, reference_host, offset_s, method, anchor_count, confidence_note) VALUES (?, ?, ?, ?, ?, ?)", ("db01", "web01", 300, "manual", 1, "looks good"))
    
    db.rebuild_fts(conn)
    conn.commit()
    conn.close()
    return case_dir

def test_timeline_filters(tmp_path):
    case_dir = make_case(tmp_path)
    db_path = case_dir / "case.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    events = query_events(conn, Filters(hosts=["web01"]))
    assert len(events) == 1
    
    # FTS with quotes should not raise
    events = query_events(conn, Filters(text="attack ' quote"))
    assert len(events) == 2
    
    events = query_events(conn, Filters(text='attack " quote'))
    assert len(events) == 2

    events = query_events(conn, Filters(source_types=["nginx"]))
    assert len(events) == 2

    events = query_events(conn, Filters(event_types=["ssh_login"]))
    assert len(events) == 1

    events = query_events(conn, Filters(severities=["high"]))
    assert len(events) == 1

    events = query_events(conn, Filters(src_ip="10.0.0.1"))
    assert len(events) == 1

    events = query_events(conn, Filters(username="root"))
    assert len(events) == 1

    events = query_events(conn, Filters(ts_from="2026-10-01T10:30:00Z"))
    assert len(events) == 2

    events = query_events(conn, Filters(ts_to="2026-10-01T10:30:00Z"))
    assert len(events) == 1

    events = query_events(conn, Filters(use_corrected=True))
    assert len(events) == 3

    conn.close()

def test_report_generation(tmp_path):
    case_dir = make_case(tmp_path)
    
    out_html = tmp_path / "report.html"
    out_json = tmp_path / "report.json"
    out_csv = tmp_path / "report.csv"
    
    generate_report(case_dir, out_html, out_json, out_csv)
    
    assert out_html.exists()
    html = out_html.read_text()
    
    # Check 8 section headings
    headings = ["Case Summary", "Executive Summary", "Evidence Manifest", "Time Handling", "Key-Event Timeline", "Parsing Gaps", "Limitations", "Appendix"]
    for heading in headings:
        assert heading in html
    
    assert "Limitations &amp; scope:" in html
    
    assert "abcdef123456" in html
    assert "deadbeef0000" in html
    
    assert out_json.exists()
    j = json.loads(out_json.read_text())
    for key in ["case", "summary", "evidence", "skew", "key_events", "gaps", "limitations"]:
        assert key in j
    
    assert out_csv.exists()
    with open(out_csv, newline='') as f:
        reader = csv.reader(f)
        rows = list(reader)
        header = rows[0]
        assert header[0] == "ts_utc_corrected"
        assert len(rows) == 4 # header + 3 events

def test_report_verification_status(tmp_path):
    from forensic.pipeline import run_case
    case_dir = tmp_path / "case"
    run_case(Path("scenarios/s3_clock_skew/sources.json"), case_dir)
    
    out_html = tmp_path / "report.html"
    out_json = tmp_path / "report.json"
    generate_report(case_dir, out_html, out_json)
    
    html = out_html.read_text()
    assert "UNKNOWN" not in html
    
    j = json.loads(out_json.read_text())
    for ev in j["evidence"]:
        if "status" in ev: # it will have status once I fix report.py
            assert ev["status"] == "OK"
        
    # Tamper file
    from forensic import db
    conn = db.connect(case_dir)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT stored_path FROM evidence LIMIT 1").fetchone()
    conn.close()
    
    tamper_path = case_dir / row["stored_path"]
    import stat
    import os
    os.chmod(tamper_path, stat.S_IWRITE)
    with open(tamper_path, "ab") as f:
        f.write(b"x")
        
    generate_report(case_dir, out_html, out_json)
    j = json.loads(out_json.read_text())
    tampered_found = False
    ok_found = False
    for ev in j["evidence"]:
        if "stored_path" not in ev:
            continue
        if ev["stored_path"] == row["stored_path"]:
            assert ev["status"] == "TAMPERED"
            tampered_found = True
        else:
            assert ev["status"] == "OK"
            ok_found = True
    assert tampered_found
    assert ok_found
