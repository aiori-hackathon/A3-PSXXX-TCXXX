import sqlite3
from pathlib import Path

from .models import Event, ParseGap


def connect(case_dir: Path) -> sqlite3.Connection:
    db_path = case_dir / "case.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_schema(conn: sqlite3.Connection) -> None:
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()

def insert_evidence(conn: sqlite3.Connection, **fields) -> int:
    cols = ", ".join(fields.keys())
    placeholders = ", ".join("?" for _ in fields)
    cur = conn.execute(f"INSERT INTO evidence ({cols}) VALUES ({placeholders})", list(fields.values()))
    conn.commit()
    return cur.lastrowid

def insert_events(conn: sqlite3.Connection, evidence_id: int, events: list[Event]) -> None:
    if not events:
        return

    query = """
    INSERT INTO events (
        evidence_id, line_no, byte_offset, ts_original, ts_utc, ts_utc_corrected,
        host, source_type, event_type, severity, src_ip, username, detail, message, raw_line
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    rows = []
    for ev in events:
        ts_utc_str = ev.ts_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        rows.append((
            evidence_id, ev.line_no, ev.byte_offset, ev.ts_original, ts_utc_str, ts_utc_str,
            ev.host, ev.source_type, ev.event_type, ev.severity, ev.src_ip, ev.username,
            ev.detail, ev.message, ev.raw_line
        ))

    conn.executemany(query, rows)
    conn.commit()

def insert_gaps(conn: sqlite3.Connection, evidence_id: int, gaps: list[ParseGap]) -> None:
    if not gaps:
        return

    query = "INSERT INTO parse_gaps (evidence_id, line_no, reason, raw_line) VALUES (?, ?, ?, ?)"
    rows = [(evidence_id, g.line_no, g.reason, g.raw_line) for g in gaps]

    conn.executemany(query, rows)
    conn.commit()

def rebuild_fts(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
    conn.commit()
