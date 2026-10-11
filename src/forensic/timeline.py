import sqlite3
from dataclasses import dataclass
from typing import Optional, List, Dict
from datetime import datetime, timedelta

__all__ = [
    "query_events", 
    "context_window", 
    "get_evidence", 
    "summary_stats", 
    "key_events", 
    "gap_summary", 
    "skew_summary", 
    "evidence_manifest", 
    "Filters"
]

@dataclass
class Filters:
    hosts: Optional[List[str]] = None
    source_types: Optional[List[str]] = None
    event_types: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    src_ip: Optional[str] = None
    username: Optional[str] = None
    ts_from: Optional[str] = None
    ts_to: Optional[str] = None
    text: Optional[str] = None
    use_corrected: bool = True

def _dict_fetchall(cur):
    cols = [d[0] for d in cur.description] if cur.description else []
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def query_events(conn, f: Filters, limit: int = 5000, offset: int = 0) -> List[dict]:
    query = "SELECT events.* FROM events "
    params = []
    
    if f.text:
        query += " JOIN events_fts ON events.id = events_fts.rowid "
        
    conditions = []
    
    if f.text:
        safe_text = f.text.replace('"', '""')
        conditions.append("events_fts MATCH ?")
        params.append(f'"{safe_text}"')
        
    if f.hosts:
        conditions.append(f"events.host IN ({','.join(['?']*len(f.hosts))})")
        params.extend(f.hosts)
        
    if f.source_types:
        conditions.append(f"events.source_type IN ({','.join(['?']*len(f.source_types))})")
        params.extend(f.source_types)

    if f.event_types:
        conditions.append(f"events.event_type IN ({','.join(['?']*len(f.event_types))})")
        params.extend(f.event_types)
        
    if f.severities:
        conditions.append(f"events.severity IN ({','.join(['?']*len(f.severities))})")
        params.extend(f.severities)
        
    if f.src_ip:
        conditions.append("events.src_ip = ?")
        params.append(f.src_ip)
        
    if f.username:
        conditions.append("events.username = ?")
        params.append(f.username)
        
    ts_col = "events.ts_utc_corrected" if f.use_corrected else "events.ts_utc"
    if f.ts_from:
        conditions.append(f"{ts_col} >= ?")
        params.append(f.ts_from)
    if f.ts_to:
        conditions.append(f"{ts_col} <= ?")
        params.append(f.ts_to)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += f" ORDER BY {ts_col} ASC, events.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cur = conn.execute(query, params)
    return _dict_fetchall(cur)

def summary_stats(conn) -> dict:
    cur = conn.execute("SELECT host, event_type, severity, src_ip FROM events")
    events = _dict_fetchall(cur)
    if not events:
        return {}
    
    by_type = {}
    by_sev = {}
    by_host = {}
    ips = {}
    for r in events:
        by_type[r["event_type"]] = by_type.get(r["event_type"], 0) + 1
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        by_host[r["host"]] = by_host.get(r["host"], 0) + 1
        if r["src_ip"]:
            ips[r["src_ip"]] = ips.get(r["src_ip"], 0) + 1
            
    top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
    
    first = _dict_fetchall(conn.execute("SELECT ts_utc_corrected FROM events ORDER BY ts_utc_corrected ASC LIMIT 1"))
    last = _dict_fetchall(conn.execute("SELECT ts_utc_corrected FROM events ORDER BY ts_utc_corrected DESC LIMIT 1"))
    
    ev_files = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    gaps = conn.execute("SELECT COUNT(*) FROM parse_gaps").fetchone()[0]
    
    return {
        "total_events": len(events),
        "hosts": list(by_host.keys()),
        "first_event": first[0]["ts_utc_corrected"] if first else None,
        "last_event": last[0]["ts_utc_corrected"] if last else None,
        "by_type": by_type,
        "by_severity": by_sev,
        "by_host": by_host,
        "top_src_ips": top_ips,
        "evidence_files": ev_files,
        "total_gaps": gaps
    }

def gap_summary(conn) -> List[dict]:
    res = []
    evs = _dict_fetchall(conn.execute("SELECT id, filename, host, line_count FROM evidence"))
    for ev in evs:
        eid = ev["id"]
        parsed = conn.execute("SELECT COUNT(*) FROM events WHERE evidence_id = ?", (eid,)).fetchone()[0]
        gaps = _dict_fetchall(conn.execute("SELECT reason, COUNT(*) as c FROM parse_gaps WHERE evidence_id = ? GROUP BY reason", (eid,)))
        
        reasons = {g["reason"]: g["c"] for g in gaps}
        blank_lines = reasons.get("empty_line", 0)
        total = ev["line_count"] or 0
        
        pct = 0
        if total - blank_lines > 0:
            pct = parsed / (total - blank_lines) * 100
            
        res.append({
            "evidence_id": eid,
            "filename": ev["filename"],
            "host": ev["host"],
            "total_lines": total,
            "blank_lines": blank_lines,
            "parsed": parsed,
            "gaps": sum(reasons.values()),
            "parsed_pct": pct,
            "reasons": reasons
        })
    return res

def key_events(conn) -> List[dict]:
    high_med = _dict_fetchall(conn.execute("SELECT * FROM events WHERE severity IN ('high', 'medium')"))
    
    others = []
    ips = _dict_fetchall(conn.execute("SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL"))
    for ip_row in ips:
        ip = ip_row["src_ip"]
        ssh = _dict_fetchall(conn.execute("SELECT * FROM events WHERE src_ip = ? AND event_type = 'ssh_accepted_login' ORDER BY ts_utc_corrected ASC LIMIT 1", (ip,)))
        if ssh: others.append(ssh[0])
        
        web = _dict_fetchall(conn.execute("SELECT * FROM events WHERE src_ip = ? AND event_type LIKE 'web_%' AND event_type != 'web_request' ORDER BY ts_utc_corrected ASC LIMIT 1", (ip,)))
        if web: others.append(web[0])
        
    combined = {r["id"]: r for r in high_med + others}
    return sorted(combined.values(), key=lambda x: x["ts_utc_corrected"])

def skew_summary(conn) -> List[dict]:
    try:
        return _dict_fetchall(conn.execute("SELECT * FROM skew_corrections"))
    except sqlite3.OperationalError:
        return []

def evidence_manifest(conn) -> list[dict]:
    cur = conn.execute(
        "SELECT id, filename, stored_path, sha256, size_bytes, line_count, "
        "collected_at_utc, collector, host, source_type, declared_tz FROM evidence ORDER BY id")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def get_evidence(conn, evidence_id: int) -> dict:
    cur = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    rows = _dict_fetchall(cur)
    return rows[0] if rows else {}

def context_window(conn, event_id: int, seconds: int = 60) -> List[dict]:
    row = _dict_fetchall(conn.execute("SELECT ts_utc_corrected FROM events WHERE id = ?", (event_id,)))
    if not row:
        return []
        
    ts_str = row[0]["ts_utc_corrected"].replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        return []
        
    start = (ts - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end = (ts + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    cur = conn.execute("SELECT * FROM events WHERE ts_utc_corrected >= ? AND ts_utc_corrected <= ? ORDER BY ts_utc_corrected ASC", (start, end))
    return _dict_fetchall(cur)
