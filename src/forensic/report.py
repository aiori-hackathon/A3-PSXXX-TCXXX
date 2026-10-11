from jinja2 import Environment, FileSystemLoader
import sqlite3
from pathlib import Path
import json
import csv
from forensic.timeline import Filters, query_events, key_events, summary_stats, gap_summary, skew_summary, evidence_manifest

def get_verification(case_dir: Path):
    try:
        from forensic.ingest import verify_items
        return verify_items(case_dir)
    except ImportError:
        # Mocking for testing if ingest isn't available
        return []

def generate_report(case_dir: Path, out_html: Path, out_json: Path = None, out_csv: Path = None):
    db_path = case_dir / "case.db"
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found at {db_path}")
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    events = query_events(conn, Filters())
    key_evs = key_events(conn)
    stats = summary_stats(conn)
    gaps = gap_summary(conn)
    skews = skew_summary(conn)
    manifest = evidence_manifest(conn)
    verify_status = get_verification(case_dir)
    
    # map verify status
    v_map = {v["file"]: v["status"] for v in verify_status}
    for m in manifest:
        m["verify_status"] = v_map.get(m["stored_path"], "UNKNOWN")
        m["status"] = m["verify_status"]
        
    manifest_paths = {m["stored_path"] for m in manifest}
    integrity_checks = [v for v in verify_status if v["file"] not in manifest_paths]

    templates_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    template = env.get_template("report.html.j2")
    
    html_content = template.render(
        case_id=case_dir.name,
        events=events,
        key_events=key_evs,
        stats=stats,
        gaps=gaps,
        skews=skews,
        manifest=manifest,
        integrity_checks=integrity_checks,
        limitations="Limitations & scope: No live endpoint takeover, no malware removal, not forensically certified, declared-timezone and anchor-simultaneity assumptions, synthetic data."
    )
    
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html_content, encoding="utf-8")
    
    if out_json:
        data = {
            "case": case_dir.name,
            "summary": stats,
            "evidence": manifest,
            "skew": skews,
            "key_events": key_evs,
            "gaps": gaps,
            "limitations": "Limitations & scope: No live endpoint takeover, no malware removal, not forensically certified, declared-timezone and anchor-simultaneity assumptions, synthetic data."
        }
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
        
    if out_csv:
        ev_id_to_path = {m["id"]: m["stored_path"] for m in manifest}
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with open(out_csv, 'w', newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ts_utc_corrected", "ts_utc", "ts_original", "host", "event_type", "severity", "src_ip", "username", "message", "evidence_file", "line_no"])
            for e in events:
                writer.writerow([
                    e["ts_utc_corrected"], e["ts_utc"], e["ts_original"], e["host"],
                    e["event_type"], e["severity"], e.get("src_ip", ""), e.get("username", ""),
                    e["message"], ev_id_to_path.get(e.get("evidence_id"), ""), e.get("line_no", "")
                ])
    
    conn.close()
