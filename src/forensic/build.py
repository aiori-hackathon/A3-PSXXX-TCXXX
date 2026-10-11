from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import db
from .models import Event, ParseContext, ParseGap
from .parsers import REGISTRY


def iterate_with_offsets(file_path: Path):
    """Yield (line_no, byte_offset, line_str)."""
    with open(file_path, "rb") as f:
        line_no = 1
        byte_offset = 0
        for line_bytes in f:
            try:
                line_str = line_bytes.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            yield line_no, byte_offset, line_str
            line_no += 1
            byte_offset += len(line_bytes)


def build(case_dir: Path) -> list[dict]:
    """Parse all evidence files into the SQLite DB.

    Returns a list of per-file stats dicts with keys:
        evidence_id, filename, host, total_lines, parsed, gaps, parsed_pct, gap_reasons.
    """
    conn = db.connect(case_dir)

    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM parse_gaps")
    conn.execute("DELETE FROM skew_corrections")
    conn.commit()

    meta_row = conn.execute("SELECT value FROM case_meta WHERE key = 'year_hint'").fetchone()
    year_hint = int(meta_row["value"]) if meta_row else None  # may be None — that's fine

    evidence_rows = conn.execute(
        "SELECT id, filename, stored_path, host, source_type, declared_tz FROM evidence"
    ).fetchall()

    print(
        f"{'Evidence ID':<5} | {'Filename':<30} | {'Host':<10} | "
        f"{'Parsed':<8} | {'Gaps':<8} | {'% Parsed':<10} | {'Blanks':<7}"
    )
    print("-" * 90)

    all_stats: list[dict] = []

    for ev in evidence_rows:
        evidence_id = ev["id"]
        source_type = ev["source_type"]
        stored_path = case_dir / ev["stored_path"]

        parser_cls = REGISTRY.get(source_type)
        if not parser_cls:
            print(f"Unknown parser for source_type: {source_type}")
            continue

        parser = parser_cls()
        mtime_stamp = stored_path.stat().st_mtime
        mtime_utc = datetime.fromtimestamp(mtime_stamp, timezone.utc)

        ctx = ParseContext(
            host=ev["host"],
            source_type=source_type,
            declared_tz=ev["declared_tz"],
            year_hint=year_hint,
            file_mtime_utc=mtime_utc,
        )

        events: list[Event] = []
        gaps: list[ParseGap] = []
        gap_reasons: dict[str, int] = defaultdict(int)

        for line_no, byte_offset, line in iterate_with_offsets(stored_path):
            if "\ufffd" in line:  # from errors="replace"
                gaps.append(ParseGap(line_no, "encoding_error", line))
                gap_reasons["encoding_error"] += 1
                continue

            result = parser.parse_line(line, line_no, byte_offset, ctx)
            if isinstance(result, Event):
                events.append(result)
            elif isinstance(result, ParseGap):
                gaps.append(result)
                gap_reasons[result.reason] += 1

        db.insert_events(conn, evidence_id, events)
        db.insert_gaps(conn, evidence_id, gaps)

        blank_count = gap_reasons.get("empty_line", 0)
        non_empty_total = len(events) + len(gaps) - blank_count
        parsed_pct = (len(events) / non_empty_total * 100) if non_empty_total > 0 else 0.0
        total_lines = len(events) + len(gaps)

        stats = {
            "evidence_id": evidence_id,
            "filename": ev["filename"],
            "host": ev["host"],
            "total_lines": total_lines,
            "blank_lines": blank_count,
            "parsed": len(events),
            "gaps": len(gaps),
            "parsed_pct": round(parsed_pct, 1),
            "gap_reasons": dict(gap_reasons),
        }
        all_stats.append(stats)

        print(
            f"{evidence_id:<5} | {ev['filename']:<30} | {ev['host']:<10} | "
            f"{len(events):<8} | {len(gaps):<8} | {parsed_pct:>6.1f}%   | {blank_count:<7}"
        )
        if gaps:
            non_empty_reasons = {k: v for k, v in gap_reasons.items() if k != "empty_line"}
            if non_empty_reasons:
                print(f"  Gap reasons (non-blank): {non_empty_reasons}")
            if blank_count:
                print(f"  ({blank_count} blank lines)")

    db.rebuild_fts(conn)
    print("FTS index rebuilt.")
    print("Build complete.")
    conn.close()

    return all_stats
