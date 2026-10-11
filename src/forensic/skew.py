import statistics
from datetime import datetime, timezone
from pathlib import Path

from . import db


def parse_utc(ts_str: str) -> datetime:
    # ISO-8601 UTC string like "2026-10-08T09:12:44.000Z"
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def _parse_offset_str(s: str) -> tuple[str, float]:
    """Parse 'host=seconds' string, return (host, offset_s). Raises ValueError on bad format."""
    if "=" not in s:
        raise ValueError(f"Bad --offset format '{s}': expected host=seconds, e.g. db01=-420")
    host, _, val = s.partition("=")
    host = host.strip()
    val = val.strip()
    if not host:
        raise ValueError(f"Bad --offset format '{s}': host part is empty")
    try:
        offset = float(val)
    except ValueError:
        raise ValueError(f"Bad --offset format '{s}': '{val}' is not a number")
    return host, offset


def apply_offset(conn, host: str, offset_s: float) -> None:
    """Update ts_utc_corrected and skew_offset_s for all events on *host*."""
    rows = conn.execute("SELECT id, ts_utc FROM events WHERE host = ?", (host,)).fetchall()
    updates = []
    for r in rows:
        ts = parse_utc(r["ts_utc"])
        ts_corrected_dt = datetime.fromtimestamp(ts.timestamp() + offset_s, timezone.utc)
        ts_corrected_str = ts_corrected_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        updates.append((offset_s, ts_corrected_str, r["id"]))
    conn.executemany(
        "UPDATE events SET skew_offset_s = ?, ts_utc_corrected = ? WHERE id = ?", updates
    )


def skew(
    case_dir: Path,
    reference_host: str | None = None,
    manual_offsets: str | list[str] | None = None,
    offsets: str | list[str] | None = None,
) -> list[dict]:
    if offsets is not None and manual_offsets is None:
        manual_offsets = offsets

    conn = db.connect(case_dir)
    try:
        hosts = [row["host"] for row in conn.execute("SELECT DISTINCT host FROM events").fetchall()]
        if not hosts:
            print("No hosts found in events.")
            return []

        # Resolve reference host: argument > case_meta > host with most events
        if not reference_host:
            meta_row = conn.execute(
                "SELECT value FROM case_meta WHERE key = 'reference_host'"
            ).fetchone()
            if meta_row:
                reference_host = meta_row["value"]
                print(f"Using reference host from case metadata: {reference_host}")
            else:
                # Fall back to host with most events
                row = conn.execute(
                    "SELECT host, COUNT(*) AS cnt FROM events GROUP BY host ORDER BY cnt DESC LIMIT 1"
                ).fetchone()
                reference_host = row["host"]
                print(f"No reference host specified; using host with most events: {reference_host}")
        else:
            print(f"Reference host: {reference_host}")

        if reference_host not in hosts:
            print(f"Reference host '{reference_host}' not found in events.")
            return []

        # Parse manual offsets (support single string or list of strings)
        parsed_manual: dict[str, float] = {}
        if manual_offsets:
            if isinstance(manual_offsets, str):
                manual_offsets = [manual_offsets]
            for item in manual_offsets:
                try:
                    h, off = _parse_offset_str(item)
                    parsed_manual[h] = off
                except ValueError as exc:
                    print(str(exc))
                    return []

        conn.execute("DELETE FROM skew_corrections")

        # Write reference host row with offset_s=0
        conn.execute(
            "INSERT INTO skew_corrections "
            "(host, reference_host, offset_s, method, anchor_count, confidence_note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (reference_host, reference_host, 0.0, "none", 0, "reference host"),
        )
        apply_offset(conn, reference_host, 0.0)

        for host in hosts:
            if host == reference_host:
                continue

            if host in parsed_manual:
                offset = parsed_manual[host]
                conn.execute(
                    "INSERT INTO skew_corrections "
                    "(host, reference_host, offset_s, method, anchor_count, confidence_note) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (host, reference_host, offset, "manual", 0, "operator supplied"),
                )
                apply_offset(conn, host, offset)
                print(f"  {host}: manual offset {offset:+.1f}s applied")
                continue

            # Anchor-based estimation
            h_events = conn.execute(
                """
                SELECT id, ts_utc, src_ip, event_type, detail, username
                FROM events
                WHERE host = ? AND src_ip IS NOT NULL
                """,
                (host,),
            ).fetchall()

            r_events = conn.execute(
                """
                SELECT id, ts_utc, src_ip, event_type, detail, username
                FROM events
                WHERE host = ? AND src_ip IS NOT NULL
                """,
                (reference_host,),
            ).fetchall()

            # Group ref events by anchor key; each ref event used at most once (one-to-one)
            r_by_key: dict = {}
            for r in r_events:
                key = (r["src_ip"], r["event_type"], r["detail"], r["username"])
                r_by_key.setdefault(key, []).append({"row": r, "used": False})

            anchors = []
            window = 1800  # 30 min

            for h in h_events:
                key = (h["src_ip"], h["event_type"], h["detail"], h["username"])
                if key not in r_by_key:
                    continue
                h_ts = parse_utc(h["ts_utc"])
                best_diff = None
                best_idx = None

                for idx, candidate in enumerate(r_by_key[key]):
                    if candidate["used"]:
                        continue
                    r_ts = parse_utc(candidate["row"]["ts_utc"])
                    diff_s = (r_ts - h_ts).total_seconds()
                    if abs(diff_s) <= window:
                        if best_diff is None or abs(diff_s) < abs(best_diff):
                            best_diff = diff_s
                            best_idx = idx

                if best_diff is not None:
                    anchors.append(best_diff)
                    r_by_key[key][best_idx]["used"] = True  # one-to-one pairing

            n = len(anchors)
            if n >= 3:
                offset = statistics.median(anchors)
                stdev = statistics.pstdev(anchors) if n > 1 else 0.0

                if stdev < 2 and n >= 5:
                    confidence = "high"
                elif stdev < 10:
                    confidence = "medium"
                else:
                    confidence = "low"

                note = (
                    f"{n} anchors, median {offset:.1f}s, stdev {stdev:.1f}s ({confidence}). "
                    "Assumes paired events within 1800s window."
                )
                conn.execute(
                    "INSERT INTO skew_corrections "
                    "(host, reference_host, offset_s, method, anchor_count, stdev_s, confidence_note) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (host, reference_host, offset, "anchor_median", n, stdev, note),
                )
                apply_offset(conn, host, offset)
                print(f"  {host}: anchor_median offset {offset:+.1f}s ({confidence}, n={n})")
            else:
                conn.execute(
                    "INSERT INTO skew_corrections "
                    "(host, reference_host, offset_s, method, anchor_count, confidence_note) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        host,
                        reference_host,
                        0.0,
                        "none",
                        n,
                        "insufficient anchors; no correction applied. Use --offset to set manually.",
                    ),
                )
                apply_offset(conn, host, 0.0)
                print(f"  {host}: insufficient anchors ({n}<3), no correction applied")

        rows = conn.execute(
            "SELECT host, reference_host, offset_s, method, anchor_count, confidence_note "
            "FROM skew_corrections ORDER BY host"
        ).fetchall()
        result_rows = [
            {
                "host": r["host"],
                "reference_host": r["reference_host"],
                "offset_s": r["offset_s"],
                "method": r["method"],
                "anchor_count": r["anchor_count"],
                "confidence_note": r["confidence_note"],
            }
            for r in rows
        ]

        conn.commit()
        print("Skew estimation complete.")
        return result_rows
    finally:
        conn.close()
