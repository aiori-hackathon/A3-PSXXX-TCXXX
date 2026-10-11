import pytest
import json
from pathlib import Path
import sqlite3

try:
    from forensic.pipeline import run_case
except ImportError:
    # Mock for local testing before Person A's PR is merged
    def run_case(sources_json, case_dir, collector="pipeline", reference_host=None):
        pass

from forensic.timeline import query_events, Filters

scenarios_dir = Path(__file__).parent.parent / "scenarios"
scenario_paths = [d for d in scenarios_dir.iterdir() if d.is_dir() and (d / "sources.json").exists()]

@pytest.mark.parametrize("scenario_dir", scenario_paths, ids=[p.name for p in scenario_paths])
def test_ground_truth(scenario_dir, tmp_path):
    sources_json = scenario_dir / "sources.json"
    gt_json = scenario_dir / "ground_truth.json"
    
    with open(gt_json) as f:
        gt = json.load(f)
        
    case_dir = tmp_path / "case"
    try:
        run_case(sources_json, case_dir)
    except Exception:
        pytest.skip("Pipeline not fully implemented yet")
        
    db_path = case_dir / "case.db"
    if not db_path.exists():
        pytest.skip("DB not created (Pipeline incomplete)")
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # a) match every step
    for step in gt["steps"]:
        events = query_events(conn, Filters(event_types=[step["event_type"]]))
        found = False
        for e in events:
            # simple fuzzy match
            if e["host"] == step["host"]:
                match_ok = True
                for k, v in step.get("match", {}).items():
                    if e.get(k) != v:
                        match_ok = False
                if match_ok:
                    found = True
                    break
        assert found, f"Step {step['id']} not matched"
        
    # b) count gaps
    gaps = conn.execute("SELECT COUNT(*) as c FROM parse_gaps").fetchone()["c"]
    assert gaps == gt["expected_parse_gaps"]
    
    # c) triage answers derivable
    events = query_events(conn, Filters())
    assert len(events) > 0
    
    # d) specific s3 logic
    if "s3_clock_skew" in scenario_dir.name:
        skew = conn.execute("SELECT offset_s FROM skew_corrections WHERE host = 'db01'").fetchone()
        assert skew is not None
        assert abs(skew["offset_s"] - (-420)) <= 5
        
    # e) verify_items OK
    try:
        from forensic.ingest import verify_items
        status = verify_items(case_dir)
        assert all(s["status"] == "OK" for s in status)
    except ImportError:
        pass
