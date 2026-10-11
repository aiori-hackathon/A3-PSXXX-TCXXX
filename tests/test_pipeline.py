from pathlib import Path

from forensic.pipeline import run_case


def test_pipeline_run_case(tmp_path: Path):
    sources_json = Path(__file__).parent / "fixtures" / "sources.json"
    case_dir = tmp_path / "case_test"

    # First run
    res1 = run_case(sources_json, case_dir, collector="tester")
    assert res1["case_id"] == "fixture_case"
    assert res1["verified"] is True
    assert len(res1["build"]) > 0
    assert len(res1["skew"]) > 0

    # Ensure evidence files are read-only
    evidence_files = list((case_dir / "evidence").iterdir())
    assert len(evidence_files) > 0
    for ef in evidence_files:
        assert (ef.stat().st_mode & 0o777) == 0o444

    # Second run into the same directory: must recreate case cleanly even with read-only files
    res2 = run_case(sources_json, case_dir, collector="tester")
    assert res2["case_id"] == "fixture_case"
    assert res2["verified"] is True
    assert len(res2["build"]) == len(res1["build"])
    assert len(res2["skew"]) == len(res1["skew"])
