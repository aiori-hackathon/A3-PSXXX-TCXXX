import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from forensic.pipeline import run_case


def run_viewer_case(scenario_name: str, case_dir: Path, monkeypatch) -> tuple[AppTest, Path]:
    sources_json = Path(f"scenarios/{scenario_name}/sources.json")
    run_case(sources_json, case_dir)
    monkeypatch.setattr(sys, "argv", ["app.py", "--case", str(case_dir)])
    app_path = (Path(__file__).parent.parent / "viewer" / "app.py").resolve()
    at = AppTest.from_file(str(app_path), default_timeout=60).run()
    return at, case_dir


@pytest.mark.parametrize(
    ("scenario", "expected_gaps"),
    [
        ("s1_ssh_bruteforce", 4),
        ("s2_web_attack", 5),
        ("s3_clock_skew", 0),
    ],
)
def test_viewer_scenarios_smoke(scenario, expected_gaps, tmp_path, monkeypatch):
    case_dir = tmp_path / f"case_{scenario}"
    at, _ = run_viewer_case(scenario, case_dir, monkeypatch)

    assert len(at.exception) == 0
    assert len(at.tabs) == 5

    conn = sqlite3.connect(case_dir / "case.db")
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_gaps = conn.execute("SELECT COUNT(*) FROM parse_gaps").fetchone()[0]
    conn.close()

    assert total_gaps == expected_gaps
    # Metric 0 is Events, Metric 3 is Gaps
    assert at.metric[0].value == str(total_events)
    assert at.metric[3].value == str(total_gaps)


def test_viewer_s3_skew_and_integrity(tmp_path, monkeypatch):
    case_dir = tmp_path / "case_s3"
    at, _ = run_viewer_case("s3_clock_skew", case_dir, monkeypatch)

    assert len(at.exception) == 0
    # Metric 4 is Skew corrections
    assert at.metric[4].value == "2"

    at.button[0].click().run()
    assert len(at.error) == 0
    assert len(at.success) == 1
    assert at.success[0].value == "5 OK, 0 problems"


def test_viewer_s3_tamper_detection(tmp_path, monkeypatch):
    case_dir = tmp_path / "case_s3_tamper"
    at, _ = run_viewer_case("s3_clock_skew", case_dir, monkeypatch)

    evidence_file = case_dir / "evidence" / "db01__access.log"
    evidence_file.chmod(evidence_file.stat().st_mode | stat.S_IWRITE)
    with open(evidence_file, "ab") as f:
        f.write(b"X")

    at.button[0].click().run()
    assert len(at.error) == 1
    assert "1 problems" in at.error[0].value

    tampered_found = False
    for df_element in at.dataframe:
        df = df_element.value
        if "status" in df.columns:
            if "TAMPERED" in df["status"].values:
                tampered_found = True
                break
    assert tampered_found


def test_viewer_s3_toggle_skew_corrected(tmp_path, monkeypatch):
    case_dir = tmp_path / "case_s3_toggle"
    at, _ = run_viewer_case("s3_clock_skew", case_dir, monkeypatch)

    assert "ts_utc_corrected" in at.dataframe[0].value.columns

    at.checkbox[0].uncheck().run()
    assert len(at.exception) == 0
    assert "ts_utc" in at.dataframe[0].value.columns


def test_viewer_two_cases_connection_cache(tmp_path, monkeypatch):
    case_dir1 = tmp_path / "case_s1"
    at1, _ = run_viewer_case("s1_ssh_bruteforce", case_dir1, monkeypatch)

    case_dir2 = tmp_path / "case_s3"
    at2, _ = run_viewer_case("s3_clock_skew", case_dir2, monkeypatch)

    assert at1.metric[0].value != at2.metric[0].value
