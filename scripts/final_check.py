import os
import sys
import subprocess
import stat
import glob
import csv
import json
import hashlib
import shutil
from pathlib import Path

def run_cmd(cmd):
    env = os.environ.copy()
    scripts_dir = str(Path(sys.executable).parent)
    env["PATH"] = scripts_dir + os.pathsep + env.get("PATH", "")
    if isinstance(cmd, list) and cmd and cmd[0] == "python":
        cmd = [sys.executable] + cmd[1:]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

def check_1():
    print("Check 1: pytest ... ", end="")
    res = run_cmd(["python", "-m", "pytest", "-q"])
    if res.returncode == 0 and "failed" not in res.stdout and "skipped" not in res.stdout:
        print("PASS")
        return True
    print("FAIL")
    return False

def check_2():
    print("Check 2: ruff ... ", end="")
    res = run_cmd(["python", "-m", "ruff", "check", "src", "tests"])
    if res.returncode == 0:
        print("PASS")
        return True
    print("FAIL")
    return False

def check_3():
    print("Check 3: forensic --help ... ", end="")
    res = run_cmd(["forensic", "--help"])
    expected = ["ingest", "verify", "build", "skew", "search", "report", "ui", "run-all"]
    if res.returncode == 0 and all(cmd in res.stdout for cmd in expected):
        print("PASS")
        return True
    print("FAIL")
    return False

def check_4():
    print("Check 4: forensic run-all ... ", end="")
    res = run_cmd(["forensic", "run-all"])
    if res.returncode != 0:
        print("FAIL (exit non-zero)")
        return False

    out = res.stdout + res.stderr
    if "anchor_median" not in out:
        print("FAIL (missing anchor_median)")
        return False

    # Check for gaps numbers
    if not all(str(n) in out for n in [0, 4, 5]):
        print("FAIL (missing 4, 5, or 0)")
        return False

    print("PASS")
    return True

def check_5():
    print("Check 5: Tamper test ... ", end="")
    target_dir = Path("cases/s3_clock_skew/evidence")
    if not target_dir.exists():
        print("FAIL (no evidence dir)")
        return False

    files = [f for f in target_dir.iterdir() if f.is_file()]
    if not files:
        print("FAIL (no files)")
        return False

    target_file = files[0]

    # Make writable
    target_file.chmod(target_file.stat().st_mode | stat.S_IWRITE)
    # Append byte
    with open(target_file, "ab") as f:
        f.write(b"X")

    res = run_cmd(["forensic", "verify", "--case", "cases/s3_clock_skew"])
    if res.returncode != 1 or "TAMPERED" not in (res.stdout + res.stderr):
        print("FAIL")
        run_cmd(["forensic", "run-all"])  # restore
        return False

    run_cmd(["forensic", "run-all"])  # restore
    print("PASS")
    return True

def check_6():
    print("Check 6: UNKNOWN and <<<<<<< ... ", end="")
    for report_file in glob.glob("reports/*.html"):
        try:
            with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                if "UNKNOWN" in f.read():
                    print("FAIL (UNKNOWN found)")
                    return False
        except Exception:
            pass

    res = subprocess.run(
        ["git", "grep", "-E", "^(<<<<<<< |>>>>>>> )", "--", ":!scripts/final_check.py", ":!*.pdf"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if res.returncode == 0:
        print("FAIL (conflict markers found)")
        return False

    print("PASS")
    return True

def check_7():
    print("Check 7: Git hygiene ... ", end="")
    res = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    files = res.stdout.splitlines()
    forbidden = ["egg-info", "cases/", "reports/", "__pycache__"]
    for f in files:
        f_norm = f.replace("\\", "/")
        if f_norm == "mock_s3_db.py":
            print(f"FAIL (mock_s3_db.py in root: {f})")
            return False
        for bad in forbidden:
            if bad in f_norm:
                print(f"FAIL ({bad} found in {f})")
                return False

    print("PASS")
    return True

def check_8():
    print("Check 8: Required files ... ", end="")
    reqs = [
        "README.md",
        "docs/pseudocode.md",
        "docs/demo_script.md",
        "evaluation/triage_summary.md",
        "evaluation/parsing_gap_analysis.md",
    ]
    failed = False
    for r in reqs:
        if not Path(r).exists():
            print(f"\nFAIL: {r} missing")
            failed = True

    pdf_path = Path("A3-PS013-TC067.pdf")
    if not pdf_path.exists():
        if Path("docs/A3-PS013-TC067.pdf").exists():
            pdf_path = Path("docs/A3-PS013-TC067.pdf")
        else:
            print("\nFAIL: A3-PS013-TC067.pdf missing")
            failed = True
            pdf_path = None

    if failed:
        return False

    template_path = Path("Proposed-structure-hackathon.pdf")
    if template_path.exists() and pdf_path:
        pdf_hash = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
        tmpl_hash = hashlib.sha256(template_path.read_bytes()).hexdigest()
        if pdf_hash == tmpl_hash:
            print("FAIL (A3-PS013-TC067.pdf is still the unmodified template)")
            return False

    if shutil.which("pdftotext"):
        res = subprocess.run(
            ["pdftotext", str(pdf_path), "-"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode != 0:
            print("FAIL (pdftotext extraction failed)")
            return False
        extracted = res.stdout
        if "A3-PS013-TC067" not in extracted:
            print("FAIL (extracted text does not contain A3-PS013-TC067)")
            return False
        for placeholder in ["John Doe", "Lorem ipsum", "A3-PS001-TC001"]:
            if placeholder in extracted:
                print(f"FAIL (extracted text contains '{placeholder}')")
                return False
    else:
        print("(WARN: pdftotext missing) ", end="")

    print("PASS")
    return True

def check_9():
    print("Check 9: Triage results ... ", end="")

    # Check scenarios/*/ground_truth.json triage_questions
    gt_files = sorted(glob.glob("scenarios/*/ground_truth.json"))
    for gt_file in gt_files:
        try:
            with open(gt_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            triage_questions = data.get("triage_questions", [])
            for q_item in triage_questions:
                ans = q_item.get("answer")
                if ans is None or str(ans).strip().upper() == "N/A":
                    print(f"FAIL (N/A answer in {gt_file.replace(os.sep, '/')} triage_questions)")
                    return False
        except Exception as e:
            print(f"FAIL (error reading {gt_file}: {e})")
            return False

    # Check evaluation/triage_results.csv
    csv_path = Path("evaluation/triage_results.csv")
    if not csv_path.exists():
        print("FAIL (missing)")
        return False

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        if len(reader) != 18:
            print(f"FAIL (expected 18 data rows, got {len(reader)})")
            return False

        for row in reader:
            if any("Used grep and sort" in str(val) for val in row.values()):
                print("FAIL (Used grep and sort found)")
                return False

            # seconds must be numeric and greater than 0
            sec_str = row.get("seconds", "")
            try:
                sec_val = float(sec_str)
                if sec_val <= 0:
                    print(f"FAIL (seconds must be greater than 0, got {sec_val})")
                    return False
            except (ValueError, TypeError):
                print(f"FAIL (seconds must be numeric, got '{sec_str}')")
                return False

            # correct must be True/False (case-insensitive)
            corr_str = str(row.get("correct", "")).strip().lower()
            if corr_str not in ("true", "false"):
                print(f"FAIL (correct must be True/False, got '{row.get('correct')}')")
                return False

        # made of 6 sessions of 3 rows each, one session per (scenario, condition, tester)
        sessions = {}
        for row in reader:
            key = (row["scenario"].strip(), row["condition"].strip().lower(), row["tester"].strip())
            sessions.setdefault(key, []).append(row)

        if len(sessions) != 6:
            print(f"FAIL (expected 6 sessions, got {len(sessions)})")
            return False

        for key, s_rows in sessions.items():
            if len(s_rows) != 3:
                print(f"FAIL (session {key} has {len(s_rows)} rows, expected 3)")
                return False

        # each of s1_ssh_bruteforce, s2_web_attack, s3_clock_skew having one manual and one tool session
        expected_scenarios = ["s1_ssh_bruteforce", "s2_web_attack", "s3_clock_skew"]
        scenario_conditions = {}
        for (scen, cond, _tester) in sessions.keys():
            scenario_conditions.setdefault(scen, []).append(cond)

        for scen in expected_scenarios:
            if scen not in scenario_conditions:
                print(f"FAIL (missing scenario {scen})")
                return False
            conds = sorted(scenario_conditions[scen])
            if conds != ["manual", "tool"]:
                print(f"FAIL (scenario {scen} must have one manual and one tool session, got {conds})")
                return False

    except Exception as e:
        print(f"FAIL (read error: {e})")
        return False

    print("PASS")
    return True

def check_10():
    print("Check 10: Repo root hygiene ... ", end="")
    res = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if res.returncode != 0:
        print("FAIL (git ls-files non-zero exit)")
        return False

    allowed = {
        "README.md",
        "pyproject.toml",
        "requirements.txt",
        ".gitignore",
        "A3-PS013-TC067.pdf",
        "Proposed-structure-hackathon.pdf",
    }

    files = res.stdout.splitlines()
    root_files = [f for f in files if "/" not in f and "\\" not in f]
    stray = [f for f in root_files if f not in allowed]
    if stray:
        print(f"FAIL (stray root files: {', '.join(sorted(stray))})")
        return False

    print("PASS")
    return True

def main():
    checks = [
        check_1, check_2, check_3, check_4, check_5,
        check_6, check_7, check_8, check_9, check_10
    ]

    passed = 0
    failed = 0

    for check_fn in checks:
        if check_fn():
            passed += 1
        else:
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
