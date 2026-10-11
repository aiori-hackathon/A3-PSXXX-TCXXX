# PS-013 Prototype: Final Completion Plan

Repo: `Manasvi-hub/A3-PS013-TC067` | `main` = `704019f` | Checked: Sun 11 Oct 2026
Deadline: Wed 14 Oct. Plan: finish Sun 11 and Mon 12, freeze Tue 13, Wed 14 is buffer only.
People: **Gayatri** (evidence and parsing core), **Manasvi** (scenarios, timeline, viewer, report, evaluation).

Scope of this plan: the working prototype only (code, tests, evaluation data, demo). The slide deck is a separate task.

---

## 1. Verified status (fresh clone of `main`, run today)

| Prototype part | Result |
|---|---|
| Tests | 26 passed, 0 skipped |
| `ruff check src tests evaluation viewer scenarios` | clean |
| CLI | 8 commands: ingest, verify, build, skew, search, report, ui, run-all |
| `forensic run-all` | S1: 165 events, 4 gaps. S2: 106 events, 5 gaps. S3: 35 events, 0 gaps |
| Skew (S3) | db01 offset -421.5 s, 10 anchors, stdev 0.9 s, high confidence (true value -420 s) |
| Ground truth | 18 of 18 steps matched within 1.5 s |
| Evidence integrity | Tamper detected (`TAMPERED`, exit code 1) |
| Report | HTML + JSON + CSV, 8 sections, hashes shown, 0 "UNKNOWN" |
| Search | filters (`--type`, `--ip`, `--host`) and full-text work |
| Viewer (run headless on all 3 real cases) | no exceptions; 5 tabs; correct events/gaps/skew per case; skew toggle reorders db01 events; "Verify integrity" shows `5 OK, 0 problems`, and after tampering one file shows `4 OK, 1 problems` with that file marked TAMPERED |
| `forensic ui` | server starts, health check returns HTTP 200 |
| Robustness | A Windows-style input (CRLF line endings plus a UTF-8 BOM) parses identically to the original (106 events, same gaps) |
| Repo hygiene | only `main` plus the already-merged `a/core-setup`; no egg-info; docs and scripts in place |

**The prototype is functionally complete.** What is left is polish, evidence for the PS requirements, and delivery.

---

## 2. What is left

| # | Item | Owner | Why it matters | Time |
|---|---|---|---|---|
| 1 | Triage experiment: 6 timed sessions, then `summarize.py` | Both | PS requires a triage-time comparison against a manual baseline. `triage_results.csv` is header-only and `triage_summary.md` does not exist | 60 min |
| 2 | `docs/demo_script.md` | Manasvi | Required for the mentor demo | 20 min |
| 3 | Fix 2 false failures in `scripts/final_check.py` | Gayatri | Check 6 matches its own source text; check 7 rejects `mock_s3_db.py` in its allowed folder | 15 min |
| 4 | Viewer polish and a regression test (`tests/test_viewer_smoke.py`) | Manasvi | `use_container_width` is deprecated (Streamlit warns it was removed after 2025-12-31); the cached DB connection ignores the case path if a second case is opened in the same process | 40 min |
| 5 | Fresh-clone full check, tag, ownership transfer, branch cleanup | Both | Required for the certificate | 30 min |

Nothing here changes the engine (`ingest`, `parsers`, `normalize`, `skew`, `build`, `pipeline`).

---

## 3. Antigravity prompts (plain text; paste one at a time)

### Prompt 1: Gayatri, final_check fixes (branch `a/final-check-fix` from `main`)

```text
Repo: Python package forensic. Create branch a/final-check-fix from main. I am Gayatri. Edit ONLY scripts/final_check.py. Do not touch any other file.

Fix two false failures in this script:

1. Check 6 ("UNKNOWN and <<<<<<<"): it runs git grep for the text <<<<<<< which also matches the script's own source, so it always fails. Run git through subprocess with a list of arguments (no shell string, so it works on Windows). Use the line-anchored extended regex "^(<<<<<<< |>>>>>>> )" and the pathspecs ":!scripts/final_check.py" and ":!*.pdf". git grep exit code 1 means no match, which is a PASS; exit code 0 means conflict markers were found, which is a FAIL. Keep the UNKNOWN check on reports/*.html.
2. Check 7 (git hygiene): mock_s3_db.py now lives in scenarios/fixtures/ on purpose. Only fail if git ls-files lists a file named exactly "mock_s3_db.py" in the repository root. Keep the other forbidden items (egg-info, cases/, reports/, __pycache__) as they are.

Do not change any other check. Run "python scripts/final_check.py". Checks 1 to 7 must pass; checks 8 and 9 may still fail (missing demo script, triage summary, PDF, triage rows) but must be listed clearly. Run "ruff check scripts". Commit with message "fix(scripts): final_check false positives", push the branch, do not merge.
```

### Prompt 2: Manasvi, viewer polish + smoke test (branch `b/viewer-smoke` from `main`)

```text
Repo: Python package forensic, create branch b/viewer-smoke from main. I am Manasvi. Edit ONLY viewer/app.py and create tests/test_viewer_smoke.py. Do not touch any other file.

1. In viewer/app.py replace every use_container_width=True with width="stretch" (st.dataframe, st.altair_chart, st.plotly_chart and similar). Streamlit currently warns that use_container_width is deprecated. If the installed Streamlit does not accept width="stretch" for one of these calls, leave that call alone and tell me which one.
2. The database connection is cached with st.cache_resource without arguments, so a second case opened in the same process shows the first case's data. Make the cached function take the database path as a parameter (for example get_conn(db_path: str)) so each case gets its own connection, and pass it from the call site. Keep check_same_thread behaviour as it is today.
3. Create tests/test_viewer_smoke.py using streamlit.testing.v1.AppTest and forensic.pipeline.run_case. Use a module-level helper that builds a case with run_case(Path("scenarios/<name>/sources.json"), tmp_path / "case") and runs the viewer with monkeypatch.setattr(sys, "argv", ["app.py", "--case", str(case_dir)]); AppTest.from_file("viewer/app.py", default_timeout=60).run(). Tests (no try/except, no pytest.skip):
   a. parametrized over the three scenarios: no exceptions (at.exception empty), 5 tabs, and the "Events" metric equals the number of rows in the case.db events table, the "Gaps" metric equals the number of rows in parse_gaps (expected 4, 5 and 0).
   b. s3_clock_skew: the "Skew corrections" metric is 2; click the "Verify integrity" button, then at.success has exactly one message "5 OK, 0 problems" and at.error is empty.
   c. s3_clock_skew: make stored evidence file db01__access.log writable (os.chmod with stat.S_IWRITE), append one byte, click "Verify integrity", then at.error contains "1 problems" and a dataframe with a status column marks that file TAMPERED.
   d. s3_clock_skew: uncheck "Use skew-corrected time", rerun, no exception, and the timeline dataframe has a ts_utc column; with it checked it has ts_utc_corrected.
   e. opening two different cases in two AppTest runs in the same test process shows different "Events" metrics (regression for the cache bug in point 2).

Acceptance: python -m pytest -q (0 failed, 0 skipped), ruff check viewer tests, and python -m streamlit run viewer/app.py -- --case cases/s3_clock_skew still opens with no console errors. Commit with messages "fix(viewer): width=stretch and per-case connection cache" and "test(viewer): AppTest smoke tests", push the branch, do not merge.
```

### Prompt 3: Manasvi, demo script (same branch `b/viewer-smoke` or `b/demo-script`)

```text
Repo: Python package forensic. I am Manasvi. Create ONLY the file docs/demo_script.md (on branch b/demo-script from main). Title "Demo script (5 minutes)". Use a table with columns Time, Action, What to say, with these rows (keep the commands exactly):
0:00 | Show the README problem statement | Small teams rebuild timelines by hand; logs are messy, clocks drift, evidence integrity is fragile.
0:20 | forensic run-all | One command: verify, hash, parse and skew-correct three synthetic incidents.
0:50 | Open cases/s3_clock_skew/manifest.json | Every evidence file has a SHA-256 and the manifest itself is hashed.
1:10 | Make a stored file writable, append one byte, run: forensic verify --case cases/s3_clock_skew | Tampering is detected: TAMPERED, exit code 1. Then run forensic run-all again to restore.
1:40 | forensic ui --case cases/s3_clock_skew, Parsing gaps tab | Coverage and gaps are shown; nothing is silently dropped. S1 has 4 gaps, S2 has 5, S3 has 0.
2:10 | Clock skew tab, then untick and tick "Use skew-corrected time" on the Timeline tab | db01's clock runs 7 minutes fast; 10 anchor pairs give a median offset of -421.5 s (true -420 s). The db01 pivot login moves from 09:19:45 to about 09:12:44, which is 4 min 31 s after the webshell instead of 11 min 33 s.
3:00 | Event detail tab on that login | Raw line, evidence file, line number, byte offset and SHA-256: every event traces back to its source line.
3:30 | forensic search --case cases/s2_web_attack "UNION" and a filtered search | Searchable timeline.
3:50 | forensic report --case cases/s3_clock_skew --out reports/s3_clock_skew.html, open it | Hashes with verification status, skew with confidence, gaps, limitations.
4:20 | Open evaluation/triage_summary.md | Measured triage times against the grep baseline, with honest limitations.
4:45 | Show docs/pseudocode.md | The core algorithm in about 20 lines.
Add a "Fallback" section: keep cases/ and reports/ pre-built, keep a screen recording, and a "Before the demo" checklist: git pull, pip install -e ., forensic run-all, close other Streamlit servers (netstat -ano | findstr :850), have terminals open at the repo root. Add an "Anticipated questions" section with three short answers: Why anchor-based skew? (it needs no external reference clock and gives a confidence note); What does the tool not do? (live takeover, malware removal, certification, formats other than auth.log and Nginx); How do you know timestamps are right? (ground-truth tests: 18 of 18 steps within 1.5 s). Commit with message "docs: demo script", push the branch, do not merge.
```

---

## 4. The triage experiment (item 1, needs humans, do not skip)

The PS requires a triage-time comparison against a manual baseline. The tooling already exists: `evaluation/triage_timer.py` and `evaluation/summarize.py`.

| Scenario | Manual (grep, sort, less only) | Tool (CLI or viewer) |
|---|---|---|
| S1 | Gayatri | Manasvi |
| S2 | Manasvi | Gayatri |
| S3 | Gayatri | Manasvi |

If a third person (classmate) can do Manasvi's manual session on S2, use them: Manasvi wrote the scenarios and knows the answers.

Setup: `forensic run-all` (cases exist), then each session:

```
python evaluation/triage_timer.py --scenario s1_ssh_bruteforce --tester Gayatri --condition manual
python evaluation/triage_timer.py --scenario s2_web_attack     --tester Gayatri --condition tool
python evaluation/triage_timer.py --scenario s3_clock_skew     --tester Gayatri --condition manual
```
(Manasvi runs her three the same way with her name and conditions.)

Rules:
- Press Enter to start, Enter to stop, then type the answer. Wrong answers are recorded, not retried.
- Do not read `ground_truth.json`, the reports or the other condition's output before the session.
- Manual testers use only the raw files in `scenarios/<s>/`. For S3 the question about which event came first is the point: db01's clock is 7 minutes off.
- Do not edit numbers afterward. If the tool was slower or less accurate on something, report that.

After all 6 sessions (18 rows):
```
python evaluation/summarize.py
python evaluation/gap_report.py
git add evaluation && git commit -m "docs(eval): real triage timings and gap analysis" && git push
```
State the limitations in the summary: 6 sessions, small sample, testers know the tool, scenario-author bias.

---

## 5. Schedule

| When | Gayatri | Manasvi |
|---|---|---|
| **Sun 11, morning** | Prompt 1, open PR (15 min). Then triage sessions (3) | Prompts 2 and 3, open PRs (60 min). Then triage sessions (3) |
| **Sun 11, afternoon** | Merge PRs (merge commits, not squash). Run `python scripts/final_check.py`: only the triage and PDF checks should fail | `summarize.py`, `gap_report.py`, commit results |
| **Mon 12** | Second pass of the demo with Manasvi (twice, with `docs/demo_script.md`), including the tamper moment | Fix anything found; re-run everything from a clean clone |
| **Tue 13** | Freeze 18:00. `final_check.py` on a fresh clone must show all PASS (the PDF line passes once the deck is committed). Tag `v1.0-submission`. Confirm collaborator access | Ownership transfer to `aiori-hackathon`; delete merged branches |
| **Wed 14** | Buffer, submit | Buffer, submit |

Git rules: branch from `main`, merge commits (not squash), `git pull --rebase` before pushing, no edits to the other person's files.

---

## 6. Prototype definition of done (PS key requirements and the evidence)

| PS key requirement | Evidence in the repo |
|---|---|
| Process 2 different log formats | `parsers/auth_log.py`, `parsers/nginx.py`; tests per event type |
| Test against 3 synthetic incident scenarios | `scenarios/`; `tests/test_ground_truth.py` (18 of 18 steps) |
| Preserve original records, create normalised copies | read-only `evidence/` + `events` table with `ts_original` and `raw_line` |
| Generate evidence hashes | `manifest.json`, `manifest.sha256`, `verify`, viewer button |
| Handle timezone differences and clock skew | `normalize.py`, `skew.py`; S3 -421.5 s vs -420 s true |
| Identify and document parsing gaps | `parse_gaps` table, `evaluation/parsing_gap_analysis.md` |
| Compare triage time against a manual baseline | **pending: Section 4** |
| No live takeover, malware removal or certification | Limitations section in every report; README |
| Deliverable: log ingestion and parsing tool | `forensic ingest`, `build` |
| Deliverable: searchable incident timeline viewer | `forensic ui`, `forensic search` |
| Deliverable: incident-report export | `forensic report` (HTML, JSON, CSV) |
| Deliverable: parsing-gap and triage-time analysis | gap analysis done; triage summary pending |
| Deliverable: demo + pseudocode | `docs/demo_script.md` (Prompt 3), `docs/pseudocode.md` (done) |

---

## 7. Final submission checklist

- [ ] Prompts 1 to 3 merged; pytest 0 failed, 0 skipped; ruff clean
- [ ] `evaluation/triage_results.csv` has 18 real rows; `triage_summary.md` and `parsing_gap_analysis.md` committed
- [ ] `python scripts/final_check.py` all PASS on a fresh clone (the PDF check passes once the deck is committed)
- [ ] Demo rehearsed twice, tamper moment practiced, fallback ready
- [ ] `aiori-hackathon` accepted as collaborator; both teammates accepted
- [ ] Repo private and named `A3-PS013-TC067`
- [ ] Ownership transferred to `aiori-hackathon` (last step, by Manasvi); Gayatri can still push
- [ ] Merged branches deleted; tag `v1.0-submission` pushed

## 8. If time runs short
Cut the viewer polish (Prompt 2) before anything else. Never cut: the real triage numbers, the demo script, the final check on a fresh clone, the ownership transfer.
