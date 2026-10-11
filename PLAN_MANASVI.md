# PS-013 Merge-Ready Plan (Manasvi), from Sat 10 Oct to Wed 14 Oct

> **Your role: scenarios, timeline, report, viewer, evaluation, deck.** Branches: `b/scenario-fixes` first, then `b/timeline-report`, `b/viewer`, `b/tests-eval`.
>
> **Sections 0 to 5 are identical in both people's plans. They are the alignment contract that removes the current conflicts. Change them only through a PR that both of you approve.**
> Mapping: **A = Gayatri** (evidence and parsing), **B = Manasvi** (scenarios, timeline, viewer, report, evaluation).

---

## 0. Where we are right now (verified by running the code)

| Area | State |
|---|---|
| `main` | Manasvi's work: scenario generator, 3 scenarios, `timeline.py`, stub `report.py`, Streamlit viewer, `cli_analysis.py`, plus her own bootstrap (stub `db.py`, `models.py`, `cli_evidence.py`) |
| `a/core-setup` | Gayatri's work: real `ingest`, `verify`, parsers, `normalize`, `build`, `skew`, tests. **Not merged. 9 add/add conflicts with `main`.** |
| Bugs in A's code | skew crashes (`timezone` import); re-ingest empties the manifest so `verify` passes on tampered data; SQLi on `*.php?` tagged as webshell; leap-day parsing; skew picks an arbitrary reference host |
| Bugs in B's code | generator writes `Oct  3  2:04:07` (non-padded hour) so S1 parses 1 of 259 lines; thin ground truth; S3 `web01/auth.log` empty; S3 attack URLs not classifiable; report is a stub; `summary_stats`/`gap_summary` are stubs; FTS query built by f-string; `report.py` loads templates from the current directory |
| Missing | tests, evaluation, deck PDF, demo script, pseudocode, README |

---

## 1. Merge order (follow exactly, this is what makes the branches merge cleanly)

```
Step 1  Manasvi  b/scenario-fixes  -> main     (touches ONLY scenarios/; target: Sat noon)
Step 2  Gayatri  a/core-setup: finish fixes, then `git merge origin/main`, resolve conflicts
                 using the table in section 2, run the full test suite -> PR into main
                 (target: Sat evening). Manasvi reviews and merges.
Step 3  Manasvi  rebase her feature branches on the new main, then PRs:
                 b/timeline-report -> b/viewer -> b/tests-eval  (Sat night to Mon)
Step 4  Everyone Tue 13 evening: code freeze, tag v1.0-submission on main
```

Rules while this is in progress:
- **Until Step 2 is merged, Manasvi does not edit any file outside `scenarios/`** (no edits to `models.py`, `db.py`, `schema.sql`, `cli*.py`, `pyproject.toml`, `.gitignore`, `CODEOWNERS`). That removes the conflict source.
- **Shared files are owned by Gayatri:** `models.py`, `schema.sql`, `db.py`, `pyproject.toml`, `.gitignore`, `.github/CODEOWNERS`, `cli.py`, `pipeline.py`. Manasvi requests changes to them through an issue or PR to Gayatri.
- **Manasvi's files:** `scenarios/`, `timeline.py`, `report.py`, `templates/`, `cli_analysis.py`, `viewer/`, `evaluation/`, `docs/` (except the implementation guides), `tests/test_ground_truth.py`, `tests/test_timeline_report.py`.
- Never force-push a shared branch. Squash-merge PRs. Rebase on `origin/main` each morning.

---

## 2. Conflict resolution table (for Gayatri's merge in Step 2)

Run: `git checkout a/core-setup && git fetch && git merge origin/main`. Resolve each file like this:

| File | Resolution |
|---|---|
| `src/forensic/db.py` | **Gayatri's version.** Main's is a stub where every function is `pass`. |
| `src/forensic/models.py` | **Gayatri's version.** Main's differs only in typing style (`X \| None`); both match the contract. |
| `src/forensic/schema.sql` | **Main's version** (identical tables, plus the 3 comment lines on populating `events_fts`). |
| `src/forensic/cli_evidence.py` | **Gayatri's version**, but rename `evidence_app` to `app` (main's `cli.py` imports `app`). |
| `src/forensic/cli.py` | **Rewrite** (code in section 3.4): combine evidence + analysis apps and `run-all`. |
| `src/forensic/__init__.py` | either (both trivial); keep `__version__ = "0.1.0"`. |
| `pyproject.toml` | Gayatri's, **plus** main's `[tool.setuptools.packages.find] where = ["src"]` and package data (section 3.6). |
| `.gitignore` | **Union** of both, plus `*.egg-info/`, `reports/`, `.ruff_cache/`. |
| `.github/CODEOWNERS` | Gayatri's structure, with real usernames: `@gayatri-karanjkar` for [A] paths, `@Manasvi-hub` for [B] paths. |
| `src/forensic.egg-info/*` (6 files on main) | `git rm -r --cached src/forensic.egg-info` |
| `IMPLEMENTATION_PERSON_A*.md`, `IMPLEMENTATION_PERSON_B.md` (repo root) | move into `docs/` |

After resolving: `pip install -e . && pytest -q` must be green, and `forensic --help` must list **ingest, verify, build, skew, search, report, ui, run-all**.

---

## 3. Aligned interfaces (the contract both sides code against)

### 3.1 Python API (Gayatri implements, Manasvi calls)

```python
# forensic/ingest.py
def ingest(case_dir: Path, sources_json: Path, collector: str) -> None
def verify(case_dir: Path) -> bool                         # prints OK/TAMPERED/MISSING/MISMATCH lines
def verify_items(case_dir: Path) -> list[dict]             # [{"file","status","expected","actual"}], status in
                                                           #   OK | TAMPERED | MISSING | MISMATCH ; verify() = all OK

# forensic/build.py
def build(case_dir: Path) -> list[dict]                    # one stats dict per evidence file:
    # {"evidence_id","filename","host","total_lines","blank_lines","parsed","gaps","parsed_pct","gap_reasons":{}}
    # parsed_pct = parsed / (total_lines - blank_lines) * 100

# forensic/skew.py
def skew(case_dir: Path, reference_host: str | None = None,
         offsets: list[str] | str | None = None) -> list[dict]   # rows written to skew_corrections

# forensic/pipeline.py   (NEW, owned by Gayatri; used by `run-all` and by Manasvi's tests)
def run_case(sources_json: Path, case_dir: Path, collector: str = "pipeline",
             reference_host: str | None = None) -> dict
    # ingest -> build -> skew; returns {"case_id","verified": bool,"build": [...],"skew": [...]}
    # reference_host defaults to sources.json["reference_host"]; case_dir is deleted and recreated if it exists
```

### 3.2 `case_meta` keys written by `ingest`
`case_id`, `created_at_utc`, `tool_version`, `year_hint`, `reference_host` (from `sources.json`).

### 3.3 Definitions that must mean the same thing to both people
- **`expected_parse_gaps`** in `ground_truth.json` = **`SELECT COUNT(*) FROM parse_gaps`** after `build` for the whole case (blank lines included, because they are stored as `empty_line` gaps).
- **Time tolerance:** an event matches ground truth if `event_type` and every key in `match` agree and `ts_utc_corrected` is within **5 seconds** of the step's `ts_utc`.
- **`expected_skew`** is the offset in seconds that must be **added** to that host's clock to reach the reference (a host running 7 minutes fast has `-420`). Tolerance: **5 s**.
- **Syslog timestamps** follow RFC 3164: `Oct  3 02:04:07` (day space-padded to 2, hour zero-padded to 2). The parser is strict about this.
- **Unparsed lines** are stored once in `parse_gaps`; a line the parser understood structurally but did not classify becomes `syslog_other`, not a gap.
- **Case folders** are always `cases/<case_id>/`, `case_id` taken from `sources.json`.

### 3.3b Scenario content rules (Manasvi must produce, Gayatri's parsers rely on)
- Attack web requests use a scanner UA the parser knows (`Nikto`, `sqlmap`, `gobuster`, `masscan`) and real attack strings (`UNION SELECT`, `../`, `?cmd=`), so each event type in the vocabulary appears at least once across the scenarios.
- S3 has **at least 10 anchor pairs** (same `src_ip` + same request path on both hosts, within 5 s true time).

### 3.4 Combined `cli.py` (Gayatri writes it in Step 2)

```python
import typer
from forensic.cli_evidence import app as evidence_app
from forensic.cli_analysis import app as analysis_app

app = typer.Typer(help="Forensic Timeline & Evidence Collection Tool", no_args_is_help=True)
for sub in (evidence_app, analysis_app):
    for cmd in sub.registered_commands:
        app.registered_commands.append(cmd)

@app.command("run-all")
def run_all(scenarios_dir: Path = typer.Option(Path("scenarios")), cases_dir: Path = typer.Option(Path("cases")),
            report: bool = typer.Option(True, help="Also generate reports/<case_id>.html if forensic.report exists")):
    """ingest -> build -> skew for every scenario folder that has a sources.json."""
    ...
```
(Both sub-apps expose a `typer.Typer()` named `app` and no callback. If `registered_commands` merging misbehaves, use `app.add_typer(sub)` instead, but verify `forensic --help` lists all 8 commands.)

### 3.5 CLI contract (unchanged flags)
`forensic ingest --case C --sources S --collector NAME` | `verify --case C` | `build --case C` | `skew --case C [--reference H] [--offset H=SECONDS ...]` | `search --case C "text" [--host --ip --type --from --to --limit]` | `report --case C --out FILE [--json FILE] [--csv FILE]` | `ui --case C` | `run-all`.

### 3.6 `pyproject.toml` additions (Gayatri)
```toml
[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
forensic = ["schema.sql", "templates/*.j2"]
```
`dependencies` = typer, jinja2, streamlit, pandas. `dev` extra = pytest, ruff.

---

## 4. Shared definition of "ready to merge"

A PR is mergeable only when all of these hold:
1. `pip install -e . && python -m pytest -q` is green on a **fresh clone** of the branch.
2. `ruff check src tests viewer scenarios` is clean.
3. `forensic --help` lists all 8 commands.
4. No files outside the PR author's ownership are changed (except Gayatri's shared files).
5. No committed `egg-info`, `cases/`, `.venv`, `__pycache__`.
6. The other person has skimmed the diff and approved.

---

## 5. Shared timeline

| Day | Gayatri | Manasvi | Sync |
|---|---|---|---|
| **Sat 10** | G1 to G6: fix bugs, rename `app`, write `pipeline.py`. After Step 1 merges: `git merge origin/main`, resolve (G7), PR | M1: generator fixes + ground truth, **PR `b/scenario-fixes` by noon**; then M2 `timeline.py` on a local branch (do not push shared files) | Noon: Step 1 merged. Evening: **Step 2 merged** |
| **Sun 11** | G8 tests, G9 README, G10 support Manasvi with pipeline questions | Rebase on main. M3 report, M4 viewer, M5 CLI | Night: **full run-all on 3 scenarios, report + viewer on real data** |
| **Mon 12** | Second tester in triage experiment, fix defects, G11 pseudocode | M6 tests, M7 evaluation, M8 deck PDF | Numbers agreed |
| **Tue 13** | Freeze 18:00, tag, repo hygiene, verify ownership transfer | M9 demo rehearsal x2, upload PDF | `v1.0-submission` tag |
| **Wed 14** | Buffer, submit | Buffer, submit | |

---

# PART II: MANASVI'S TASKS (Scenarios, Timeline, Report, Viewer, Evaluation, Deck)

You own: `scenarios/`, `timeline.py`, `report.py`, `templates/`, `cli_analysis.py`, `viewer/`, `evaluation/`, `docs/` (deck, demo script, pseudocode), `tests/test_ground_truth.py`, `tests/test_timeline_report.py`.
You do **not** touch `models.py`, `db.py`, `schema.sql`, `cli.py`, `cli_evidence.py`, `pyproject.toml`, `.gitignore`, `CODEOWNERS`, `pipeline.py`, `ingest.py`, `parsers/`, `normalize.py`, `skew.py`, `build.py`. If you need a change there, tell Gayatri.

Branches (create from `main`, short-lived):
`b/scenario-fixes` (Step 1, **first**), then `b/timeline-report`, `b/viewer`, `b/tests-eval`.

**How to test your scenarios against Gayatri's real parsers before her PR is merged:**
```bash
git fetch origin
git worktree add ../a-core origin/a/core-setup      # separate folder with her code
cd ../a-core && python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e . pytest
forensic ingest --case /tmp/s1 --sources <your-repo>/scenarios/s1_ssh_bruteforce/sources.json --collector manasvi
forensic build  --case /tmp/s1       # shows parsed / gaps; compare with your expected_parse_gaps
```
(Her branch needs her Prompt 1 fixes pushed first; ask her if `forensic skew` still crashes.)

---

## M1. Scenario fixes (Step 1, branch `b/scenario-fixes`, only `scenarios/`)

### M1.1 The bug that breaks S1 (generator line 19)
`strftime("%b %e %H:%M:%S").replace(" 0", "  ")` also rewrites the hour (`02:04:07` becomes ` 2:04:07`), so Gayatri's strict RFC 3164 parser rejects 258 of 259 lines. `%e` is also not portable (it fails on Windows). Replace with:
```python
ts = f"{local_dt:%b} {local_dt.day:2d} {local_dt:%H:%M:%S}"      # Oct  3 02:04:07
```
Also: write files with `open(path, "w", newline="\n", encoding="utf-8")`, end every file with a trailing newline, and use a local `random.Random(seed)` per scenario instead of the global `random.seed(42)`.

### M1.2 Scenario content (ground truth uses TRUE UTC times, never the skewed ones)

**S1 `s1_ssh_bruteforce`** (web01, auth.log, declared tz UTC; 3 Oct 2026)
| Step | UTC | Event | type |
|---|---|---|---|
| S1-01 | 02:14:07 | first brute-force attempt, attacker `203.0.113.50`, about 150 attempts over 5 min, users `root, admin, test, oracle` | `ssh_failed_login` / `ssh_invalid_user` |
| S1-02 | 02:19:51 | `Accepted password for deploy` | `ssh_accepted_login` |
| S1-03 | 02:20:30 | session opened for deploy | `session_opened` |
| S1-04 | 02:22:12 | `sudo ... COMMAND=/bin/bash` | `sudo_command` |
| S1-05 | 02:24:40 | `new user: name=support` | `user_added` |
| S1-06 | 02:31:05 | session closed | `session_closed` |
Noise: cron sessions, `alice`/`bob` logins from `198.51.100.x`, typo failures. Malformed lines: exactly 4 (truncated line, garbage/NUL line, `Feb 30`, a line in a different format).

**S2 `s2_web_attack`** (web01, Nginx, `+0000`; 5 Oct 2026)
| Step | UTC | Event | type |
|---|---|---|---|
| S2-01 | 14:02:10 | `Nikto` UA probes `/wp-login.php`, `/.env`, `/phpmyadmin` | `web_scan` |
| S2-02 | 14:09:33 | `/products.php?id=1' UNION SELECT ...` (one URL-encoded, one double-encoded) | `web_sqli_attempt` |
| S2-03 | 14:14:02 | `/download?file=../../etc/passwd` | `web_path_traversal` |
| S2-04 | 14:18:47 | `POST /upload.php` with `shell.php`, status 200 | `web_webshell_upload` |
| S2-05 | 14:20:15 | `GET /uploads/shell.php?cmd=id` then `cmd=cat+/etc/shadow` | `web_webshell_access` |
| S2-06 | 14:27:40 | last attacker request (404/500 burst before) | `web_request` |
Noise: ~100 normal requests from many `198.51.100.x` clients with realistic UAs. Malformed lines: exactly 5 (truncated mid-quote, wrong date format, missing quotes, other log format, one blank line).

**S3 `s3_clock_skew`** (the differentiator; 8 Oct 2026)
- Hosts: `web01` (reference, correct clock, tz UTC) and `db01` (clock **+420 s fast**, syslog declared tz `Asia/Kolkata`, nginx lines in `+0000`).
- **All four files must be non-empty** (today `web01/auth.log` is empty).
| Step | True UTC | Event |
|---|---|---|
| S3-01 | 09:00:00 to 09:00:18 | Same **10 distinct paths** hit on **both** hosts by `203.0.113.90` with UA `Nikto` (anchors; db01 times = true + 420 s + jitter of 0 to 2 s) |
| S3-02 | 09:05:30 | `web01` SQLi: `/search.php?q=1' UNION SELECT 1,2` |
| S3-03 | 09:08:12 | `web01` webshell: `/uploads/shell.php?cmd=id` |
| S3-04 | 09:12:45 | `db01` `Accepted password for dbadmin from 192.0.2.10` (syslog line time = true + 420 s, written in IST) |
| S3-05 | 09:14:03 | `db01` `sudo ... COMMAND=/bin/bash` |
| S3-06 | 09:15:30 | `db01` data export `GET /export.php` 200 |
- `web01/auth.log`: normal logins plus a few failed attempts so the host has syslog content.
- Without correction, db01's login (09:19:45Z raw) sorts after S3-06 on web01; with correction it lands before. `expected_skew: {"db01": -420}`.

### M1.3 `ground_truth.json` rules (per scenario)
- `steps`: **one entry per row of the tables above** (S1 6, S2 6, S3 6), each with `id`, `ts_utc`, `host`, `event_type`, `match` (`src_ip`, `username` where relevant), `description`.
- `triage_questions`: 3 to 4 `{q, answer}` (S3 includes "Which happened first: web01 webshell or db01 login?").
- `expected_parse_gaps` = **`COUNT(*)` of `parse_gaps` after Gayatri's `build`** (blank lines count). Confirm using the worktree command above, then hard-code it. Target: S1 = 4, S2 = 5, S3 = 0.
- `expected_skew` per section 3.3.

### M1.4 Also in this PR
- `scenarios/fixtures/seed_db.py`: resolve `schema.sql` with `Path(__file__).resolve().parents[2] / "src/forensic/schema.sql"` (not the current directory).
- Add a self-check at the end of `generate.py`: for each ground-truth step, assert a log line exists at the corresponding (skew-adjusted) time; print per-file line counts.
- Regenerate all logs, commit them, open PR `b/scenario-fixes` to `main`. Gayatri reviews and merges (**Step 1**).

---

## M2. `timeline.py` (branch `b/timeline-report`, after Step 2 merged)

Keep the existing `Filters` dataclass and `query_events`. Changes and additions:
- **FTS safety:** do not interpolate into SQL. Use `events_fts MATCH ?` with the parameter `'"' + text.replace('"', '""') + '"'`. Today a single quote in a search crashes the query.
- `summary_stats(conn) -> dict`: `total_events`, `hosts` (list), `first_event`, `last_event` (corrected UTC), `by_type`, `by_severity`, `by_host` (dicts of counts), `top_src_ips` (top 5 `[ip, count]`), `evidence_files`, `total_gaps`.
- `gap_summary(conn) -> list[dict]`: per evidence file `{"evidence_id","filename","host","total_lines","blank_lines","parsed","gaps","parsed_pct","reasons":{...}}` computed from `evidence.line_count`, `events`, `parse_gaps` (same maths as section 3.1).
- `key_events(conn)`: all `high` severity, all `medium`, and the first `ssh_accepted_login` and first `web_*` attack event per source IP; ordered by `ts_utc_corrected`, de-duplicated.
- `skew_summary(conn)` returns dicts (not `Row`s); `evidence_manifest(conn)` returns evidence rows as dicts.
- `context_window` must handle milliseconds correctly (use the event's own timestamp +/- N seconds).

## M3. `report.py` + `templates/report.html.j2`

- `generate_report(case_dir, out_html, out_json=None, out_csv=None)`; load the template with `Path(__file__).parent / "templates"` (**not** the current directory) and name it `report.html.j2` (today it looks for `templates/report.html` relative to the working directory and silently falls back to a one-line page).
- Sections: (1) case summary; (2) executive summary bullets built from `key_events`, e.g. "First successful login: 2026-10-03T02:19:51Z from 203.0.113.50 as deploy"; (3) evidence manifest with SHA-256 and **verification status from `forensic.ingest.verify_items`**; (4) time handling: declared timezones, year hint, skew table with confidence notes, "reference host"; (5) key-event timeline with source file + line number; (6) parsing gaps per file with reasons and a sample of unparsed lines; (7) **Limitations & scope** (no live endpoint takeover, no malware removal, not forensically certified, assumptions on declared tz and anchor simultaneity, synthetic data); (8) appendix counts.
- Print-friendly CSS (`@media print`), no external assets. HTML-escape all log content (logs are untrusted input).
- JSON export: `case`, `summary`, `evidence` (with hashes + status), `skew`, `key_events`, `gaps`, `limitations`. CSV export: full timeline `ts_utc_corrected, ts_utc, ts_original, host, event_type, severity, src_ip, username, message, evidence_file, line_no`.

## M4. Viewer (`viewer/app.py`, branch `b/viewer`)

- Parse args with `argparse` using `parse_known_args` (Streamlit adds its own flags); default `--case cases/s3_clock_skew`.
- Sidebar: multiselects for host, event type, severity; text inputs for IP, username, full-text search; time range; toggle "Use skew-corrected time" (default on); event limit.
- Header strip: case id, events, first/last time, number of gaps, number of skew corrections.
- **Timeline tab:** table (corrected time, original time, host, type, severity, IP, user, message), plus an Altair events-per-minute chart coloured by host. Selecting a row (or an event id) drives the detail tab.
- **Event detail tab:** raw line, evidence file, line number, byte offset, **evidence SHA-256**, original vs UTC vs corrected time, and a +/- 60 s context window across hosts.
- **Evidence tab:** manifest table and a **"Verify integrity"** button calling `forensic.ingest.verify_items`, showing OK / TAMPERED per file.
- **Parsing gaps tab:** per-file coverage (`gap_summary`), reasons bar chart, table of unparsed lines.
- **Clock skew tab:** `skew_summary` table and a before/after chart for the skewed host.
- Use `st.cache_data` keyed by `(db_path, filters)` so widgets stay responsive. Handle missing tables with friendly messages.

## M5. `cli_analysis.py`

- Export the Typer instance as `app` (as `cli.py` expects).
- `search`: add `--limit` (default 200); output `time_utc | host | type | ip | message`; exit 1 with a clear message if the case DB does not exist.
- `ui`: launch with `[sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve().parents[2] / "viewer" / "app.py"), "--", "--case", str(case)]` so it works from any directory.
- `report`: keep flags `--out`, `--json`, `--csv`.

## M6. Tests (`tests/test_ground_truth.py`, `tests/test_timeline_report.py`)

Use Gayatri's `forensic.pipeline.run_case(sources_json, tmp_case_dir)` and `forensic.timeline`.

`test_ground_truth.py`, parametrized over the three scenarios:
1. every `steps[*]` has a matching event: same `event_type`, all `match` keys equal, `ts_utc_corrected` within 5 s of the step time;
2. `SELECT COUNT(*) FROM parse_gaps` equals `expected_parse_gaps`;
3. each `triage_questions` answer is derivable from a `query_events` result (assert the first accepted login / first attack event time and IP);
4. S3 only: `skew_corrections` db01 `offset_s` within 5 s of `-420`; **without** correction (`use_corrected=False`) the db01 login sorts after the web01 webshell and the db01 export, **with** correction it sorts between them in the right causal order (S3-03 < S3-04 < S3-05);
5. `verify` returns True on the fresh case.

`test_timeline_report.py`: each filter works; FTS with a `'` or `"` in the query does not raise; `summary_stats`/`gap_summary` keys present; the HTML report contains all section headings, every evidence SHA-256 and the limitations text; JSON parses and has the keys in M3; CSV row count equals total events.

## M7. Evaluation (`evaluation/`, branch `b/tests-eval`)

- `triage_questions.md`: 4 fixed questions per scenario (first success time, source IP, first sensitive action, S3 causal order).
- `triage_results.csv` columns: `scenario,tester,condition,question_id,seconds,correct,notes`.
- **Protocol:** both testers, each tests scenarios they did not write (Gayatri does S1/S2 manually; you do S3 after she explains only the raw files). Manual condition: `grep`, `less`, `sort`, `date` only. Tool condition: viewer or CLI. Alternate which goes first. Stopwatch per question, accuracy against ground truth.
- `evaluation/summarize.py`: reads the CSV and writes `triage_summary.md` (median time per condition and scenario, speed-up factor, accuracy). State honestly: n is small and testers know the tool.
- `evaluation/gap_report.py`: runs `gap_summary` for all three cases and writes `parsing_gap_analysis.md` (table per file, reasons, discussion, what the tool does not parse).

## M8. Deck PDF (`docs/`)
Fill the Beamer template from `Proposed-structure-hackathon.pdf` (Overleaf). Title slide ID **`A3-PS013-TC067`**, PS-013 title, both names, date. Slides: abstract/problem, background (NIST SP 800-86), literature (NIST 800-86, RFC 3164, RFC 5424, RFC 3339, Plaso/Timesketch docs, Nginx log format), solution, optimization table with real triage numbers, architecture diagram, data-flow diagram, timeline, real bibliography (replace the Einstein and cow placeholders). Export `docs/A3-PS013-TC067.pdf`.

## M9. Demo and pseudocode
`docs/demo_script.md` (5 minutes: problem 20 s; ingest + tamper + verify 60 s; build + gaps 60 s; viewer S3 before/after skew 90 s; report 45 s; triage numbers + limitations 45 s). Rehearse twice. Keep prebuilt cases as a fallback. Pseudocode comes from Gayatri (G10) into `docs/pseudocode.md`.

## M10. Self-check before every PR
```bash
python -m pytest -q                  # your tests + hers
ruff check scenarios viewer src/forensic/timeline.py src/forensic/report.py src/forensic/cli_analysis.py tests
forensic --help                      # 8 commands
forensic run-all && forensic report --case cases/s3_clock_skew --out reports/s3.html
forensic ui --case cases/s3_clock_skew     # click through all 5 tabs
git diff --stat origin/main          # only your files
```

## M11. Definition of done (Manasvi)
- [ ] Generator fixed; S1/S2/S3 logs regenerated with full ground truth; all four S3 files non-empty
- [ ] Gap counts in ground truth match Gayatri's `build` (4 / 5 / 0)
- [ ] `timeline.py` helpers complete; FTS safe
- [ ] Report has all 8 sections with hashes, gaps, skew, limitations; JSON + CSV export
- [ ] Viewer has all filters, charts, verify button, 5 tabs; `forensic ui` works from any directory
- [ ] Ground-truth and report tests green
- [ ] Triage CSV + summary + gap analysis written; deck PDF `A3-PS013-TC067.pdf` in `docs/`
- [ ] Demo rehearsed twice; ownership transfer verified

---

# ANTIGRAVITY PROMPT 3 (run now: Step 1, branch `b/scenario-fixes`, scenarios only)

````text
Repo: Python project (package `forensic`). I am Manasvi (Person B). Create branch `b/scenario-fixes` from the current `main` and work ONLY inside the `scenarios/` folder. Do not edit anything else (no src/, viewer/, tests/, pyproject, .gitignore, CODEOWNERS).

Files: scenarios/generate.py, scenarios/fixtures/seed_db.py, and for each scenario s1_ssh_bruteforce, s2_web_attack, s3_clock_skew: logs, sources.json, ground_truth.json.

## Bug fixes in scenarios/generate.py
1. Line ~19: `ts = local_dt.strftime("%b %e %H:%M:%S").replace(" 0", "  ")` also rewrites the hour (02:04:07 becomes " 2:04:07"), producing invalid RFC 3164 syslog and breaking the parser (258 of 259 S1 lines unparseable). Replace with `ts = f"{local_dt:%b} {local_dt.day:2d} {local_dt:%H:%M:%S}"` which gives `Oct  3 02:04:07`. (%e is also not portable to Windows.)
2. Write every file with `open(path, "w", newline="\n", encoding="utf-8")` and end each file with a trailing newline.
3. Replace global `random.seed(42)` with a local `rng = random.Random(<fixed seed per scenario>)` passed into every helper; output must be byte-for-byte identical on repeated runs.
4. scenarios/fixtures/seed_db.py: resolve the schema path with `Path(__file__).resolve().parents[2] / "src" / "forensic" / "schema.sql"` (no dependence on the current directory).

## Scenario content (ground truth times are TRUE UTC, never skewed)
S1 s1_ssh_bruteforce: single host web01, auth.log, declared tz UTC, 3 Oct 2026. Steps: S1-01 02:14:07 first brute-force attempt from 203.0.113.50 (about 150 failed attempts over 5 min, users root/admin/test/oracle, mix of "Failed password for invalid user" and "Failed password for <valid user>"); S1-02 02:19:51 "Accepted password for deploy from 203.0.113.50"; S1-03 02:20:30 session opened for deploy; S1-04 02:22:12 "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"; S1-05 02:24:40 "useradd ... new user: name=support"; S1-06 02:31:05 session closed. Noise: cron sessions, alice/bob legitimate logins from 198.51.100.x, a few typo failures. Exactly 4 malformed lines (truncated line, garbage line with a NUL byte, an invalid date "Feb 30 ...", a line in a totally different format).
S2 s2_web_attack: web01 Nginx combined log, offsets +0000, 5 Oct 2026. S2-01 14:02:10 scanner 203.0.113.77 UA "Nikto/2.5" probing /wp-login.php, /.env, /phpmyadmin (mostly 404); S2-02 14:09:33 "/products.php?id=1' UNION SELECT 1,2" (one URL-encoded %27%20UNION%20SELECT, one double-encoded); S2-03 14:14:02 "/download?file=../../etc/passwd"; S2-04 14:18:47 "POST /upload.php" 200 (webshell upload of shell.php); S2-05 14:20:15 "GET /uploads/shell.php?cmd=id" and later "?cmd=cat+/etc/shadow"; S2-06 14:27:40 last attacker request. About 100 normal requests from many 198.51.100.x clients with realistic user agents. Exactly 5 malformed lines (truncated mid-quote, wrong date format, missing quotes, a different log format, one blank line).
S3 s3_clock_skew: hosts web01 (reference, correct clock, tz UTC) and db01 (clock runs +420 s fast; db01 syslog declared tz Asia/Kolkata so syslog lines are written as IST of (true time + 420 s); db01 nginx lines use +0000 with the +420 s). ALL FOUR files must be non-empty: web01/auth.log, web01/access.log, db01/auth.log, db01/access.log. S3-01 true 09:00:00 to 09:00:18: attacker 203.0.113.90 with UA "Nikto" requests the SAME 10 distinct paths on BOTH hosts (db01 times = true + 420 s + random jitter 0 to 2 s); S3-02 09:05:30 web01 "/search.php?q=1' UNION SELECT 1,2"; S3-03 09:08:12 web01 "/uploads/shell.php?cmd=id"; S3-04 09:12:45 db01 "Accepted password for dbadmin from 192.0.2.10 port 51122 ssh2" (syslog time = true + 420 s in IST); S3-05 09:14:03 db01 "sudo: dbadmin : ... COMMAND=/bin/bash"; S3-06 09:15:30 db01 "GET /export.php" 200. web01/auth.log must contain normal logins plus a few failed attempts. Add some normal noise to every file. expected_skew = {"db01": -420}.

## ground_truth.json (per scenario)
- "steps": one entry per step above (S1 6, S2 6, S3 6): {"id","ts_utc" (true UTC, ISO with Z),"host","event_type","match":{"src_ip"/"username" as relevant},"description"}. Use event types exactly from this vocabulary: ssh_failed_login, ssh_invalid_user, ssh_accepted_login, session_opened, session_closed, sudo_command, user_added, web_request, web_scan, web_sqli_attempt, web_path_traversal, web_webshell_upload, web_webshell_access.
- "triage_questions": 3 to 4 {"q","answer"} per scenario (S3 includes "Which happened first: web01 webshell or db01 login?").
- "expected_parse_gaps": number of rows that will be in the parse_gaps table after build for the whole case (blank lines count). Targets S1 = 4, S2 = 5, S3 = 0. Verify by counting your deliberately malformed lines, and print the expected number from generate.py.
- "expected_skew": {} for S1/S2, {"db01": -420} for S3.
- sources.json keeps the format {"case_id","year_hint":2026,"reference_host","sources":[{"path","host","source_type":"auth_log"|"nginx","declared_tz"}]}; S3 has reference_host "web01" and four sources.

## Self-check at the end of generate.py
For every ground-truth step assert that a log line exists at the corresponding time (add the +420 s for db01 lines), print per-file line counts and the expected gap count per scenario, and exit non-zero on any failure.

## Finish
Run `python scenarios/generate.py` twice and confirm `git diff` shows no change the second time. Commit with messages like `fix(scenarios): RFC3164 timestamp padding, deterministic generator` and `feat(scenarios): full ground truth, non-empty S3 logs`, push `b/scenario-fixes`. Do NOT merge. Print: file list changed, per-file line counts, expected gaps per scenario.
````

---

# ANTIGRAVITY PROMPT 4 (run AFTER Gayatri's PR is merged: timeline, report, viewer, CLI, tests, evaluation)

````text
Repo: Python package `forensic` (src layout). I am Manasvi (Person B). First: `git checkout main && git pull`, then `pip install -e . pytest ruff`, and confirm `forensic --help` lists ingest, verify, build, skew, search, report, ui, run-all and `forensic run-all` works. Then create branch `b/timeline-report` and do Part 1 and Part 2; after I merge it create `b/viewer` for Part 3; then `b/tests-eval` for Parts 4 and 5.

## Hard rules
- Edit ONLY: src/forensic/timeline.py, src/forensic/report.py, src/forensic/templates/, src/forensic/cli_analysis.py, viewer/, evaluation/, docs/ (new files only), tests/test_ground_truth.py, tests/test_timeline_report.py.
- Do NOT edit models.py, db.py, schema.sql, cli.py, cli_evidence.py, pyproject.toml, .gitignore, CODEOWNERS, pipeline.py, ingest.py, parsers/, normalize.py, skew.py, build.py, or scenarios/.
- Use Gayatri's API: forensic.ingest.verify_items(case_dir) -> list[{"file","status","expected","actual"}], forensic.pipeline.run_case(sources_json, case_dir, collector="pipeline", reference_host=None) -> dict.
- DB timestamps are ISO-8601 UTC strings ending in Z with milliseconds; ts_utc_corrected is the display/sort column.

## Part 1: src/forensic/timeline.py
Keep Filters and query_events. Fix FTS: use `events_fts MATCH ?` with the bound parameter '"' + text.replace('"','""') + '"' (no string interpolation; a quote character must not crash). Implement (return dicts, not sqlite Rows, for the summary helpers):
- summary_stats(conn): total_events, hosts, first_event, last_event (corrected UTC), by_type, by_severity, by_host, top_src_ips (top 5 [ip,count]), evidence_files, total_gaps.
- gap_summary(conn): per evidence file {"evidence_id","filename","host","total_lines","blank_lines","parsed","gaps","parsed_pct","reasons":{reason:count}}; total_lines from evidence.line_count; blank_lines = count of empty_line gaps; parsed = events count; parsed_pct = parsed/(total_lines-blank_lines)*100.
- key_events(conn): all high + all medium severity events plus the first ssh_accepted_login and the first web attack event per src_ip, de-duplicated, ordered by ts_utc_corrected.
- skew_summary(conn) -> list of dicts; evidence_manifest(conn) -> list of dicts; context_window(conn, event_id, seconds=60) using the event's own timestamp +/- seconds with correct millisecond handling.

## Part 2: report + CLI
- src/forensic/cli_analysis.py: the Typer instance must be named `app`. `search` gets `--limit` (default 200), prints `time_utc | host | type | ip | message`, and exits 1 with a clear message if the case database is missing. `ui` launches `[sys.executable, "-m", "streamlit", "run", str(Path(__file__).resolve().parents[2] / "viewer" / "app.py"), "--", "--case", str(case)]`. `report` keeps --out, --json, --csv.
- src/forensic/report.py: generate_report(case_dir, out_html, out_json=None, out_csv=None). Load the template with Environment(loader=FileSystemLoader(Path(__file__).parent / "templates")) and template name "report.html.j2" (it must NOT depend on the working directory and must not silently fall back to a one-line page; raise on errors). Create src/forensic/templates/report.html.j2 with sections: 1 Case summary; 2 Executive summary bullets from key_events (e.g. "First successful login: <time> from <ip> as <user>"); 3 Evidence manifest with SHA-256 and verification status from verify_items; 4 Time handling (declared timezones, year hint, skew table with confidence notes, reference host); 5 Key-event timeline with source file and line number; 6 Parsing gaps per file with reasons and up to 10 sample unparsed lines; 7 Limitations & scope (no live endpoint takeover, no malware removal, not forensically certified, declared-timezone and anchor-simultaneity assumptions, synthetic data); 8 Appendix counts by type and host. Print-friendly CSS with @media print, no external assets, autoescape ON (log content is untrusted). JSON export keys: case, summary, evidence (with hashes + status), skew, key_events, gaps, limitations. CSV export columns: ts_utc_corrected, ts_utc, ts_original, host, event_type, severity, src_ip, username, message, evidence_file, line_no.

## Part 3: viewer/app.py
argparse with parse_known_args (Streamlit adds its own flags), default --case cases/s3_clock_skew. Sidebar: multiselect host / event type / severity, text inputs IP / username / full-text search, time range, toggle "Use skew-corrected time" (default on), event limit. Header strip: case id, events, first/last time, gap count, skew-correction count. Tabs: (1) Timeline: table with corrected time, original time, host, type, severity, IP, user, message + Altair events-per-minute chart colored by host; (2) Event detail: raw line, evidence file, line number, byte offset, evidence SHA-256, original vs UTC vs corrected time, plus +/- 60 s context window across hosts; (3) Evidence: manifest table + "Verify integrity" button calling forensic.ingest.verify_items showing OK/TAMPERED per file; (4) Parsing gaps: gap_summary table, reasons bar chart, table of unparsed lines; (5) Clock skew: skew_summary table + before/after chart for the skewed host. Use st.cache_data keyed by (db_path, filters). Friendly messages when tables are empty or missing.

## Part 4: tests
tests/test_ground_truth.py, parametrized over scenarios/*/ using forensic.pipeline.run_case into tmp_path: (a) each ground_truth step has a matching event (same event_type, all `match` keys equal, ts_utc_corrected within 5 s of ts_utc); (b) SELECT COUNT(*) FROM parse_gaps == expected_parse_gaps; (c) each triage answer is derivable from query_events; (d) for s3_clock_skew: skew db01 offset_s within 5 s of -420, and with use_corrected=False the db01 login sorts AFTER the web01 webshell and the db01 export, while with correction the order is S3-03 < S3-04 < S3-05; (e) verify_items are all OK. tests/test_timeline_report.py: every filter works; FTS with ' and " does not raise; summary_stats and gap_summary have the documented keys; the HTML report contains all 8 section headings, every evidence SHA-256 and the limitations text; JSON has the documented keys; CSV rows == total events.

## Part 5: evaluation (new files only)
evaluation/triage_questions.md (4 questions per scenario: first success time, source IP, first sensitive action, S3 causal order), evaluation/triage_results.csv header `scenario,tester,condition,question_id,seconds,correct,notes`, evaluation/summarize.py (reads the CSV, writes triage_summary.md: median time per condition and scenario, speed-up factor, accuracy, honest limitations), evaluation/gap_report.py (runs gap_summary on all three cases and writes parsing_gap_analysis.md with a table per file, reasons, discussion, and what the tool does not parse).

## Acceptance
python -m pytest -q passes; ruff check on the files I own is clean; `forensic run-all` then `forensic report --case cases/s3_clock_skew --out reports/s3.html --json reports/s3.json --csv reports/s3.csv` works from the repo root AND from another directory; `forensic ui --case cases/s3_clock_skew` opens a viewer with all 5 tabs; `git diff --stat origin/main` shows only files I own.

Commit small and logically (feat(timeline), feat(report), feat(viewer), test, docs), push each branch, do not force-push, do not merge. Print files changed, pytest summary, ruff result.
````
