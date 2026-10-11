# PS-013 Incident Timeline & Evidence Collection: Implementation Guide (Person B)

> **Your role:** Scenarios, timeline queries, Streamlit viewer, report export, evaluation, PDF deck and demo.
> **Window:** Wed 7 Oct 2026 to Wed 14 Oct 2026 (submission). Target: feature-complete by Mon 12, frozen Tue 13, Wed 14 is buffer only.
> **Section 0 to 6 are identical in both people's files (the contract). Do not change them without a PR labelled `contract` that both of you approve.**

---

## 0. What we are building (one paragraph)

A lightweight, zero-infrastructure forensic tool for small teams. It ingests raw Linux `auth.log` and Nginx access logs, copies them untouched into an evidence store, hashes them (SHA-256) at collection, parses them into **normalized copies** in SQLite (with UTC timestamps, clock-skew correction, and full-text search), records every line it could not parse, and presents a searchable chronological timeline in a Streamlit viewer plus an exportable incident report. We evaluate it on **3 synthetic scenarios** and compare **triage time against a manual `grep` baseline**.

**Hard constraints from the PS (never cut these):** 2 log formats, 3 synthetic scenarios, original records preserved, evidence hashes, timezone + clock skew handling, parsing gaps documented, triage-time comparison. **Out of scope (state in report):** live endpoint takeover, malware removal, forensic certification.

**Deliverables for the certificate:** (1) private repo named after the team, `aiori-hackathon` accepted as collaborator, then ownership transferred; (2) PDF in the repo following `Proposed-structure-hackathon.pdf`; (3) prototype demo with a pseudocode snippet.

---

## 1. Tech stack

| Concern | Choice |
|---|---|
| Language | Python 3.12 |
| CLI | Typer |
| Parsing | `re` (named groups), `zoneinfo`, `datetime` |
| Hashing | `hashlib.sha256` (chunked, 1 MiB) |
| Storage | SQLite 3 with FTS5 (stdlib `sqlite3`) |
| Viewer | Streamlit + pandas + Altair (comes with Streamlit) |
| Report | Jinja2 to HTML (print to PDF from browser), JSON export |
| Tests | pytest |
| Lint (optional) | ruff |

`requirements.txt`:
```
typer>=0.12
jinja2>=3.1
streamlit>=1.38
pandas>=2.2
pytest>=8.0
ruff>=0.6
```

Setup: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && pip install -e .`

---

## 2. Repo layout (final, shared)

```
<team-repo>/
├── README.md
├── pyproject.toml                # package "forensic", console script: forensic = forensic.cli:app
├── requirements.txt
├── .gitignore                    # cases/, .venv/, __pycache__/
├── .github/CODEOWNERS
├── src/forensic/
│   ├── __init__.py
│   ├── models.py                 # [A] Event, ParseGap, ParseContext, SourceSpec dataclasses (section 4)
│   ├── db.py                     # [A] schema.sql loader, connection helper, insert helpers
│   ├── schema.sql                # [A] exact schema from section 3
│   ├── ingest.py                 # [A] copy, hash, manifest, verify
│   ├── parsers/
│   │   ├── __init__.py           # [A] registry: {"auth_log": AuthLogParser, "nginx": NginxParser}
│   │   ├── auth_log.py           # [A]
│   │   └── nginx.py              # [A]
│   ├── normalize.py              # [A] tz to UTC, year inference
│   ├── skew.py                   # [A] anchor-based offset estimation + apply
│   ├── build.py                  # [A] orchestrates parse -> normalize -> DB
│   ├── timeline.py               # [B] query layer: filters, FTS search, context window
│   ├── report.py                 # [B] HTML + JSON export
│   ├── templates/report.html.j2  # [B]
│   └── cli.py                    # [shared] A owns ingest/verify/build/skew, B owns search/report/ui
├── viewer/app.py                 # [B] Streamlit
├── scenarios/
│   ├── generate.py               # [B] synthetic log generator (seeded, deterministic)
│   ├── s1_ssh_bruteforce/        # [B] auth.log, sources.json, ground_truth.json
│   ├── s2_web_attack/            # [B] access.log, sources.json, ground_truth.json
│   ├── s3_clock_skew/            # [B] multi-host, sources.json, ground_truth.json
│   └── fixtures/seed_db.py       # [B] builds a fake case.db from ground_truth (lets B work before A is done)
├── tests/
│   ├── fixtures/                 # [A] tiny hand-written log samples
│   ├── test_ingest.py            # [A]
│   ├── test_parsers.py           # [A]
│   ├── test_normalize.py         # [A]
│   ├── test_skew.py              # [A]
│   ├── test_ground_truth.py      # [B] runs full pipeline on each scenario, asserts vs ground truth
│   └── test_timeline_report.py   # [B]
├── evaluation/                   # [B] triage_questions.md, triage_results.csv, parsing_gap_analysis.md
├── docs/                         # [B] architecture + DFD diagrams, deck PDF, demo script, pseudocode.md
└── cases/                        # runtime output, gitignored (cases/<id>/evidence, manifest.json, case.db)
```

**Case directory (created by `ingest`, gitignored):**
```
cases/<case_id>/
├── evidence/            # read-only copies of originals, never modified
├── manifest.json        # chain of custody
└── case.db              # SQLite (section 3)
```

---

## 3. SQLite schema (`src/forensic/schema.sql`, written by A, read by B)

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS evidence (
  id               INTEGER PRIMARY KEY,
  filename         TEXT NOT NULL,         -- original file name
  stored_path      TEXT NOT NULL,         -- path inside cases/<id>/evidence/
  sha256           TEXT NOT NULL UNIQUE,  -- hash of the ORIGINAL bytes, computed at collection
  size_bytes       INTEGER NOT NULL,
  line_count       INTEGER NOT NULL,
  collected_at_utc TEXT NOT NULL,         -- ISO-8601 UTC, e.g. 2026-10-08T09:12:44Z
  collector        TEXT NOT NULL,         -- username of person running the tool
  host             TEXT NOT NULL,         -- logical host the log came from (web01, db01 ...)
  source_type      TEXT NOT NULL,         -- 'auth_log' | 'nginx'
  declared_tz      TEXT NOT NULL          -- IANA name, e.g. 'Asia/Kolkata', 'UTC'
);

CREATE TABLE IF NOT EXISTS events (
  id                INTEGER PRIMARY KEY,
  evidence_id       INTEGER NOT NULL REFERENCES evidence(id),
  line_no           INTEGER NOT NULL,     -- 1-based line in the original file
  byte_offset       INTEGER NOT NULL,     -- offset of line start in the original file
  ts_original       TEXT NOT NULL,        -- timestamp string exactly as in the log
  ts_utc            TEXT NOT NULL,        -- ISO-8601 UTC after tz normalization (no skew fix)
  ts_utc_corrected  TEXT NOT NULL,        -- ts_utc + skew offset (equals ts_utc if no correction)
  skew_offset_s     REAL NOT NULL DEFAULT 0,
  host              TEXT NOT NULL,
  source_type       TEXT NOT NULL,
  event_type        TEXT NOT NULL,        -- see event-type vocabulary in section 4
  severity          TEXT NOT NULL DEFAULT 'info',   -- 'info' | 'low' | 'medium' | 'high'
  src_ip            TEXT,
  username          TEXT,
  detail            TEXT,                 -- request path for web, command for sudo, etc.
  message           TEXT NOT NULL,        -- human-readable summary
  raw_line          TEXT NOT NULL,        -- verbatim original line (also in evidence file)
  UNIQUE (evidence_id, line_no)
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts_utc_corrected);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  message, raw_line, username, src_ip, detail,
  content='events', content_rowid='id'
);
-- build.py must populate events_fts after loading events:
--   INSERT INTO events_fts(rowid, message, raw_line, username, src_ip, detail)
--   SELECT id, message, raw_line, username, src_ip, detail FROM events;

CREATE TABLE IF NOT EXISTS parse_gaps (
  id           INTEGER PRIMARY KEY,
  evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
  line_no      INTEGER NOT NULL,
  reason       TEXT NOT NULL,   -- 'no_regex_match' | 'bad_timestamp' | 'truncated' | 'empty_line' | 'encoding_error'
  raw_line     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skew_corrections (
  host            TEXT PRIMARY KEY,
  reference_host  TEXT NOT NULL,
  offset_s        REAL NOT NULL,    -- seconds ADDED to this host's ts_utc to align with reference
  method          TEXT NOT NULL,    -- 'anchor_median' | 'manual' | 'none'
  anchor_count    INTEGER NOT NULL,
  stdev_s         REAL,
  confidence_note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL   -- case_id, created_at_utc, tool_version, year_hint
);
```

**Conventions:** all timestamps in the DB are ISO-8601 strings in UTC with a trailing `Z` and millisecond precision where available (`2026-10-08T09:12:44.000Z`), so string sort equals chronological sort. Offset sign: `ts_utc_corrected = ts_utc + offset_s`, where `offset_s` is the amount the host's clock must be shifted to match the reference host (a host running 7 minutes **fast** has `offset_s = -420`).

---

## 4. Interfaces (`src/forensic/models.py`, written by A on Wed 7 and pushed immediately)

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class ParseContext:
    host: str
    source_type: str          # 'auth_log' | 'nginx'
    declared_tz: str          # IANA tz, e.g. "Asia/Kolkata"
    year_hint: int            # used for syslog lines that have no year
    file_mtime_utc: Optional[datetime] = None   # fallback for year inference

@dataclass
class Event:
    line_no: int
    byte_offset: int
    ts_original: str
    ts_utc: datetime          # tz-aware UTC
    host: str
    source_type: str
    event_type: str
    severity: str = "info"
    src_ip: Optional[str] = None
    username: Optional[str] = None
    detail: Optional[str] = None
    message: str = ""
    raw_line: str = ""

@dataclass
class ParseGap:
    line_no: int
    reason: str               # see parse_gaps.reason vocabulary
    raw_line: str

# Every parser implements:
class LineParser:
    def parse_line(self, line: str, line_no: int, byte_offset: int,
                   ctx: ParseContext) -> "Event | ParseGap": ...
```

### Event-type vocabulary (both sides must use exactly these strings)

| event_type | source | severity | meaning |
|---|---|---|---|
| `ssh_failed_login` | auth_log | low | failed password / publickey for a valid user |
| `ssh_invalid_user` | auth_log | low | attempt for a non-existent user |
| `ssh_accepted_login` | auth_log | medium | successful login |
| `ssh_disconnect` | auth_log | info | disconnect / connection closed |
| `session_opened` / `session_closed` | auth_log | info | PAM session |
| `sudo_command` | auth_log | medium (high if shell/`su`/`/etc/shadow`) | sudo usage |
| `user_added` | auth_log | high | `useradd` / `new user` |
| `web_request` | nginx | info | ordinary request |
| `web_scan` | nginx | low | many 404s / scanner UA / probes (`/wp-login.php`, `/.env`, `/phpmyadmin`) |
| `web_sqli_attempt` | nginx | high | `UNION SELECT`, `' OR 1=1`, `sleep(`, `information_schema` (URL-decoded) |
| `web_path_traversal` | nginx | high | `../`, `%2e%2e` |
| `web_webshell_upload` | nginx | high | POST/PUT to upload endpoint of a `.php`/`.jsp` file, or 200 on new suspicious script |
| `web_webshell_access` | nginx | high | request to known shell path with `cmd=`/`exec=` parameters |

### `sources.json` (the file that connects B's scenarios to A's ingest)

```json
{
  "case_id": "s3_clock_skew",
  "year_hint": 2026,
  "reference_host": "web01",
  "sources": [
    {"path": "web01/auth.log",   "host": "web01", "source_type": "auth_log", "declared_tz": "UTC"},
    {"path": "web01/access.log", "host": "web01", "source_type": "nginx",    "declared_tz": "UTC"},
    {"path": "db01/auth.log",    "host": "db01",  "source_type": "auth_log", "declared_tz": "Asia/Kolkata"}
  ]
}
```
Paths are relative to the `sources.json` file. `declared_tz` is what the *operator says* the host's clock/zone is (syslog lines carry no zone). Nginx lines carry their own offset (`[08/Oct/2026:09:12:44 +0000]`), which wins over `declared_tz`.

### `ground_truth.json` (B writes, both use in tests)

```json
{
  "case_id": "s1_ssh_bruteforce",
  "attacker_ips": ["203.0.113.50"],
  "steps": [
    {"id": "S1-01", "ts_utc": "2026-10-03T02:14:07Z", "host": "web01",
     "event_type": "ssh_failed_login", "match": {"src_ip": "203.0.113.50"},
     "description": "First brute-force attempt"},
    {"id": "S1-02", "ts_utc": "2026-10-03T02:19:51Z", "host": "web01",
     "event_type": "ssh_accepted_login", "match": {"src_ip": "203.0.113.50", "username": "deploy"},
     "description": "First successful login (the answer to 'when did they get in?')"}
  ],
  "triage_questions": [
    {"q": "When did the attacker first successfully log in (UTC)?", "answer": "2026-10-03T02:19:51Z"},
    {"q": "Which source IP?", "answer": "203.0.113.50"},
    {"q": "What was the first privileged command run?", "answer": "sudo /bin/bash"}
  ],
  "expected_parse_gaps": 4,
  "expected_skew": {}
}
```

---

## 5. CLI contract (`forensic ...`, Typer)

| Command | Owner | Behaviour |
|---|---|---|
| `forensic ingest --case cases/s1 --sources scenarios/s1_ssh_bruteforce/sources.json --collector alice` | A | Creates the case dir, copies each file to `evidence/` (chmod 0444), SHA-256 at collection, writes `evidence` rows and `manifest.json`. Duplicate hash is skipped with a notice. |
| `forensic verify --case cases/s1` | A | Re-hashes every stored file vs manifest and DB. Prints `OK <file>` or `TAMPERED <file> expected=... actual=...`. Exit code 1 if any mismatch. |
| `forensic build --case cases/s1` | A | Parse, normalize, load `events`, `parse_gaps`, fill FTS. Idempotent (clears events first). Prints "N of M lines parsed (X%)". |
| `forensic skew --case cases/s1 [--reference web01] [--offset db01=-420]` | A | Estimates per-host offsets from anchors (or applies manual), writes `skew_corrections`, updates `ts_utc_corrected` / `skew_offset_s`. |
| `forensic search --case cases/s1 "union select" [--host web01] [--ip ...] [--type ...] [--from ... --to ...]` | B | Prints matching events in chronological order. |
| `forensic report --case cases/s1 --out reports/s1.html [--json reports/s1.json]` | B | Writes the incident report. |
| `forensic ui --case cases/s1` | B | Launches Streamlit viewer on that case. |
| `forensic run-all` | shared | Convenience: for each scenario folder run ingest, build, skew, report. Used by tests and the demo. |

`cli.py` is shared: A adds the first four commands, B adds the rest. To avoid merge conflicts each person writes their commands in their own module (`cli_evidence.py` for A, `cli_analysis.py` for B) and `cli.py` only does `app.add_typer(...)`. A creates `cli.py` on Wed 7.

---

## 6. Git workflow and merge rules

1. **Branches:** never commit to `main` directly. A uses `a/<topic>` (e.g. `a/ingest`), B uses `b/<topic>`. Keep branches under 1 day old, then PR.
2. **PRs:** the other person reviews (even a 5-minute skim) and merges with **squash**. Green `pytest` required before merge.
3. **Commit style:** `feat(ingest): add sha256 chunked hashing`, `fix(parser): handle Dec-Jan rollover`, `test:`, `docs:`.
4. **File ownership:** see layout tags `[A]`/`[B]`. Do not edit the other's files; open an issue or a PR for them to review. `.github/CODEOWNERS` encodes this.
5. **Contract changes** (sections 0 to 6, `schema.sql`, `models.py`, `sources.json` or `ground_truth.json` format): PR with label `contract`, both approve, and announce in chat before merging.
6. **Never commit** `cases/`, `.venv/`, real secrets, or real personal logs. Synthetic scenario logs are committed.
7. **Rebase daily:** `git fetch && git rebase origin/main` every morning.
8. **Integration checkpoints (merge everything to `main`):**
   - **Fri 9 Oct night:** thin end-to-end slice (S1: ingest, build, search).
   - **Sun 11 Oct night:** all 3 scenarios end to end including viewer and report.
   - **Tue 13 Oct evening:** code freeze, tag `v1.0-submission`.
9. **Repo admin (do today if not done):** invite accepted by `aiori-hackathon`; transfer ownership only after both teammates and `aiori-hackathon` accepted; repo name = team name. After transfer you keep working through collaborator access, so confirm you still have write access.

---

## 7. Daily timeline (shared view)

| Day | Person A | Person B | Sync |
|---|---|---|---|
| **Wed 7** | models.py, schema.sql, db.py, cli skeleton, push; start ingest | Scenario generator S1+S2; start PDF (problem, background); fixtures/seed_db.py | Push contract files tonight; 15-min call |
| **Thu 8** | Ingest, hashing, verify; start auth parser | Finish S3 + ground truths; push all logs by midday; timeline.py skeleton | A runs ingest on B's logs |
| **Fri 9** | Both parsers, normalize, parse_gaps, build | timeline.py queries + FTS; start viewer on seeded DB | **Checkpoint 1: thin slice merged** |
| **Sat 10** | Skew; tests | Viewer finished; report template | S3 correlates only after skew |
| **Sun 11** | Bug fixes, edge cases, README | Report finished; evaluation harness; run-all | **Checkpoint 2: full e2e merged** |
| **Mon 12** | Support evaluation; fix issues; final tests | Triage experiment; parsing-gap analysis; PDF finalised | Agree on numbers |
| **Tue 13** | Freeze; repo cleanup; tag | Demo rehearsal x2; pseudocode; upload PDF | Verify collaborator + ownership |
| **Wed 14** | Buffer | Buffer | Submit |

---

# PART II: PERSON B TASKS (Scenarios, Timeline, Viewer, Report, Evaluation, Deck)

You own: `scenarios/`, `timeline.py`, `report.py`, `templates/`, `viewer/app.py`, `cli_analysis.py`, `evaluation/`, `docs/`, and tests `test_ground_truth.py`, `test_timeline_report.py`.

**Your first deliverable blocks A.** Push scenario logs by **Thu 8 midday**. Until A's pipeline is ready (Fri 9), develop against a **seeded fake DB** (B2).

## B1. Synthetic scenario generator (`scenarios/generate.py`)

Requirements: deterministic (`random.Random(seed)`), writes logs + `sources.json` + `ground_truth.json` into each scenario folder, mixes **background noise** (legitimate traffic and logins, roughly 90% of lines) with **attack steps** (roughly 10%), and includes **deliberate malformed lines** for parsing-gap testing. Use fake IPs from documentation ranges only (`203.0.113.0/24` attacker, `198.51.100.0/24` normal users, `192.0.2.0/24` internal). No real data.

Run: `python scenarios/generate.py` regenerates all three (commit the output so A can use them).

### Scenario 1: `s1_ssh_bruteforce` (single host, auth.log, tz UTC)

| Step | Time (UTC, 3 Oct 2026) | Action |
|---|---|---|
| S1-01 | 02:14:07 | Attacker `203.0.113.50` starts brute force: ~150 failed attempts over 5 minutes, usernames `root`, `admin`, `test`, `oracle` (mix of `invalid user` and valid) |
| S1-02 | 02:19:51 | `Accepted password for deploy from 203.0.113.50` (the answer to "when did they get in?") |
| S1-03 | 02:20:30 | `session opened for user deploy` |
| S1-04 | 02:22:12 | `sudo: deploy : ... COMMAND=/bin/bash` (privilege escalation) |
| S1-05 | 02:24:40 | `new user: name=support` (persistence), then `sudo ... COMMAND=/usr/bin/passwd support` |
| S1-06 | 02:31:05 | Session closed |

Noise: cron sessions, legitimate logins by `alice` and `bob` from `198.51.100.x`, a few failed logins from real users (typos). Malformed lines (4): a truncated line, a garbled-binary line, a line with `Feb 30` timestamp, a line in a different format entirely. `expected_parse_gaps: 4`.

### Scenario 2: `s2_web_attack` (single host, Nginx access.log, offset +0000)

| Step | Time (UTC, 5 Oct 2026) | Action |
|---|---|---|
| S2-01 | 14:02:10 | Scanner `203.0.113.77` (UA `Nikto`) probes `/wp-login.php`, `/.env`, `/phpmyadmin`, mostly 404s |
| S2-02 | 14:09:33 | SQL injection on `/products.php?id=1' UNION SELECT ...` (one URL-encoded, one double-encoded) |
| S2-03 | 14:14:02 | Directory traversal `/download?file=../../etc/passwd` |
| S2-04 | 14:18:47 | `POST /upload.php` with `shell.php`, status 200 (webshell upload) |
| S2-05 | 14:20:15 | `GET /uploads/shell.php?cmd=id` and later `cmd=cat+/etc/shadow` (webshell use) |
| S2-06 | 14:27:40 | Burst of 404/500 as attacker explores; last attacker request |

Noise: normal browsing from many `198.51.100.x` clients with realistic UAs, static assets, API calls. Malformed lines (5): truncated line, wrong date format, missing quotes, a line from a different log format, empty line. `expected_parse_gaps: 5`.

### Scenario 3: `s3_clock_skew` (two hosts, the differentiator)

Hosts: **web01** (nginx access.log + auth.log, tz UTC, **reference**, correct clock) and **db01** (auth.log + nginx-fronted admin panel `access.log`, declared tz `Asia/Kolkata`, **clock runs 7 min 0 s fast**).

| Step | True time (UTC, 8 Oct 2026) | Action |
|---|---|---|
| S3-01 | 09:00:00 to 09:00:20 | Attacker `203.0.113.90` scripted scan hits the **same ~10 paths on both web01 and db01 within about 2 s of each other** (these are the anchors; make the paths distinct, e.g. `/admin`, `/backup.sql`, `/server-status`) |
| S3-02 | 09:05:30 | SQLi on web01 `/search.php` |
| S3-03 | 09:08:12 | Webshell on web01 |
| S3-04 | 09:12:45 | From web01 the attacker pivots: `Accepted password for dbadmin from 192.0.2.10` on **db01** |
| S3-05 | 09:14:03 | `sudo` on db01 |
| S3-06 | 09:15:30 | Data export request on db01 admin panel |

db01's log entries are written with `true_time + 7 min` (and expressed in IST for syslog). **Without correction, db01's login at "09:19:45" appears to happen after the sudo and export on web01 timeline ordering is broken; with correction the causal order S3-03, S3-04, S3-05 is restored.** Store in ground truth: `"expected_skew": {"db01": -420}`. This scenario also needs at least 3 well-spaced anchors (use 10).

### Output per scenario folder
```
scenarios/s1_ssh_bruteforce/auth.log
scenarios/s1_ssh_bruteforce/sources.json     # section 4 format
scenarios/s1_ssh_bruteforce/ground_truth.json
scenarios/s3_clock_skew/web01/{auth.log,access.log}
scenarios/s3_clock_skew/db01/{auth.log,access.log}
```
Generator helper sketch:
```python
def write_syslog(path, host, tz, entries):   # entries: (true_utc, proc, msg); applies clock_offset_s then tz
def write_nginx(path, entries):              # entries: (true_utc, ip, method, path, status, ua); applies offset
def inject_malformed(lines, rng, kinds):     # insert deliberate bad lines at random positions
```

**Done when:** all three scenarios + ground truth pushed Thu midday; you have hand-checked that ground-truth times match the log lines.

## B2. Fixture DB (`scenarios/fixtures/seed_db.py`) so you are never blocked

Builds `cases/<id>/case.db` using A's `schema.sql`, inserting events derived from `ground_truth.json` plus synthetic noise, fake evidence rows (fake hashes), and a sample `skew_corrections` row. Build the timeline and viewer against it from Thu onward. On Fri, replace with A's real `forensic build`.

## B3. Timeline query layer (`timeline.py`)

```python
@dataclass
class Filters:
    hosts: list[str] | None = None
    source_types: list[str] | None = None
    event_types: list[str] | None = None
    severities: list[str] | None = None
    src_ip: str | None = None
    username: str | None = None
    ts_from: str | None = None      # ISO UTC
    ts_to: str | None = None
    text: str | None = None         # FTS query
    use_corrected: bool = True      # sort/filter on ts_utc_corrected vs ts_utc

def query_events(conn, f: Filters, limit=5000, offset=0) -> list[sqlite3.Row]
def context_window(conn, event_id: int, seconds=60) -> list[Row]        # events around one event, all hosts
def get_evidence(conn, evidence_id) -> Row                              # for hash display
def summary_stats(conn) -> dict          # counts by host/type/severity, first/last event, top src IPs
def key_events(conn) -> list[Row]        # severity high, plus first ssh_accepted_login per IP
def gap_summary(conn) -> list[dict]      # per evidence: total, parsed, gaps, by reason
def skew_summary(conn) -> list[Row]
```
- FTS: `SELECT ... FROM events JOIN events_fts ON events.id = events_fts.rowid WHERE events_fts MATCH ?`. Sanitise user input (wrap in double quotes, escape internal quotes) so special characters do not crash FTS.
- Order by `ts_utc_corrected, id`. Return both `ts_utc` and `ts_original` so the UI can show them.
- **CLI `search`** in `cli_analysis.py` prints a compact table: `time_utc | host | type | ip | message`.

**Done when:** querying S1 for `ssh_accepted_login` returns S1-02's time exactly as in ground truth.

## B4. Streamlit viewer (`viewer/app.py`)

Launch: `forensic ui --case cases/s1` (runs `streamlit run viewer/app.py -- --case cases/s1`).

Layout:
- **Sidebar:** case picker, filters (hosts, event types, severity, IP, username, time range, free-text search), toggle "use skew-corrected time".
- **Tab 1, Timeline:** table (time UTC, original time, host, type, severity, IP, user, message), severity colour hints, row selection, pagination. Above it an Altair histogram of events per minute, coloured by host.
- **Tab 2, Event detail:** for the selected event show raw line, evidence file, line number, byte offset, **evidence SHA-256**, original vs normalized vs corrected time, and a +/- 60 s context window across hosts.
- **Tab 3, Evidence:** manifest table (file, host, hash, size, collected_at, collector); button **"Verify integrity"** that calls A's verify function and shows OK/TAMPERED.
- **Tab 4, Parsing gaps:** per-file stats (parsed %), reasons bar chart, table of unparsed raw lines.
- **Tab 5, Clock skew:** skew table with confidence notes, plus a before/after chart for the skewed host.
- **Header strip:** case id, number of events, first/last event time, number of gaps.

Keep it simple: no auth, no network, everything from `case.db`.
**Done when:** on S3 toggling "use corrected time" visibly reorders db01 events relative to web01.

## B5. Report export (`report.py`, `templates/report.html.j2`)

`forensic report --case cases/s3 --out reports/s3.html --json reports/s3.json`

Sections (HTML, print-friendly CSS, `@media print`):
1. **Case summary:** case id, generated at UTC, tool version, collector, time span, hosts.
2. **Executive timeline summary:** auto-generated bullets from `key_events`, e.g. "First successful login: 2026-10-03T02:19:51Z from 203.0.113.50 as deploy".
3. **Evidence manifest:** table with SHA-256 for every file, manifest hash, and verification status at report time.
4. **Normalization & time handling:** declared timezones, year assumptions, skew corrections table with confidence notes.
5. **Chronological key-event timeline** (all `medium` or `high`, plus first/last events), each row with source file + line number.
6. **Parsing gaps:** per-file coverage and reasons, with a sample of unparsed lines.
7. **Limitations & scope:** no live endpoint takeover, no malware removal, **not forensically certified**; assumptions (declared tz, anchor simultaneity); synthetic data notice.
8. **Appendix:** full event count by type/host.

JSON export mirrors these sections (machine-readable). Add CSV export of the full timeline (`--csv`).
**Done when:** one command yields a report that opens in a browser and prints cleanly to PDF.

## B6. Ground-truth tests (`tests/test_ground_truth.py`)

For each scenario run: ingest, build, skew via the Python API, then assert:
1. Every `steps[*]` has a matching event (by `event_type` + `match` fields) with `ts_utc_corrected` within **5 s** of the true time.
2. Each `triage_questions` answer is derivable from `query_events`.
3. Gap count equals `expected_parse_gaps`.
4. For S3: without skew, ordering of S3-03 and S3-04 is wrong; with skew correct; estimated offset within 5 s of `expected_skew`.
5. `verify` returns OK on a clean case.

## B7. Evaluation (`evaluation/`)

### B7a. Triage-time experiment (the "manual baseline")

Per scenario, 4 fixed questions (stored in `ground_truth.json.triage_questions` and copied to `evaluation/triage_questions.md`):
1. When did the attacker first succeed (UTC)?
2. Which source IP(s)?
3. What was the first sensitive action after that?
4. (S3 only) Which happened first: web01 webshell or db01 login?

**Protocol**
- Both people participate; **each tests the scenario the other did not write** (A for S1/S2 written by B, and so on) to reduce bias. Note: B wrote all the scenarios, so have A do S1 and S2 manually, and B do S3 manually after A explains only the raw files, not the answer.
- Condition M (manual): only `grep`, `less`, `sort`, `date` allowed. Condition T (tool): the viewer/CLI. Alternate which condition goes first.
- Start a stopwatch when the questions are shown, stop per question when the answer is stated. Record correctness against ground truth.
- Record in `evaluation/triage_results.csv`:
```
scenario,tester,condition,question_id,seconds,correct,notes
s1,A,manual,Q1,412,true,"grep Accepted auth.log"
s1,A,tool,Q1,38,true,"filter ssh_accepted_login"
```
- Compute: median time per condition, speedup factor, accuracy per condition. Report honestly: n is small (2 testers x 3 scenarios), and testers know the tool, which biases toward the tool. State this limitation.

### B7b. Parsing-gap analysis (`evaluation/parsing_gap_analysis.md`)

From `gap_summary`: table per scenario and file: total lines, parsed, gaps, parsed %, reasons. Discuss each gap category: why it occurred, whether it is a tool limitation or a malformed input, and what extra work would close it (e.g. support RFC 5424 syslog, Apache error log, JSON logs). Include honest "what this tool does not parse" list.

## B8. Deck / PDF (`docs/`)

Use the AIORI Beamer template in `Proposed-structure-hackathon.pdf` (LaTeX, Overleaf). Fill each slide:

| Slide | Content source |
|---|---|
| Title | Team name, member names, PS-013 title, date |
| Abstract / Problem | Section 0 of this guide plus the "scattered, messy, skewed, fragile logs" problem |
| Background | Small-team IR reality; hashing and chain of custody; NIST SP 800-86 [1] |
| Literature & RFC review | NIST SP 800-86; RFC 3164 / RFC 5424 (syslog); RFC 3339 (timestamps); Plaso/Timesketch papers or docs; Nginx log format docs. Keep to 4 to 5 |
| Proposed solution | Pipeline: collect, hash, parse, normalize, skew-correct, timeline, report |
| Optimization | Before/after table: manual grep/Excel vs tool (time, integrity, skew handling, gap visibility) using real numbers from B7 |
| Architecture (UML) | Component diagram: CLI, Ingest, Parsers, Normalizer, Skew, SQLite, Timeline, Viewer, Report |
| Data flow diagram | Logs -> evidence store (+hash) -> parsers -> normalized events -> skew -> DB -> viewer/report |
| Deployment timeline | The 7 to 14 Oct plan, trimmed |
| Bibliography | Real references only (replace Einstein/cows placeholders) |

Draw diagrams in draw.io or Mermaid, export PNG. Final file: `docs/<TeamName>-PS013.pdf`, also linked from README. Start slides 1 to 4 on Wed 7 while A bootstraps.

## B9. Demo script and pseudocode (`docs/demo_script.md`, `docs/pseudocode.md`)

**5-minute demo flow**
1. 20 s: problem statement (messy logs, drifting clocks, integrity).
2. 60 s: `forensic ingest` S3, show manifest + hashes; tamper one byte, `forensic verify` fails, restore.
3. 60 s: `forensic build`, show parsing coverage and gap table.
4. 90 s: viewer, S3 without correction vs with `forensic skew`; show causal order restored; click an event to show raw line + hash.
5. 45 s: `forensic report`, open HTML.
6. 45 s: triage results table and limitations.
Rehearse twice (Tue). Keep a pre-built case (`cases/`) as a fallback if live commands fail.

**Pseudocode snippet for the mentor (about 25 lines, final from A on Tue)**
```
for each source file:
    h = SHA256(file); copy to read-only evidence/; record (name, h, collector, utc_now)
for each stored file, line by line:
    event or gap = parser(line)             # keep line_no, byte_offset, raw_line
    ts_utc = to_utc(ts_original, declared_tz, year_hint)
anchors = pairs of same (ip, type, detail) across hosts
offset[host] = median(ref_ts - host_ts over anchors); confidence from stdev
ts_corrected = ts_utc + offset[host]
timeline = events ordered by ts_corrected; report = timeline + manifest + gaps + limitations
```

## B10. Your day-by-day

| Day | Tasks | Exit criterion |
|---|---|---|
| **Wed 7** | Review/merge A's bootstrap PR; B1 for S1+S2; B8 slides 1 to 4; start B2 | S1 and S2 generator drafted |
| **Thu 8** | Finish B1 incl. S3 + ground truths; **push logs by midday**; B2 fixture DB; B3 skeleton | All scenario folders on `main`; fake DB working |
| **Fri 9** | B3 queries + FTS + `search` CLI; start B4 on fake DB; swap to real DB when A merges | **Checkpoint 1:** `forensic search` works on real S1 data |
| **Sat 10** | Finish B4 viewer; B5 report template; B6 tests | Viewer shows all tabs; S3 toggle works |
| **Sun 11** | Finish B5; B6 green; `run-all`; start B7 harness; diagrams for deck | **Checkpoint 2:** all 3 scenarios e2e on `main` |
| **Mon 12** | B7 triage experiment with A, B7b analysis, fill results into deck, export PDF | Numbers + PDF in repo |
| **Tue 13** | Demo rehearsal x2, pseudocode final, PDF uploaded, verify collaborator + ownership transfer | Everything pushed |
| **Wed 14** | Buffer | Submit |

## B11. Handoffs

- **To A (Thu midday):** scenario logs, `sources.json`, `ground_truth.json`.
- **From A (Fri 9):** working `ingest`, `build`; Sat: `skew`.
- **If A's parser output differs from your ground truth:** first check your generator, then open an issue with the exact line; do not edit A's parsers.

## B12. Cut order if time runs out

Viewer polish (charts, context window), then CSV export, then report styling. **Never cut:** 3 scenarios, ground-truth tests, searchable timeline, report with hashes + gaps + limitations, triage comparison, PDF.

## B13. Definition of done (B)

- [ ] 3 scenarios generated with noise, malformed lines, ground truth
- [ ] Timeline filters + FTS search; CLI `search`
- [ ] Viewer with timeline, event detail (hash shown), evidence, gaps, skew tabs
- [ ] HTML + JSON (+ CSV) report with limitations section
- [ ] Ground-truth tests green; triage CSV + analysis written
- [ ] PDF in repo following template; demo rehearsed; pseudocode ready
