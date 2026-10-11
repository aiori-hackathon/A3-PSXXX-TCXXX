# AIORI PS-013 Incident Timeline & Evidence Collection

This is a lightweight digital-forensics CLI tool for the AIORI hackathon (PS-013). It ingests Linux `auth.log` and Nginx access logs, copies them untouched into a read-only evidence store with SHA-256 hashes and a manifest, parses them into a SQLite database with UTC timestamps, records unparsed lines (parse gaps), and corrects clock skew between hosts.

## Installation

```bash
python -m venv .venv
# Activate the virtual environment:
# Windows: .venv\Scripts\activate
# Unix/MacOS: source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Quick Start

The tool provides a main `forensic` CLI with four core commands:

1. **Ingest**: Collect log files, hash them, and store them securely.
   ```bash
   forensic ingest --case /tmp/c --sources /path/to/sources.json --collector gayatri
   ```
2. **Verify**: Check the integrity of the evidence store against the manifest.
   ```bash
   forensic verify --case /tmp/c
   ```
3. **Build**: Parse evidence files into the SQLite database.
   ```bash
   forensic build --case /tmp/c
   ```
4. **Skew**: Estimate and correct clock skew between hosts.
   ```bash
   forensic skew --case /tmp/c --reference web01
   ```
   Or manually set an offset:
   ```bash
   forensic skew --case /tmp/c --offset db01=-420
   ```
   
There is also a `run-all` command to process multiple scenarios at once.

## Verification

Verification ensures that the collected evidence has not been tampered with:
1. **Hash at Ingest**: Files are hashed (SHA-256) upon collection and copied to a read-only evidence store (`0o444` permissions).
2. **Manifest**: A `manifest.json` tracks each file, its original path, size, line count, and SHA-256 hash. A `manifest.sha256` hash of the manifest file itself is also created.
3. **Verify Command**: The `forensic verify` command checks the manifest's own hash, then verifies that every file listed in the manifest exists, matches its expected hash, and corresponds to exactly one row in the evidence database table with matching details.

## SQLite Database Tables

- `case_meta`: Key-value pairs for case metadata (e.g., case_id, created_at_utc).
- `evidence`: Registry of collected files and their metadata (hashes, paths).
- `events`: Parsed log events with normalized UTC timestamps and extracted details.
- `events_fts`: Full-text search index for the events table.
- `parse_gaps`: Records lines that could not be parsed and the reason why.
- `skew_corrections`: Applied clock skew corrections per host.

## Known Limitations

- Syslog year and timezone are operator-declared (via `sources.json` hints or file mtime inference).
- Clock skew anchor matching assumes the paired events happened within 5 seconds of each other.
- Daylight Saving Time (DST) fold ambiguity is not automatically resolved.
- Currently supports only two log formats: `auth.log` (syslog) and `nginx` access logs.
- This tool is a prototype and is not forensically certified.
- Does not include capabilities for live endpoint takeover or malware removal.

## Project Layout

- `src/forensic/`: Core Python package.
  - `models.py`, `schema.sql`: Shared data models and database schema.
  - `ingest.py`, `build.py`, `skew.py`, `normalize.py`: Core processing logic.
  - `parsers/`: Log format parsers (`auth_log.py`, `nginx.py`).
  - `cli.py`, `cli_evidence.py`: Typer CLI applications.
- `tests/`: Pytest suite and fixtures.
- `docs/`: Documentation (including implementation guides).
- `cases/`: Generated case output directories (git-ignored).
- `scenarios/`: Example input scenarios for testing (handled by Person B).

## Demo walkthrough

- `forensic run-all`: Processes all scenarios through ingest, build, skew, and report generation.
- `forensic verify --case cases/s3_clock_skew`: Verifies evidence integrity against the generated manifest hashes.
- Tamper one stored evidence file then verify again: Demonstrates that the verify command detects any unauthorized modification to the read-only evidence store.
- `forensic search --case cases/s2_web_attack "UNION"`: Performs a full-text search to find SQL injection attempts in the database.
- `forensic report --case cases/s3_clock_skew --out reports/s3_clock_skew.html`: Generates an interactive HTML summary report for the scenario.
- `forensic ui --case cases/s3_clock_skew`: Starts a local web server to interactively explore the timeline data.

## Scenarios

| Scenario | Expected Parse Gaps | Expected Skew |
|---|---|---|
| S1 SSH brute force | 4 | None |
| S2 web attack | 5 | None |
| S3 clock skew | 0 | db01 about -420 seconds |

## Results

- **Triage Speed & Accuracy:** 4.4x overall speedup (Tool median 8.2 s vs. Manual baseline median 36.1 s). Manual triage misidentified timestamp order under clock skew (db01 login), whereas the tool's skew correction reconstructed the true sequence.
- **Ground Truth Validation:** 18 of 18 attack progression steps matched within 1.5 seconds across all 3 scenarios.
- **Clock Skew Resolution:** In S3, db01 clock was estimated at -421.5 s (true offset: -420 s) with 10 anchor pairs and standard deviation 0.9 s (high confidence).
- **Parsing Gap Transparency:** Zero silent drops. Identified 4 gaps in S1 (97.6% parsed), 5 in S2 (96.4% parsed), and 0 in S3 (100% parsed).
- **Cryptographic Evidence Integrity:** SHA-256 manifest and read-only preservation detect tampering with 100% reliability.

## Deliverables

- [x] [docs/pseudocode.md](docs/pseudocode.md)
- [x] [docs/demo_script.md](docs/demo_script.md)
- [x] [A3-PS013-TC067.pdf](A3-PS013-TC067.pdf)
- [x] [evaluation/triage_summary.md](evaluation/triage_summary.md)
- [x] [evaluation/parsing_gap_analysis.md](evaluation/parsing_gap_analysis.md)
