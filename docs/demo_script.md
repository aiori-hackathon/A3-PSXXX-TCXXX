# Demo script (5 minutes)

| Time | Action | What to say |
|---|---|---|
| 0:00 | Show the README problem statement | Small teams rebuild timelines by hand; logs are messy, clocks drift, evidence integrity is fragile. |
| 0:20 | `forensic run-all` | One command: verify, hash, parse and skew-correct three synthetic incidents. |
| 0:50 | Open `cases/s3_clock_skew/manifest.json` | Every evidence file has a SHA-256 and the manifest itself is hashed. |
| 1:10 | Make a stored file writable, append one byte, run: `forensic verify --case cases/s3_clock_skew` | Tampering is detected: TAMPERED, exit code 1. Then run forensic run-all again to restore. |
| 1:40 | `forensic ui --case cases/s3_clock_skew`, Parsing gaps tab | Coverage and gaps are shown; nothing is silently dropped. S1 has 4 gaps, S2 has 5, S3 has 0. |
| 2:10 | Clock skew tab, then untick and tick "Use skew-corrected time" on the Timeline tab | db01's clock runs 7 minutes fast; 10 anchor pairs give a median offset of -421.5 s (true -420 s). The db01 pivot login moves from 09:19:45 to about 09:12:44, which is 4 min 31 s after the webshell instead of 11 min 33 s. |
| 3:00 | Event detail tab on that login | Raw line, evidence file, line number, byte offset and SHA-256: every event traces back to its source line. |
| 3:30 | `forensic search --case cases/s2_web_attack "UNION"` and a filtered search | Searchable timeline. |
| 3:50 | `forensic report --case cases/s3_clock_skew --out reports/s3_clock_skew.html`, open it | Hashes with verification status, skew with confidence, gaps, limitations. |
| 4:20 | Open `evaluation/triage_summary.md` | Measured triage times against the grep baseline, with honest limitations. |
| 4:45 | Show `docs/pseudocode.md` | The core algorithm in about 20 lines. |

## Fallback
- Keep `cases/` and `reports/` pre-built in the repository workspace.
- Keep a backup screen recording of the complete workflow.

## Before the demo
- `git pull`
- `pip install -e .`
- `forensic run-all`
- Close other Streamlit servers: `netstat -ano | findstr :850`
- Have terminal windows open at the repository root.

## Anticipated questions
- **Why anchor-based skew?**
  It needs no external reference clock and gives a confidence note based on standard deviation and anchor count.
- **What does the tool not do?**
  Live takeover, malware removal, certification, or formats other than `auth.log` and Nginx `access.log`.
- **How do you know timestamps are right?**
  Ground-truth tests: 18 of 18 steps matched within 1.5 seconds.
