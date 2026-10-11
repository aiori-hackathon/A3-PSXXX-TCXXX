import sqlite3
import sys
from pathlib import Path
from forensic.timeline import gap_summary
from forensic import db

def main():
    cases_dir = Path("cases")
    if not cases_dir.exists():
        print("No cases directory found.")
        sys.exit(1)
        
    out_lines = ["# Parsing Gap Analysis\n"]
    out_lines.append("## Coverage by Scenario and File\n")
    out_lines.append("| Scenario | Host | File | Total Lines | Parsed | Gaps | Blank | Parsed % | Reasons |")
    out_lines.append("|---|---|---|---|---|---|---|---|---|")
    
    import json
    valid_cases = set()
    for sources_file in Path("scenarios").rglob("sources.json"):
        with open(sources_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "case_id" in data:
                valid_cases.add(data["case_id"])
                
    for case_path in sorted(cases_dir.iterdir()):
        if not case_path.is_dir():
            continue
            
        if case_path.name not in valid_cases:
            print(f"Warning: skipping {case_path.name} as it is not a scenario case_id.")
            continue
            
        db_path = case_path / "case.db"
        if not db_path.exists():
            continue
            
        conn = db.connect(case_path)
        conn.row_factory = sqlite3.Row
        
        gaps = gap_summary(conn)
        for g in gaps:
            # format reasons
            reason_str = ", ".join(f"{k}: {v}" for k, v in g.get("reasons", {}).items())
            if not reason_str:
                reason_str = "None"
                
            out_lines.append(f"| {case_path.name} | {g['host']} | {g['filename']} | {g['total_lines']} | {g['parsed']} | {g['gaps']} | {g['blank_lines']} | {g['parsed_pct']:.2f}% | {reason_str} |")
            
        conn.close()
        
    out_lines.append("\n## Gap Categories Discussion\n")
    out_lines.append("- **no_regex_match**: The log line format does not match the parser's expected regular expression. This is typically a tool limitation (e.g. unknown daemon) but can also happen for malformed input.")
    out_lines.append("- **bad_timestamp**: The timestamp could not be parsed into a valid date/time. Often caused by corrupted logs or unexpected date formats (malformed input).")
    out_lines.append("- **truncated**: The log line ends abruptly, possibly due to a crash, disk full, or bad network transfer (malformed input).")
    out_lines.append("- **empty_line**: The log line consists entirely of whitespace. Usually safe to ignore (malformed input / noise).")
    out_lines.append("- **encoding_error**: The line contains non-UTF-8 bytes. Caused by binary data dumped into logs or different encodings (malformed input).")
    
    out_lines.append("\n## What the tool does not parse\n")
    out_lines.append("- RFC 5424 syslog format")
    out_lines.append("- Apache error log")
    out_lines.append("- JSON logs")
    out_lines.append("- Multi-line stack traces (often recorded as multiple invalid lines)")
    out_lines.append("- Non-UTF-8 logs")
    out_lines.append("- DST-ambiguous local times")
    
    out_path = Path("evaluation/parsing_gap_analysis.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    
if __name__ == "__main__":
    main()
