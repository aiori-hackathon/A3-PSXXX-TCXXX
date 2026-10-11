import csv
import statistics
import sys
from pathlib import Path

def main():
    csv_path = Path("evaluation/triage_results.csv")
    if not csv_path.exists():
        print("No data yet")
        sys.exit(0)
        
    rows = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
            
    if not rows:
        out_path = Path("evaluation/triage_summary.md")
        out_path.write_text("No data yet", encoding="utf-8")
        print("No data yet")
        sys.exit(0)
        
    # Group by scenario and condition
    stats = {} # (scenario, condition) -> list of rows
    overall = {"manual": [], "tool": []}
    
    for r in rows:
        scen = r["scenario"]
        cond = r["condition"]
        sec = float(r["seconds"])
        correct = r["correct"].lower() == "true"
        
        if (scen, cond) not in stats:
            stats[(scen, cond)] = []
        stats[(scen, cond)].append({"seconds": sec, "correct": correct})
        
        if cond in overall:
            overall[cond].append(sec)
            
    out_lines = ["# Triage Evaluation Summary\n"]
    
    # Per scenario table
    scenarios = sorted(list(set(k[0] for k in stats.keys())))
    out_lines.append("## Results by Scenario\n")
    out_lines.append("| Scenario | Condition | Median (s) | Total (s) | Accuracy |")
    out_lines.append("|---|---|---|---|---|")
    
    for scen in scenarios:
        for cond in ["manual", "tool"]:
            k = (scen, cond)
            if k in stats:
                times = [x["seconds"] for x in stats[k]]
                med = statistics.median(times)
                tot = sum(times)
                corr = sum(1 for x in stats[k] if x["correct"])
                acc = (corr / len(times)) * 100
                out_lines.append(f"| {scen} | {cond} | {med:.1f} | {tot:.1f} | {acc:.1f}% |")
                
    out_lines.append("\n## Overall Performance\n")
    med_man = statistics.median(overall["manual"]) if overall["manual"] else 0
    med_tool = statistics.median(overall["tool"]) if overall["tool"] else 0
    
    out_lines.append(f"- **Manual overall median:** {med_man:.1f} s")
    out_lines.append(f"- **Tool overall median:** {med_tool:.1f} s")
    if med_tool > 0 and med_man > 0:
        speedup = med_man / med_tool
        out_lines.append(f"- **Speed-up:** {speedup:.1f}x")
        
    out_lines.append("\n## Limitations")
    out_lines.append("- Sample size (n) is very small.")
    out_lines.append("- Testers are the authors and know the tool well.")
    out_lines.append("- Scenario authors had prior knowledge of the events.")
    out_lines.append("- Synthetic data might not perfectly replicate real-world complexity.")
    
    out_path = Path("evaluation/triage_summary.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    
if __name__ == "__main__":
    main()
