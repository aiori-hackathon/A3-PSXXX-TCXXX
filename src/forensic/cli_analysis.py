import typer
import sqlite3
from pathlib import Path
from forensic.timeline import query_events, Filters
import json
import subprocess
import sys

app = typer.Typer()

def get_conn(case_dir: Path):
    db_path = case_dir / "case.db"
    if not db_path.exists():
        typer.echo(f"Database not found: {db_path}", err=True)
        raise typer.Exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@app.command()
def search(
    case: Path = typer.Option(..., "--case", help="Case directory"),
    query: str = typer.Argument(None, help="FTS search query"),
    host: str = typer.Option(None, help="Filter by host"),
    ip: str = typer.Option(None, help="Filter by source IP"),
    type: str = typer.Option(None, help="Filter by event type"),
    ts_from: str = typer.Option(None, "--from", help="Start time (ISO UTC)"),
    ts_to: str = typer.Option(None, "--to", help="End time (ISO UTC)"),
    limit: int = typer.Option(200, "--limit", help="Max results")
):
    conn = get_conn(case)
    f = Filters(
        text=query,
        hosts=[host] if host else None,
        src_ip=ip,
        event_types=[type] if type else None,
        ts_from=ts_from,
        ts_to=ts_to
    )
    events = query_events(conn, f, limit=limit)
    for e in events:
        typer.echo(f"{e['ts_utc_corrected']} | {e['host']} | {e['event_type']} | {e.get('src_ip', '')} | {e['message']}")

@app.command()
def report(
    case: Path = typer.Option(..., "--case", help="Case directory"),
    out: Path = typer.Option(..., help="Output HTML path"),
    json_out: Path = typer.Option(None, "--json", help="Output JSON path"),
    csv: Path = typer.Option(None, "--csv", help="Output CSV path")
):
    from forensic.report import generate_report
    generate_report(case, out, json_out, csv)
    typer.echo(f"Report generated at {out}")

@app.command()
def ui(case: Path = typer.Option(..., "--case", help="Case directory")):
    typer.echo(f"Launching Streamlit viewer for {case}...")
    app_path = Path(__file__).resolve().parents[2] / "viewer" / "app.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path), "--", "--case", str(case)])
