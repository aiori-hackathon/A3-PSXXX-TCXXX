import json
from pathlib import Path

import typer

from forensic.cli_analysis import app as analysis_app
from forensic.cli_evidence import app as evidence_app

app = typer.Typer(help="Forensic Timeline & Evidence Collection Tool", no_args_is_help=True)
for _sub in (evidence_app, analysis_app):
    for _cmd in _sub.registered_commands:
        app.registered_commands.append(_cmd)


@app.command("run-all")
def run_all(
    scenarios_dir: Path = typer.Option(Path("scenarios"), "--scenarios"),
    cases_dir: Path = typer.Option(Path("cases"), "--cases"),
    reports_dir: Path = typer.Option(Path("reports"), "--reports"),
    collector: str = typer.Option("run-all", "--collector"),
    report: bool = typer.Option(True, "--report/--no-report"),
):
    from forensic.pipeline import run_case

    if not scenarios_dir.exists() or not any(scenarios_dir.iterdir()):
        typer.echo("No scenarios found")
        raise typer.Exit(0)

    found_any = False
    for scenario in sorted(scenarios_dir.iterdir()):
        sources_json = scenario / "sources.json"
        if not scenario.is_dir() or not sources_json.exists():
            continue

        found_any = True
        with open(sources_json, "r", encoding="utf-8") as f:
            spec = json.load(f)
        case_id = spec.get("case_id", scenario.name)
        case_dir = cases_dir / case_id

        res = run_case(sources_json, case_dir, collector)
        total_events = sum(s.get("parsed", 0) for s in res.get("build", []))
        total_gaps = sum(s.get("gaps", 0) for s in res.get("build", []))
        skew_count = len(res.get("skew", []))

        typer.echo(f"{case_id}: {total_events} events parsed, {total_gaps} gaps, {skew_count} skew rows")

        if report:
            from forensic.report import generate_report

            reports_dir.mkdir(parents=True, exist_ok=True)
            generate_report(
                case_dir,
                reports_dir / f"{case_id}.html",
                reports_dir / f"{case_id}.json",
                reports_dir / f"{case_id}.csv",
            )

    if not found_any:
        typer.echo("No scenarios found")
        raise typer.Exit(0)


if __name__ == "__main__":
    app()
