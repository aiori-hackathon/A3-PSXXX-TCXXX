import sys
from pathlib import Path

import typer

app = typer.Typer()


@app.command()
def ingest(
    case: Path = typer.Option(..., help="Case directory"),
    sources: Path = typer.Option(..., help="Path to sources.json"),
    collector: str = typer.Option(..., help="Collector username"),
):
    """Ingest sources into the case directory."""
    from .ingest import ingest as do_ingest
    do_ingest(case, sources, collector)
    typer.echo("Ingest complete.")


@app.command()
def verify(case: Path = typer.Option(..., help="Case directory")):
    """Verify evidence integrity."""
    from .ingest import verify as do_verify
    if do_verify(case):
        typer.echo("Verification passed.")
    else:
        sys.exit(1)


@app.command()
def build(case: Path = typer.Option(..., help="Case directory")):
    """Build the database from evidence."""
    from .build import build as do_build
    do_build(case)


@app.command()
def skew(
    case: Path = typer.Option(..., help="Case directory"),
    reference: str | None = typer.Option(None, help="Reference host name"),
    offset: list[str] | None = typer.Option(
        None, "--offset", help="Manual offset: host=seconds (repeatable, e.g. --offset db01=-420)"
    ),
):
    """Estimate or manually set clock skew."""
    from .skew import skew as do_skew
    do_skew(case, reference, offset)
