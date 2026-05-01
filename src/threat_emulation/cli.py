"""Top-level Typer CLI entrypoint.

Most subcommands are stubs in Phase 0; they will be wired up in later phases.
"""

from __future__ import annotations

import typer
from rich.console import Console

from threat_emulation import __version__

app = typer.Typer(
    name="threat-emu",
    help="Automated Agentic RAG Threat Emulation Framework.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the installed version."""
    console.print(f"threat-emulation {__version__}")


@app.command()
def run(
    campaign: str = typer.Option(..., "--campaign", help="Campaign id to run."),
    dry_run: bool = typer.Option(True, "--dry-run/--execute"),
) -> None:
    """Run a campaign (stub - implemented in Phase 3)."""
    console.print(f"[yellow]not yet implemented[/yellow] (campaign={campaign}, dry_run={dry_run})")
    raise typer.Exit(code=2)


if __name__ == "__main__":  # pragma: no cover
    app()
