"""Top-level Typer CLI entrypoint.

Phase 3 wires the ``run`` subcommand to actually orchestrate a dry-run via
the in-memory provisioner. Live execution remains gated behind Phase 4
RBAC and is intentionally not exposed by this CLI yet.
"""

from __future__ import annotations

from ipaddress import IPv4Network
from uuid import uuid4

import typer
from rich.console import Console
from rich.table import Table

from threat_emulation import __version__
from threat_emulation.emulation import (
    AtomicRedTeamAdapter,
    CalderaAdapter,
    Executor,
    ExecutorOptions,
    StratusRedTeamAdapter,
)
from threat_emulation.lab import InMemoryProvisioner
from threat_emulation.schemas import (
    Campaign,
    CampaignStep,
    DestructivenessTier,
    EmulationBackend,
    Scope,
)

app = typer.Typer(
    name="threat-emu",
    help="Automated Agentic RAG Threat Emulation Framework.",
    no_args_is_help=True,
)


def _console() -> Console:
    """Build a Console at call time so test harnesses that swap stdout work."""
    return Console()


@app.command()
def version() -> None:
    """Print the installed version."""
    _console().print(f"threat-emulation {__version__}")


@app.command()
def run(
    campaign: str = typer.Option(
        "smoke", "--campaign", help="Campaign id to run (built-in: 'smoke')."
    ),
    dry_run: bool = typer.Option(True, "--dry-run/--execute"),
) -> None:
    """Run a campaign end-to-end (Phase 3: in-memory lab + dry-run only).

    The ``smoke`` campaign is a hard-coded 5-step kill-chain (T1059.001 ->
    T1547.001 -> T1071.001) used to verify the executor end-to-end without
    any external infrastructure. Real campaigns load from a registry, which
    lands in Phase 5.
    """
    cons = _console()
    if not dry_run:
        cons.print(
            "[red]Live execution is not enabled in Phase 3.[/red] "
            "Use --dry-run; live execution lands behind Phase 4 RBAC."
        )
        raise typer.Exit(code=2)

    if campaign != "smoke":
        cons.print(
            f"[yellow]Unknown campaign id {campaign!r}; only 'smoke' is wired in Phase 3.[/yellow]"
        )
        raise typer.Exit(code=2)

    scope, smoke_campaign = _build_smoke_campaign()
    executor = Executor(
        provisioner=InMemoryProvisioner(),
        adapters=(
            AtomicRedTeamAdapter(),
            StratusRedTeamAdapter(),
            CalderaAdapter(),
        ),
    )
    result = executor.run_campaign(
        campaign=smoke_campaign,
        scope=scope,
        options=ExecutorOptions(dry_run=True),
        run_id=uuid4(),
    )

    table = Table(
        title=f"Campaign result (run_id={result.run_id})",
        show_lines=False,
    )
    table.add_column("step")
    table.add_column("technique")
    table.add_column("backend")
    table.add_column("outcome")
    table.add_column("duration (s)", justify="right")
    for i, r in enumerate(result.results):
        table.add_row(
            str(i),
            r.technique_id,
            r.backend.value,
            r.outcome.value,
            f"{r.duration_seconds:.4f}",
        )
    cons.print(table)

    teardown = result.teardown
    if teardown is not None:
        status = "[green]verified[/green]" if teardown.successful else "[red]FAILED[/red]"
        cons.print(
            f"Teardown: {status} in {teardown.duration_seconds:.4f}s "
            f"(residual={len(teardown.residual_resources)})"
        )

    overall = "[green]success[/green]" if result.successful else "[red]failure[/red]"
    cons.print(f"Overall: {overall}")
    if not result.successful:
        raise typer.Exit(code=1)


def _build_smoke_campaign() -> tuple[Scope, Campaign]:
    scope = Scope(
        targets_cidr=(IPv4Network("10.42.0.0/24"),),
        test_allowlist=frozenset(
            {
                "atomic-T1059.001",
                "atomic-T1547.001",
                "atomic-T1071.001",
                "atomic-T1003.001",
                "atomic-T1055",
            }
        ),
        max_destructiveness=DestructivenessTier.OBSERVATIONAL,
    )
    steps = (
        CampaignStep(
            order=0,
            technique_id="T1059.001",
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id="atomic-T1059.001",
        ),
        CampaignStep(
            order=1,
            technique_id="T1547.001",
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id="atomic-T1547.001",
        ),
        CampaignStep(
            order=2,
            technique_id="T1003.001",
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id="atomic-T1003.001",
        ),
        CampaignStep(
            order=3,
            technique_id="T1055",
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id="atomic-T1055",
        ),
        CampaignStep(
            order=4,
            technique_id="T1071.001",
            backend=EmulationBackend.ATOMIC_RED_TEAM,
            test_id="atomic-T1071.001",
        ),
    )
    campaign = Campaign(name="smoke", scope_id=uuid4(), steps=steps)
    return scope, campaign


if __name__ == "__main__":  # pragma: no cover
    app()
