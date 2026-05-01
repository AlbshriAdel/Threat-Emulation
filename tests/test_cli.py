"""CLI smoke tests."""

from __future__ import annotations

from typer.testing import CliRunner

from threat_emulation.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "threat-emulation" in result.stdout


def test_cli_run_smoke_dry_run_succeeds() -> None:
    result = runner.invoke(app, ["run", "--campaign", "smoke", "--dry-run"])
    assert result.exit_code == 0, result.stdout
    assert "Campaign result" in result.stdout
    # Each of the 5 steps should appear in the output.
    for technique in (
        "T1059.001",
        "T1547.001",
        "T1003.001",
        "T1055",
        "T1071.001",
    ):
        assert technique in result.stdout
    assert "verified" in result.stdout
    assert "success" in result.stdout


def test_cli_run_live_is_blocked() -> None:
    result = runner.invoke(app, ["run", "--campaign", "smoke", "--execute"])
    assert result.exit_code == 2
    assert "Live execution is not enabled" in result.stdout


def test_cli_run_unknown_campaign_rejected() -> None:
    result = runner.invoke(app, ["run", "--campaign", "bogus", "--dry-run"])
    assert result.exit_code == 2
    assert "Unknown campaign" in result.stdout
