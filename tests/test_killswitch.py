"""Tests for the dual-channel kill-switch."""

from __future__ import annotations

import time
from pathlib import Path
from threading import Thread

import pytest

from threat_emulation.guardrails.killswitch import (
    KillReason,
    KillSwitch,
    SignalFileWatcher,
)


def test_killswitch_starts_disarmed() -> None:
    ks = KillSwitch()
    assert ks.is_killed() is False
    assert ks.signal() is None


def test_killswitch_trip_is_idempotent() -> None:
    ks = KillSwitch()
    a = ks.trip(KillReason.API, detail="first")
    b = ks.trip(KillReason.OPERATOR, detail="second")
    # Second call returns the *first* signal.
    assert a == b
    assert a.reason == KillReason.API
    assert ks.is_killed() is True


def test_killswitch_runs_registered_handlers_on_trip() -> None:
    ks = KillSwitch()
    fired: list[str] = []
    ks.register(lambda sig: fired.append(sig.reason.value))
    ks.trip(KillReason.API)
    assert fired == [KillReason.API.value]


def test_killswitch_handler_exception_does_not_block_trip() -> None:
    ks = KillSwitch()
    ks.register(lambda sig: (_ for _ in ()).throw(RuntimeError("boom")))
    fired: list[str] = []
    ks.register(lambda sig: fired.append("ok"))
    ks.trip(KillReason.API)
    assert ks.is_killed() is True
    assert "ok" in fired


def test_killswitch_wait_returns_true_on_trip() -> None:
    ks = KillSwitch()

    def _trip() -> None:
        time.sleep(0.05)
        ks.trip(KillReason.OPERATOR)

    Thread(target=_trip, daemon=True).start()
    assert ks.wait(timeout=1.0) is True


def test_killswitch_wait_times_out_when_not_tripped() -> None:
    ks = KillSwitch()
    assert ks.wait(timeout=0.05) is False


def test_killswitch_rejects_non_positive_budget() -> None:
    with pytest.raises(ValueError):
        KillSwitch(teardown_budget_seconds=0)


# --------------------------------------------------------------------------- #
# SignalFileWatcher
# --------------------------------------------------------------------------- #


def test_signal_file_watcher_check_once_trips_when_file_exists(tmp_path: Path) -> None:
    ks = KillSwitch()
    path = tmp_path / "kill"
    watcher = SignalFileWatcher(switch=ks, path=path)
    assert watcher.check_once() is False
    path.write_text("kill now")
    assert watcher.check_once() is True
    assert ks.is_killed()
    sig = ks.signal()
    assert sig is not None
    assert sig.reason == KillReason.SIGNAL_FILE
    assert str(path) in sig.detail


def test_signal_file_watcher_background_thread_trips_within_budget(
    tmp_path: Path,
) -> None:
    ks = KillSwitch()
    path = tmp_path / "kill"
    watcher = SignalFileWatcher(switch=ks, path=path, poll_interval_seconds=0.05)
    watcher.start()
    try:
        time.sleep(0.05)
        assert ks.is_killed() is False
        path.write_text("kill now")
        # The 5s teardown budget gives us plenty of slack here.
        triggered = ks.wait(timeout=2.0)
        assert triggered is True
        assert ks.signal() is not None
    finally:
        watcher.stop(timeout=1.0)


def test_signal_file_watcher_rejects_invalid_interval() -> None:
    ks = KillSwitch()
    with pytest.raises(ValueError):
        SignalFileWatcher(switch=ks, path="/tmp/kill", poll_interval_seconds=0)
