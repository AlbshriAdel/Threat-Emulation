"""Dual-channel kill-switch.

Per CLAUDE.md hard rule 7 the kill-switch is *both* an API endpoint and an
out-of-band signal-file watcher; either must SIGTERM the executor and
verify lab teardown within 5 seconds. This module provides:

* :class:`KillSwitch` - the in-process trigger / state. Threads check
  :meth:`is_killed` between operations.
* :class:`SignalFileWatcher` - polls a path on a background thread and
  trips the switch when the file appears.

The actual SIGTERM + teardown choreography is the executor's
responsibility; the kill-switch surfaces the *signal* so independent code
paths (API handler, CLI, signal-file watcher) can all trip the same gate.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

DEFAULT_TEARDOWN_BUDGET_SECONDS = 5.0


class KillReason(StrEnum):
    API = "api"
    SIGNAL_FILE = "signal_file"
    OPERATOR = "operator"


@dataclass(frozen=True)
class KillSignal:
    """Recorded reason and timing of a kill."""

    reason: KillReason
    triggered_at: datetime
    detail: str = ""


class KillSwitch:
    """Thread-safe kill-switch with registered teardown handlers."""

    def __init__(self, *, teardown_budget_seconds: float = DEFAULT_TEARDOWN_BUDGET_SECONDS) -> None:
        if teardown_budget_seconds <= 0:
            raise ValueError("teardown_budget_seconds must be positive")
        self._budget = teardown_budget_seconds
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._signal: KillSignal | None = None
        self._handlers: list[Callable[[KillSignal], None]] = []

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #

    @property
    def teardown_budget_seconds(self) -> float:
        return self._budget

    def is_killed(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        """Block until the switch trips or timeout elapses."""
        return self._event.wait(timeout=timeout)

    def signal(self) -> KillSignal | None:
        with self._lock:
            return self._signal

    # ------------------------------------------------------------------ #
    # Trigger
    # ------------------------------------------------------------------ #

    def trip(self, reason: KillReason, *, detail: str = "") -> KillSignal:
        with self._lock:
            if self._signal is not None:
                return self._signal
            self._signal = KillSignal(
                reason=reason,
                triggered_at=datetime.now(UTC),
                detail=detail,
            )
            self._event.set()
            handlers = list(self._handlers)
        for handler in handlers:
            try:
                handler(self._signal)
            except Exception:  # noqa: S112 - best-effort handlers
                # Handlers must never crash the switch; the signal is set
                # regardless. Errors are intentionally swallowed - the
                # caller has no way to react to a failed teardown handler
                # other than checking residual resources via the verifier.
                continue
        return self._signal

    # ------------------------------------------------------------------ #
    # Handlers
    # ------------------------------------------------------------------ #

    def register(self, handler: Callable[[KillSignal], None]) -> None:
        """Register a teardown handler; runs once when the switch trips."""
        with self._lock:
            self._handlers.append(handler)

    def handlers(self) -> Iterable[Callable[[KillSignal], None]]:
        with self._lock:
            return tuple(self._handlers)


# --------------------------------------------------------------------------- #
# Signal-file watcher
# --------------------------------------------------------------------------- #


class SignalFileWatcher:
    """Background thread that trips a :class:`KillSwitch` when a file appears.

    Mounts the lowest-cost out-of-band channel: a privileged operator can
    create the path even if the API process is wedged.
    """

    def __init__(
        self,
        *,
        switch: KillSwitch,
        path: Path | str,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        self._switch = switch
        self._path = Path(path)
        self._interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="killswitch-signal-watcher", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float | None = 1.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._thread = None

    def check_once(self) -> bool:
        """Synchronous one-shot poll. Returns True if the switch was tripped."""
        if self._path.exists():
            self._switch.trip(KillReason.SIGNAL_FILE, detail=f"observed {self._path}")
            return True
        return False

    def _run(self) -> None:
        while not self._stop.is_set():
            if self.check_once():
                return
            self._stop.wait(self._interval)
