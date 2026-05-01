"""Tests for the c2sim egress containment layer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_emulation.c2sim import (
    EgressAttempt,
    InetSimSink,
    InMemoryEgressSink,
    render_inetsim_config,
)


def _attempt(dest: str = "evil.example") -> EgressAttempt:
    return EgressAttempt(
        timestamp=datetime.now(UTC),
        source="lab-host-01",
        destination=dest,
        protocol="https",
        payload_excerpt="GET / HTTP/1.1",
    )


def test_in_memory_sink_records_attempts_in_order() -> None:
    sink = InMemoryEgressSink()
    a = _attempt("a.example")
    b = _attempt("b.example")
    sink.record(a)
    sink.record(b)
    assert sink.attempts() == (a, b)
    assert len(sink) == 2


def test_inetsim_sink_records_and_renders() -> None:
    sink = InetSimSink(bind_address="10.42.0.10", service_address="10.42.0.10")
    sink.record(_attempt())
    config = sink.render_config()
    assert "service_bind_address 10.42.0.10" in config
    assert "service_run" in config
    assert sink.attempts()


def test_inetsim_config_is_deterministic_for_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pin "now" so the timestamp header is stable.
    fixed = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object | None = None) -> _FixedDatetime:
            return _FixedDatetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)

    monkeypatch.setattr("threat_emulation.c2sim.inetsim.datetime", _FixedDatetime)
    a = render_inetsim_config(
        bind_address="10.42.0.10",
        service_address="10.42.0.10",
        services=("dns", "http"),
    )
    b = render_inetsim_config(
        bind_address="10.42.0.10",
        service_address="10.42.0.10",
        services=("dns", "http"),
    )
    assert a == b
    assert "service_run dns http" in a
    assert "10.42.0.10" in a
    assert fixed.isoformat(timespec="seconds") in a


def test_inetsim_config_rejects_empty_inputs() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        render_inetsim_config(bind_address="", service_address="x")
    with pytest.raises(ValueError, match="non-empty"):
        render_inetsim_config(bind_address="x", service_address="")
    with pytest.raises(ValueError, match="at least one service"):
        render_inetsim_config(
            bind_address="10.42.0.10",
            service_address="10.42.0.10",
            services=(),
        )


def test_inetsim_sink_from_observations() -> None:
    a = _attempt("a")
    b = _attempt("b")
    sink = InetSimSink.from_observations(
        bind_address="10.42.0.10",
        service_address="10.42.0.10",
        observed=(a, b),
    )
    assert sink.attempts() == (a, b)
