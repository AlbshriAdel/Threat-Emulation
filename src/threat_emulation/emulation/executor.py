"""Campaign executor: orchestrates provisioning, dispatch, teardown, verification.

Lifecycle for a single run:

1. Pre-flight: every campaign step's ``test_id`` must be in the scope
   allowlist; ``destructiveness`` must not exceed scope.max_destructiveness.
   Both 2-person-integrity for destructive steps (Phase 4) and the kill-switch
   are externally enforced by the API layer; this executor expects to be
   invoked only after those gates have cleared.
2. Provision an ephemeral lab via the injected
   :class:`~threat_emulation.lab.LabProvisioner`.
3. For each campaign step, look up the matching
   :class:`~threat_emulation.emulation.EmulationAdapter` and dispatch one
   :class:`ExecutionRequest` per target. Per CLAUDE.md hard rule 3, egress
   is denied unless the scope explicitly allows it - the executor refuses
   to start with ``egress_allowed=True`` when the C2 sink is missing.
4. Tear the lab down via :class:`~threat_emulation.lab.TeardownVerifier`.
   An unverified teardown fails the run.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from threat_emulation.c2sim import EgressSink
from threat_emulation.emulation.adapter import (
    EmulationAdapter,
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from threat_emulation.lab import (
    LabHandle,
    LabProvisioner,
    ProvisioningError,
    TeardownReport,
    TeardownVerifier,
)
from threat_emulation.schemas import (
    Campaign,
    DestructivenessTier,
    EmulationBackend,
    Scope,
)


class ExecutorError(RuntimeError):
    """Raised when the executor refuses to start (scope violation, missing dep)."""


_TIER_RANK: dict[DestructivenessTier, int] = {
    DestructivenessTier.OBSERVATIONAL: 0,
    DestructivenessTier.INTRUSIVE: 1,
    DestructivenessTier.DESTRUCTIVE: 2,
}


@dataclass(frozen=True)
class ExecutorOptions:
    """Knobs for a single run.

    ``dry_run`` defaults to True so the safe path is the default. Live
    execution requires ``dry_run=False`` AND scope-level approval routed
    through the Phase 4 RBAC layer.
    """

    dry_run: bool = True
    one_target: bool = True
    """If True, dispatch each step to the first target only (typical for
    smoke / dry-run). If False, dispatch to every target in the lab handle."""


@dataclass(frozen=True)
class CampaignResult:
    """The aggregate result of a single campaign run."""

    run_id: UUID
    campaign_id: UUID
    started_at: datetime
    finished_at: datetime
    handle: LabHandle | None
    results: tuple[ExecutionResult, ...] = field(default_factory=tuple)
    teardown: TeardownReport | None = None
    error: str | None = None

    @property
    def successful(self) -> bool:
        if self.error is not None:
            return False
        if self.teardown is None or not self.teardown.successful:
            return False
        return all(
            r.outcome in {ExecutionOutcome.SUCCESS, ExecutionOutcome.SKIPPED} for r in self.results
        )


class Executor:
    """Run a campaign end-to-end inside a provisioned lab."""

    def __init__(
        self,
        *,
        provisioner: LabProvisioner,
        adapters: Iterable[EmulationAdapter],
        teardown: TeardownVerifier | None = None,
        c2_sink: EgressSink | None = None,
    ) -> None:
        adapter_map: dict[EmulationBackend, EmulationAdapter] = {}
        for adapter in adapters:
            if adapter.backend in adapter_map:
                raise ExecutorError(f"Duplicate adapter for backend {adapter.backend.value}")
            adapter_map[adapter.backend] = adapter
        if not adapter_map:
            raise ExecutorError("Executor requires at least one EmulationAdapter")
        self._adapters = adapter_map
        self._provisioner = provisioner
        self._teardown = teardown or TeardownVerifier()
        self._c2_sink = c2_sink

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def run_campaign(
        self,
        *,
        campaign: Campaign,
        scope: Scope,
        options: ExecutorOptions | None = None,
        run_id: UUID | None = None,
    ) -> CampaignResult:
        opts = options or ExecutorOptions()
        rid = run_id or uuid4()
        started = datetime.now(UTC)

        try:
            self._preflight(campaign=campaign, scope=scope, options=opts)
        except ExecutorError as exc:
            return CampaignResult(
                run_id=rid,
                campaign_id=campaign.id,
                started_at=started,
                finished_at=datetime.now(UTC),
                handle=None,
                error=str(exc),
            )

        try:
            handle = self._provisioner.provision(run_id=rid, scope=scope)
        except ProvisioningError as exc:
            return CampaignResult(
                run_id=rid,
                campaign_id=campaign.id,
                started_at=started,
                finished_at=datetime.now(UTC),
                handle=None,
                error=f"provisioning failed: {exc}",
            )

        results = self._dispatch_steps(handle=handle, campaign=campaign, options=opts)
        teardown = self._teardown.verify(provisioner=self._provisioner, handle=handle)

        return CampaignResult(
            run_id=rid,
            campaign_id=campaign.id,
            started_at=started,
            finished_at=datetime.now(UTC),
            handle=handle,
            results=tuple(results),
            teardown=teardown,
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _preflight(
        self,
        *,
        campaign: Campaign,
        scope: Scope,
        options: ExecutorOptions,
    ) -> None:
        # Tier ceiling.
        max_rank = _TIER_RANK[scope.max_destructiveness]
        for step in campaign.steps:
            if _TIER_RANK[step.destructiveness] > max_rank:
                raise ExecutorError(
                    f"Step {step.technique_id} is {step.destructiveness.value} but "
                    f"scope ceiling is {scope.max_destructiveness.value}"
                )
        # Allowlist.
        if scope.test_allowlist:
            for step in campaign.steps:
                if step.test_id not in scope.test_allowlist:
                    raise ExecutorError(
                        f"test_id {step.test_id!r} (technique {step.technique_id}) "
                        "is not in the scope allowlist"
                    )
        # Adapter coverage.
        for step in campaign.steps:
            if step.backend not in self._adapters:
                raise ExecutorError(f"No adapter registered for backend {step.backend.value}")
        # Egress containment.
        if scope.egress_allowed and self._c2_sink is None:
            raise ExecutorError(
                "Scope grants egress but no C2 sink is configured. "
                "Refusing to start: hard rule 'no real-internet egress from the lab'."
            )
        # Live execution requires explicit opt-in.
        if not options.dry_run and scope.max_destructiveness == DestructivenessTier.DESTRUCTIVE:
            # Phase 4 RBAC will gate this further; we leave it to the caller.
            return None

    def _dispatch_steps(
        self,
        *,
        handle: LabHandle,
        campaign: Campaign,
        options: ExecutorOptions,
    ) -> list[ExecutionResult]:
        targets = handle.targets if not options.one_target else handle.targets[:1]
        results: list[ExecutionResult] = []
        for step in campaign.steps:
            adapter = self._adapters[step.backend]
            for target in targets:
                request = ExecutionRequest(
                    run_id=handle.run_id,
                    backend=step.backend,
                    test_id=step.test_id,
                    technique_id=step.technique_id,
                    target=target,
                    destructiveness=step.destructiveness,
                    dry_run=options.dry_run,
                )
                results.append(adapter.execute(request))
        return results
