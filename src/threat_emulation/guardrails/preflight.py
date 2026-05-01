"""Preflight pipeline.

Layered on top of the executor's lightweight pre-flight, this checker
evaluates a candidate run against:

* the loaded :class:`~threat_emulation.guardrails.policy.Policy` (scope
  ceilings, allowed backends, allowlist requirement, egress rules),
* the 2-person-integrity gate
  (:class:`~threat_emulation.auth.TwoPersonIntegrity`),
* the bound :class:`~threat_emulation.schemas.ScopeOfEngagement`'s validity
  window.

Returns a :class:`PreflightReport` with structured violations so audit
events can quote the exact rule that failed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from threat_emulation.auth.twopi import ApprovalToken, TwoPersonIntegrity
from threat_emulation.guardrails.policy import Policy
from threat_emulation.schemas import (
    Campaign,
    DestructivenessTier,
    Scope,
    ScopeOfEngagement,
)

_TIER_RANK: dict[DestructivenessTier, int] = {
    DestructivenessTier.OBSERVATIONAL: 0,
    DestructivenessTier.INTRUSIVE: 1,
    DestructivenessTier.DESTRUCTIVE: 2,
}


@dataclass(frozen=True)
class PreflightViolation:
    """A single structured violation returned from the pipeline."""

    rule: str
    detail: str


@dataclass(frozen=True)
class PreflightReport:
    """Aggregate report from the preflight pipeline."""

    ok: bool
    violations: tuple[PreflightViolation, ...] = field(default_factory=tuple)
    distinct_approvers: tuple[str, ...] = field(default_factory=tuple)


def hash_scope(scope: Scope) -> str:
    """Stable SHA-256 of a Scope's canonical JSON."""
    encoded = json.dumps(scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def hash_campaign(campaign: Campaign) -> str:
    """Stable SHA-256 of a Campaign's canonical JSON."""
    encoded = json.dumps(campaign.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class PreflightChecker:
    """Evaluate policy + 2PI + SoE for a candidate run."""

    def __init__(
        self,
        *,
        policy: Policy,
        two_person_integrity: TwoPersonIntegrity,
    ) -> None:
        self._policy = policy
        self._twopi = two_person_integrity

    def check(
        self,
        *,
        campaign: Campaign,
        scope: Scope,
        scope_of_engagement: ScopeOfEngagement,
        approvals: tuple[ApprovalToken, ...],
        now: datetime | None = None,
    ) -> PreflightReport:
        moment = now or datetime.now(UTC)
        violations: list[PreflightViolation] = []

        # ---- Scope-of-engagement window ----
        if not scope_of_engagement.is_active(moment):
            violations.append(
                PreflightViolation(
                    rule="soe.window",
                    detail=(
                        f"scope-of-engagement {scope_of_engagement.id} is not active "
                        f"at {moment.isoformat()}"
                    ),
                )
            )

        # ---- Policy: scope constraints ----
        constraints = self._policy.scope_constraints
        if _TIER_RANK[scope.max_destructiveness] > _TIER_RANK[constraints.max_destructiveness]:
            violations.append(
                PreflightViolation(
                    rule="policy.scope.max_destructiveness",
                    detail=(
                        f"scope.max_destructiveness={scope.max_destructiveness.value} "
                        f"exceeds policy ceiling "
                        f"{constraints.max_destructiveness.value}"
                    ),
                )
            )

        for step in campaign.steps:
            if step.backend not in constraints.allowed_backends:
                violations.append(
                    PreflightViolation(
                        rule="policy.scope.allowed_backends",
                        detail=(
                            f"step {step.order} uses backend {step.backend.value} "
                            "which is not in policy.allowed_backends"
                        ),
                    )
                )

        if constraints.require_test_allowlist and not scope.test_allowlist:
            violations.append(
                PreflightViolation(
                    rule="policy.scope.require_test_allowlist",
                    detail="policy requires a non-empty scope.test_allowlist",
                )
            )

        # ---- Policy: egress ----
        egress = self._policy.egress
        if egress.default_deny and scope.egress_allowed and egress.require_c2_sink:
            # The executor enforces the sink at runtime; preflight only
            # records the requirement (informational at this layer).
            violations.append(
                PreflightViolation(
                    rule="policy.egress.require_c2_sink",
                    detail=("scope grants egress; policy requires a C2 sink at runtime"),
                )
            )

        # ---- 2-person integrity ----
        tier = campaign.max_destructiveness
        decision = self._twopi.evaluate(
            tier=tier,
            campaign_hash=hash_campaign(campaign),
            scope_hash=hash_scope(scope),
            approvals=approvals,
        )
        if not decision.granted:
            violations.append(
                PreflightViolation(
                    rule="auth.twopi",
                    detail=decision.reason,
                )
            )

        return PreflightReport(
            ok=not violations,
            violations=tuple(violations),
            distinct_approvers=decision.distinct_approvers,
        )
