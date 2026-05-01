"""``request_approval`` tool: signal the HITL gate to halt for approval.

This tool does **not** grant approval - it only sets a flag on the blackboard
so the run lifecycle (Phase 4 RBAC + 2PI) can pick up the campaign and route
it to a human approver. The audit log records the request itself.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threat_emulation.agent.state import BlackboardState
from threat_emulation.agent.tools.base import ToolBase, ToolDependencies, ToolResult


class RequestApprovalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2048)


class RequestApprovalOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_requested: bool
    reason: str


class RequestApprovalTool(ToolBase[RequestApprovalInput, RequestApprovalOutput]):
    name = "request_approval"
    description = (
        "Mark the proposed Campaign as awaiting human approval. Does NOT "
        "grant approval; the lifecycle layer routes it to a 2-person-integrity "
        "gate when destructive."
    )
    InputModel = RequestApprovalInput
    OutputModel = RequestApprovalOutput

    def execute(
        self,
        state: BlackboardState,
        deps: ToolDependencies,
        inputs: RequestApprovalInput,
    ) -> ToolResult[RequestApprovalOutput]:
        del deps
        new_state = state.with_updates(
            approval_requested=True,
            approval_reason=inputs.reason,
        )
        output = RequestApprovalOutput(
            approval_requested=True,
            reason=inputs.reason,
        )
        return ToolResult(state=new_state, output=output)
