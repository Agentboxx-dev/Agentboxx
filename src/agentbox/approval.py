"""Human-in-the-loop (HITL) approval workflow for high-stakes agent actions (Issue #96)."""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Protocol, runtime_checkable



class UnattendedApprovalError(RuntimeError):
    """Raised when an approval is required in a non-interactive environment with on_unattended='fail'."""


@dataclass(frozen=True)
class ApprovalRequest:
    """Details of a command requiring human operator authorization."""

    command: str
    command_fingerprint: str
    rule: str
    reason: str
    step_index: int
    requested_at: float = field(default_factory=time.time)
    timeout_s: float | None = None
    thought: str = ""
    tool: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "step_index": self.step_index,
            "command": self.command,
            "command_fingerprint": self.command_fingerprint,
            "rule": self.rule,
            "reason": self.reason,
            "requested_at": self.requested_at,
        }
        if self.timeout_s is not None:
            data["timeout_s"] = self.timeout_s
        if self.thought:
            data["thought"] = self.thought
        if self.tool is not None:
            data["tool"] = self.tool
        if self.metadata:
            data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class ApprovalDecision:
    """The authorization decision recorded in the audit trail."""

    approved: bool
    approver: str = "operator"
    rationale: str = ""
    decision_at: float = field(default_factory=time.time)
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "approver": self.approver,
            "rationale": self.rationale,
            "decision_at": self.decision_at,
            "timed_out": self.timed_out,
        }


@runtime_checkable
class ApprovalHandler(Protocol):
    """Protocol for approval interceptor handlers."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """Evaluate an approval request and return the decision."""
        ...


class InteractiveApprover:
    """Interactive CLI terminal prompt for human operator confirmation.

    Args:
        approver_id: Identity tag for the operator (defaults to username or 'cli:operator').
        on_unattended: Fallback behavior when terminal is non-interactive ('deny' or 'fail').
        timeout_s: Optional timeout in seconds to wait for operator response.
        prompt_fn: Optional custom prompt callable for testing (signature: prompt_str -> user_str).
        isatty_fn: Optional custom isatty callable for testing (signature: () -> bool).
    """

    def __init__(
        self,
        approver_id: str | None = None,
        on_unattended: Literal["deny", "fail"] = "deny",
        timeout_s: float | None = None,
        prompt_fn: Callable[[str], str] | None = None,
        isatty_fn: Callable[[], bool] | None = None,
    ) -> None:
        if on_unattended not in ("deny", "fail"):
            raise ValueError(f"on_unattended must be 'deny' or 'fail', got {on_unattended!r}")
        self.approver_id = (
            approver_id
            or os.environ.get("USER")
            or os.environ.get("USERNAME")
            or "cli:operator"
        )
        self.on_unattended: Literal["deny", "fail"] = on_unattended
        self.timeout_s = timeout_s
        self._prompt_fn = prompt_fn
        self._isatty_fn = isatty_fn

    def is_interactive(self) -> bool:
        """Return True if terminal is interactive."""
        if self._isatty_fn is not None:
            return self._isatty_fn()
        return sys.stdin.isatty() and sys.stdout.isatty()

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """Prompt operator for decision or apply unattended fallback."""
        if not self.is_interactive():
            if self.on_unattended == "fail":
                raise UnattendedApprovalError(
                    f"Approval required for command '{request.command}' ({request.rule}), "
                    "but environment is non-interactive (on_unattended='fail')."
                )
            return ApprovalDecision(
                approved=False,
                approver="unattended",
                rationale="Non-interactive terminal without human operator (unattended fallback)",
                timed_out=False,
            )

        prompt_text = (
            f"\n[agentbox] APPROVAL REQUIRED\n"
            f"  Command: {request.command}\n"
            f"  Rule:    {request.rule} ({request.reason})\n"
            f"  Step:    {request.step_index}\n"
            f"Authorize execution? [y/N]: "
        )

        timed_out = False
        raw_ans = ""

        if self._prompt_fn is not None:
            try:
                raw_ans = self._prompt_fn(prompt_text)
            except Exception as e:
                return ApprovalDecision(
                    approved=False,
                    approver=self.approver_id,
                    rationale=f"Prompt error: {e}",
                )
        else:
            try:
                if self.timeout_s is not None and sys.platform != "win32":
                    import select
                    sys.stdout.write(prompt_text)
                    sys.stdout.flush()
                    rlist, _, _ = select.select([sys.stdin], [], [], self.timeout_s)
                    if not rlist:
                        timed_out = True
                        print("\n[agentbox] Timed out waiting for operator approval.")
                    else:
                        raw_ans = sys.stdin.readline().strip()
                else:
                    raw_ans = input(prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                return ApprovalDecision(
                    approved=False,
                    approver=self.approver_id,
                    rationale="Operator aborted prompt (EOF/Ctrl+C)",
                )

        if timed_out:
            return ApprovalDecision(
                approved=False,
                approver=self.approver_id,
                rationale=f"Approval request timed out after {self.timeout_s}s",
                timed_out=True,
            )

        ans = raw_ans.strip().lower()
        if ans in ("y", "yes"):
            return ApprovalDecision(
                approved=True,
                approver=self.approver_id,
                rationale="Approved by operator in terminal",
            )

        return ApprovalDecision(
            approved=False,
            approver=self.approver_id,
            rationale=f"Denied by operator in terminal ({raw_ans or 'default N'})",
        )


class CallbackApprover:
    """Programmatic callback approver for automated agents and bots."""

    def __init__(
        self,
        callback: Callable[[ApprovalRequest], bool | ApprovalDecision | tuple[bool, str]],
        approver_id: str = "callback",
    ) -> None:
        self.callback = callback
        self.approver_id = approver_id

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        try:
            res = self.callback(request)
        except Exception as e:
            return ApprovalDecision(
                approved=False,
                approver=self.approver_id,
                rationale=f"Approval callback raised exception: {e}",
            )

        if isinstance(res, ApprovalDecision):
            return res
        if isinstance(res, tuple) and len(res) == 2:
            return ApprovalDecision(
                approved=bool(res[0]),
                approver=self.approver_id,
                rationale=str(res[1]),
            )
        if isinstance(res, bool):
            return ApprovalDecision(
                approved=res,
                approver=self.approver_id,
                rationale="Approved by callback" if res else "Denied by callback",
            )
        return ApprovalDecision(
            approved=False,
            approver=self.approver_id,
            rationale=f"Invalid callback return type: {type(res).__name__}",
        )


class StaticApprover:
    """Deterministic approver with pre-configured static decision."""

    def __init__(
        self,
        approved: bool,
        approver: str = "static",
        rationale: str = "",
    ) -> None:
        self.approved = approved
        self.approver = approver
        self.rationale = rationale or ("Static allow" if approved else "Static deny")

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            approved=self.approved,
            approver=self.approver,
            rationale=self.rationale,
        )
