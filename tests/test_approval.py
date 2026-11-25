"""Tests for Human-in-the-loop (HITL) approval workflow (Issue #96)."""
import json
from pathlib import Path

import jsonschema
import pytest

from agentbox import (
    ApprovalDecision,
    ApprovalRequest,
    CallbackApprover,
    CommandRule,
    InteractiveApprover,
    PolicyAction,
    Recorder,
    SecurityPolicy,
    StaticApprover,
    UnattendedApprovalError,
)
from agentbox.signer import load_or_create_key, verify_log

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs" / "schema.json").read_text(encoding="utf-8"))
APPROVAL_RULE = CommandRule(
    PolicyAction.REQUIRE_APPROVAL,
    prefix="touch",
    name="ask-touch",
    reason="filesystem write needs confirmation",
)


def _rec(tmp_path, **kw):
    return Recorder(
        "appr",
        workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "runs"),
        key_path=tmp_path / "key",
        **kw,
    )


def _events(rec):
    return [
        json.loads(line)["event"]
        for line in rec.log_path.read_text(encoding="utf-8").splitlines()
    ]


def _types(rec):
    return [e["event_type"] for e in _events(rec)]


def test_approved_command_pauses_and_records_requested_and_decision(tmp_path):
    """An approved command records approval.requested and approval.decision in the ledger."""
    order = []

    def handle_request(req: ApprovalRequest) -> ApprovalDecision:
        order.append("prompt_invoked")
        assert req.command == "touch deploy.txt"
        assert req.rule == "ask-touch"
        assert req.step_index == 1
        return ApprovalDecision(
            approved=True,
            approver="alice@corp.com",
            rationale="Approved production deployment",
        )

    approver = CallbackApprover(handle_request)
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch deploy.txt")
    rec.close()

    assert order == ["prompt_invoked"]
    assert "blocked" not in out
    assert (tmp_path / "ws" / "deploy.txt").exists()

    types = _types(rec)
    assert types == [
        "session.start",
        "approval.requested",
        "approval.decision",
        "policy.approved",
        "step",
        "session.end",
    ]

    events = _events(rec)
    req_ev = events[1]["data"]
    assert req_ev["command"] == "touch deploy.txt"
    assert req_ev["rule"] == "ask-touch"
    assert req_ev["step_index"] == 1

    dec_ev = events[2]["data"]
    assert dec_ev["approved"] is True
    assert dec_ev["approver"] == "alice@corp.com"
    assert dec_ev["rationale"] == "Approved production deployment"

    problems, incomplete = verify_log(rec.log_path, load_or_create_key(tmp_path / "key"))
    assert not problems and not incomplete


def test_denied_command_records_events_and_blocks_execution(tmp_path):
    """A rejected approval records decision and blocks execution with exit code 126."""
    approver = StaticApprover(approved=False, approver="security_team", rationale="Dangerous action blocked")
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch blocked.txt")
    rec.close()

    assert out["blocked"] is True
    assert not (tmp_path / "ws" / "blocked.txt").exists()
    assert out["observation"]["exit_code"] == 126

    types = _types(rec)
    assert types == [
        "session.start",
        "approval.requested",
        "approval.decision",
        "policy.blocked",
        "session.end",
    ]

    events = _events(rec)
    dec_ev = events[2]["data"]
    assert dec_ev["approved"] is False
    assert dec_ev["approver"] == "security_team"
    assert dec_ev["rationale"] == "Dangerous action blocked"

    problems, _ = verify_log(rec.log_path, load_or_create_key(tmp_path / "key"))
    assert not problems


def test_interactive_approver_confirms_on_y(tmp_path):
    """InteractiveApprover approves when operator types 'y'."""
    prompt_called = []

    def mock_prompt(prompt_text):
        prompt_called.append(prompt_text)
        return "y"

    approver = InteractiveApprover(
        approver_id="test_admin",
        prompt_fn=mock_prompt,
        isatty_fn=lambda: True,
    )
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch verified.txt")
    rec.close()

    assert len(prompt_called) == 1
    assert "APPROVAL REQUIRED" in prompt_called[0]
    assert "blocked" not in out
    assert (tmp_path / "ws" / "verified.txt").exists()

    events = _events(rec)
    dec_ev = events[2]["data"]
    assert dec_ev["approved"] is True
    assert dec_ev["approver"] == "test_admin"


def test_interactive_approver_denies_on_n(tmp_path):
    """InteractiveApprover rejects when operator types 'n'."""
    approver = InteractiveApprover(
        approver_id="test_admin",
        prompt_fn=lambda p: "n",
        isatty_fn=lambda: True,
    )
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch denied.txt")
    rec.close()

    assert out["blocked"] is True
    assert not (tmp_path / "ws" / "denied.txt").exists()
    assert _events(rec)[2]["data"]["approved"] is False


def test_unattended_deny_fallback_in_non_interactive_ci(tmp_path):
    """In non-interactive CI/CD, on_unattended='deny' fails closed without hanging."""
    approver = InteractiveApprover(
        on_unattended="deny",
        isatty_fn=lambda: False,
    )
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch non_interactive.txt")
    rec.close()

    assert out["blocked"] is True
    assert not (tmp_path / "ws" / "non_interactive.txt").exists()

    dec_ev = _events(rec)[2]["data"]
    assert dec_ev["approved"] is False
    assert dec_ev["approver"] == "unattended"
    assert "unattended fallback" in dec_ev["rationale"].lower()


def test_unattended_fail_raises_exception_in_ci(tmp_path):
    """In non-interactive CI/CD, on_unattended='fail' raises UnattendedApprovalError immediately."""
    approver = InteractiveApprover(
        on_unattended="fail",
        isatty_fn=lambda: False,
    )
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    with pytest.raises(UnattendedApprovalError, match="non-interactive"):
        rec.run("touch should_raise.txt")

    rec.close()


def test_callback_approver_handles_exceptions_safely(tmp_path):
    """A crashed callback fails closed without crashing the recorder."""
    def broken_callback(req):
        raise RuntimeError("network timeout to ticketing service")

    approver = CallbackApprover(broken_callback)
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    out = rec.run("touch error.txt")
    rec.close()

    assert out["blocked"] is True
    dec_ev = _events(rec)[2]["data"]
    assert dec_ev["approved"] is False
    assert "network timeout" in dec_ev["rationale"]


def test_approval_events_validate_against_json_schema(tmp_path):
    """All approval events strictly conform to docs/schema.json."""
    approver = StaticApprover(approved=True, approver="auditor@sec.org", rationale="Passed review")
    policy = SecurityPolicy(rules=[APPROVAL_RULE])
    rec = _rec(tmp_path, policy=policy, approver=approver)

    rec.run("touch audited.txt")
    rec.close()

    records = [json.loads(line) for line in rec.log_path.read_text(encoding="utf-8").splitlines()]
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for r in records:
        validator.validate(r)

    # Check event structure
    req_record = next(r for r in records if r["event"]["event_type"] == "approval.requested")
    dec_record = next(r for r in records if r["event"]["event_type"] == "approval.decision")

    assert req_record["event"]["data"]["command"] == "touch audited.txt"
    assert dec_record["event"]["data"]["approved"] is True
    assert dec_record["event"]["data"]["approver"] == "auditor@sec.org"
