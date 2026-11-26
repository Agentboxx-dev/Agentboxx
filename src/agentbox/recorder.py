"""The main API. Wrap every action your agent takes in `recorder.run(...)`."""
import atexit
import hashlib
import os
import signal as _signal
import time
import warnings
from pathlib import Path
from typing import Any, Callable

from .contract import ContractVerdict, TaskContract
from .executor import error_signature, fingerprint, run_command
from .loop_detector import LoopConfig, LoopDetector
from .approval import ApprovalHandler, ApprovalRequest
from .policy import PolicyAction, SecurityPolicy
from .redact import Redactor, merge_counts
from .semantic_detector import SemanticDriftConfig, SemanticDriftDetector
from .signer import ChainWriter, load_or_create_key, load_ed25519_private_key
from .toolcall import MAX_PAYLOAD_BYTES, as_text, cap_payload, serialize, to_jsonable
from .workspace import workspace_hash


def _crash_kind(sbx: dict):
    if sbx.get("oom_events", 0) > 0 or sbx.get("oom_killed"):
        return "oom_kill"
    if sbx.get("running") is False:
        return "container_stopped"
    return None


def _make_stream_record(
    text: str,
    total_bytes: int | None = None,
    truncated: bool = False,
) -> dict:
    encoded = text.encode("utf-8")
    tb = len(encoded) if total_bytes is None else total_bytes

    return {
        "text": text,
        "total_chars": tb,
        "total_bytes": tb,
        "truncated": truncated,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


class Recorder:
    """Host-side session recorder.

    Every agent action passes through run() or record_step(); the results are
    hash-chained and HMAC-signed with a key that never enters the sandbox.
    """

    def __init__(
        self,
        session_id: str,
        workspace: str = "./workspace",
        log_dir: str = "./runs",
        key_path: str | Path | None = None,
        loop_cfg: LoopConfig | None = None,
        sandbox: Any | None = None,
        overwrite: bool = False,
        agent_id: str | None = None,
        ed25519_key_path: str | Path | None = None,
        contract: TaskContract | dict | None = None,
        goal: str | None = None,
        semantic_cfg: SemanticDriftConfig | None = None,
        embed_fn: Callable[[str], list[float]] | None = None,
        redact_patterns: list[tuple] | None = None,
        policy: SecurityPolicy | None = None,
        approver: ApprovalHandler | Callable | None = None,
        require_receipt: bool = False,
    ) -> None:
        """Initialize a new recording session.

        Args:
            session_id: Unique identifier for this session.
            workspace: Working directory mounted or inspected during runs.
            log_dir: Destination directory for the signed log and manifest.
            key_path: Optional path to symmetric HMAC signing key.
            loop_cfg: Optional configuration thresholds for loop detection.
            sandbox: Optional execution sandbox instance (e.g. DockerSandbox).
            overwrite: Whether to overwrite existing log file of same name.
            agent_id: Optional identifier tag for the executing agent.
            ed25519_key_path: Optional path to Ed25519 private key for receipts.
            contract: Optional TaskContract instance or dictionary defining constraints.
            goal: Optional objective string for semantic drift detection.
            semantic_cfg: Optional config for semantic drift and thought repetition.
            embed_fn: Optional embedding callable mapping strings to float vectors.
            redact_patterns: Optional list of (name, regex) or (name, regex, replacement)
                tuples for custom secret redaction on top of the built-in patterns.
            policy: Optional SecurityPolicy evaluated by run() before a command executes.
                Blocked commands are never executed. None (default) changes nothing.
            approver: Optional ApprovalHandler or callable for human-in-the-loop approvals.
            require_receipt: If True, raise RuntimeError when no Ed25519 private key is
                available instead of closing without a signed run receipt.
        """
        self.session_id, self.workspace, self.sandbox = (
            session_id,
            workspace,
            sandbox,
        )
        self.agent_id = agent_id
        self._redactor = Redactor(extra_patterns=redact_patterns)
        self.policy = policy
        self.approver = approver or (getattr(policy, "approver", None) if isinstance(getattr(policy, "approver", None), ApprovalHandler) else None)
        self.log_path = Path(log_dir) / f"{session_id}.ndjson"
        self.ed25519_key = load_ed25519_private_key(ed25519_key_path)
        self.require_receipt = bool(require_receipt)
        if self.require_receipt and self.ed25519_key is None:
            raise RuntimeError(
                "agentbox: require_receipt=True, but no Ed25519 private key was found. "
                "Run 'agentbox keygen' or pass ed25519_key_path."
            )

        self.writer = ChainWriter(
            self.log_path,
            load_or_create_key(key_path),
            overwrite=overwrite,
            ed25519_key=self.ed25519_key,
        )

        self.detector = LoopDetector(loop_cfg)
        self.step_index = 0
        self.closed = False
        self._register_exit_handlers()

        if isinstance(contract, dict):
            self.contract: TaskContract | None = TaskContract.from_dict(contract)
        elif isinstance(contract, TaskContract):
            self.contract = contract
        else:
            self.contract = None

        if goal is None and self.contract and getattr(self.contract, "description", None):
            goal = self.contract.description

        self.goal = goal
        self.semantic_detector = SemanticDriftDetector(
            goal=self.goal,
            cfg=semantic_cfg,
            embed_fn=embed_fn,
        )

        self.contract_verdict: ContractVerdict | None = None
        self.start_wall_clock = time.monotonic()
        self.cumulative_duration_ms = 0

        isolation = sandbox.describe() if sandbox else {"backend": "local"}
        start = {"session_id": session_id, "isolation": isolation}

        if agent_id:
            start["agent_id"] = agent_id

        if policy is not None:
            start["policy"] = policy.describe()

        if self.contract:
            if self.contract.test_files and not self.contract.test_hashes:
                self.contract.record_test_hashes(self.workspace)
            start["contract"] = self.contract.to_dict()

        self.writer.append("session.start", start)

    def set_goal(self, goal: str | None) -> None:
        """Set or update the goal for semantic drift detection."""
        self.goal = goal
        if self.semantic_detector:
            self.semantic_detector.set_goal(goal)

    def record_step(
        self,
        *,
        command: str,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        thought: str = "",
        tool: str | None = None,
        duration_ms: int = 0,
        timed_out: bool = False,
        output_limit_exceeded: bool = False,
        parent_step: int | None = None,
        usage: dict | None = None,
        workspace_hash_val: str | None = None,
    ) -> dict[str, Any]:
        """Record an already-executed action (e.g. from an agent framework callback).

        Args:
            command: Shell command string that was executed.
            stdout: Standard output produced by the command.
            stderr: Standard error produced by the command.
            exit_code: Process exit code.
            thought: Reasoning text or chain-of-thought preceding the action.
            tool: Optional identifier for tool or framework invoking the command.
            duration_ms: Execution duration in milliseconds.
            timed_out: Whether command timed out during execution.
            output_limit_exceeded: Whether output exceeded byte limits.
            parent_step: Optional parent step index in hierarchical runs.
            usage: Optional token or resource usage statistics dict.
            workspace_hash_val: Precomputed workspace SHA-256 hash string.

        Returns:
            dict[str, Any]: Observation dict and any loop detection signals.
        """
        self.step_index += 1

        command, stdout, stderr, redactions = self._redactor.redact_all(
            command, stdout, stderr
        )
        thought, t_counts = self._redactor.redact(thought)
        redactions = merge_counts(redactions, t_counts)

        sig, cls = error_signature(stderr, exit_code)
        ws_hash = (
            workspace_hash_val
            if workspace_hash_val is not None
            else workspace_hash(self.workspace)
        )

        out_stream = _make_stream_record(stdout)
        err_stream = _make_stream_record(stderr)

        obs = {
            "command": command,
            "command_fingerprint": fingerprint(command),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "output_limit_exceeded": output_limit_exceeded,
            "stdout": out_stream,
            "stderr": err_stream,
            "error_signature": sig,
            "error_class": cls,
            "workspace_hash": ws_hash,
            "duration_ms": duration_ms,
            "redactions": redactions,
        }

        step = {
            "session_id": self.session_id,
            "step_index": self.step_index,
            "thought": thought,
            **obs,
        }

        if self.agent_id:
            step["agent_id"] = self.agent_id

        if tool:
            step["tool"] = tool

        if parent_step is not None:
            step["parent_step_index"] = int(parent_step)

        if usage:
            step["usage"] = {str(k): int(v) for k, v in usage.items()}

        self.writer.append("step", step)

        self.cumulative_duration_ms += duration_ms
        signals = list(self.detector.observe(step))
        if self.semantic_detector and thought:
            signals.extend(self.semantic_detector.observe(thought, self.step_index))

        for signal in signals:
            self.writer.append(
                "analysis.signal",
                {"step_index": self.step_index, **signal},
            )

        self._enforce_contract_budgets()

        return {"observation": obs, "signals": signals}

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tool_source: str,
        arguments: Any = None,
        result: Any = None,
        duration_ms: int = 0,
        is_error: bool = False,
        thought: str = "",
        parent_step: int | None = None,
        usage: dict | None = None,
        workspace_hash_val: str | None = None,
    ) -> dict[str, Any]:
        """Record an already-executed tool call (for example an MCP tool call).

        It is one step: it takes the next `step_index`, counts toward the
        contract's max_steps and feeds the loop detector, the same as a shell
        command. `arguments` and `result` may be any JSON-like value. Secrets
        are removed before anything is written, and a value larger than
        64 KB is cut to its head and tail with its size and SHA-256 kept.

        `tool_source` is free text. Suggested forms: "mcp:<server>"
        (for example "mcp:github"), "builtin", "langchain", "function".
        """
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string")

        if not isinstance(tool_source, str) or not tool_source.strip():
            raise ValueError(
                "tool_source must be a non-empty string "
                "(for example 'mcp:github')"
            )

        duration_ms = max(int(duration_ms), 0)

        self.step_index += 1

        tool_name, c_name = self._redactor.redact(tool_name)
        tool_source, c_src = self._redactor.redact(tool_source)
        thought, c_thought = self._redactor.redact(thought)

        args, c_args = self._redactor.redact_value(to_jsonable(arguments))
        res, c_res = self._redactor.redact_value(to_jsonable(result))

        redactions = merge_counts(
            c_name,
            c_src,
            c_thought,
            c_args,
            c_res,
        )

        ws_hash = (
            workspace_hash_val
            if workspace_hash_val is not None
            else workspace_hash(self.workspace)
        )

        # The loop detector sees the same call on unchanged files as a repeat.
        # The fingerprint is exact, not normalized like a command's.
        err_text = as_text(res) if is_error else ""
        sig, _cls = error_signature(err_text, 1 if is_error else 0)

        observed = {
            "command_fingerprint": hashlib.sha256(
                f"tool {tool_source} {tool_name} ".encode()
                + serialize(args)
            ).hexdigest()[:16],
            "workspace_hash": ws_hash,
            "exit_code": 1 if is_error else 0,
            "error_signature": sig,
        }

        args, args_cut = cap_payload(args, MAX_PAYLOAD_BYTES)
        res, res_cut = cap_payload(res, MAX_PAYLOAD_BYTES)

        call = {
            "session_id": self.session_id,
            "step_index": self.step_index,
            "tool_name": tool_name,
            "tool_source": tool_source,
            "arguments": args,
            "result": res,
            "is_error": bool(is_error),
            "duration_ms": duration_ms,
            "thought": thought,
            "workspace_hash": ws_hash,
            "redactions": redactions,
        }

        if args_cut:
            call["arguments_truncated"] = True

        if res_cut:
            call["result_truncated"] = True

        if self.agent_id:
            call["agent_id"] = self.agent_id

        if parent_step is not None:
            call["parent_step_index"] = int(parent_step)

        if usage:
            call["usage"] = {str(k): int(v) for k, v in usage.items()}

        self.writer.append("tool.call", call)

        self.cumulative_duration_ms += duration_ms
        signals = list(self.detector.observe(observed))
        if self.semantic_detector and thought:
            signals.extend(self.semantic_detector.observe(thought, self.step_index))

        for signal in signals:
            self.writer.append(
                "analysis.signal",
                {"step_index": self.step_index, **signal},
            )

        self._enforce_contract_budgets()

        return {"observation": call, "signals": signals}

    def _redact_observation(self, obs: dict[str, Any]) -> dict[str, int]:
        """Apply this recorder's redactor (including custom patterns) to an observation dict."""
        cmd = obs.get("command", "")
        out_rec = obs.get("stdout") or {}
        err_rec = obs.get("stderr") or {}
        out_text = out_rec.get("text", "") if isinstance(out_rec, dict) else str(out_rec)
        err_text = err_rec.get("text", "") if isinstance(err_rec, dict) else str(err_rec)

        cmd_clean, out_clean, err_clean, extra_counts = self._redactor.redact_all(
            cmd, out_text, err_text
        )
        if not extra_counts:
            return {}

        if cmd_clean != cmd:
            obs["command"] = cmd_clean
            obs["command_fingerprint"] = fingerprint(cmd_clean)

        if isinstance(out_rec, dict) and out_clean != out_text:
            out_rec["text"] = out_clean
            out_rec["sha256"] = hashlib.sha256(out_clean.encode()).hexdigest()

        if isinstance(err_rec, dict) and err_clean != err_text:
            err_rec["text"] = err_clean
            err_rec["sha256"] = hashlib.sha256(err_clean.encode()).hexdigest()
            sig, cls = error_signature(err_clean, obs.get("exit_code", 0))
            obs["error_signature"] = sig
            obs["error_class"] = cls

        return extra_counts

    def _enforce_contract_budgets(self):
        if self.contract and not self.closed:
            if self.contract.check_step_budget(self.step_index):
                self.close(reason="contract_budget_exceeded:max_steps")
            elif self.contract.check_deadline_budget(
                time.monotonic() - self.start_wall_clock
            ):
                self.close(reason="contract_budget_exceeded:deadline_s")

    def run(
        self,
        command: str,
        thought: str = "",
        timeout_s: int = 60,
        *,
        tool: str | None = None,
        parent_step: int | None = None,
        usage: dict | None = None,
    ) -> dict[str, Any]:
        """Run a command in the sandbox/workspace and record the step.

        Args:
            command: Shell command string to execute.
            thought: Reasoning text or chain-of-thought preceding the action.
            timeout_s: Process execution timeout in seconds.
            tool: Optional tool name tag.
            parent_step: Optional parent step index in hierarchical runs.
            usage: Optional usage metric dictionary.

        Returns:
            dict[str, Any]: Contains 'observation', 'signals', and optional 'sandbox' metrics.
        """
        self.step_index += 1

        if self.policy is not None:
            blocked = self._apply_policy(
                command, thought, tool=tool, parent_step=parent_step, usage=usage
            )
            if blocked is not None:
                return blocked

        if self.sandbox:
            obs = self.sandbox.run(command, timeout_s)
        else:
            obs = run_command(command, self.workspace, timeout_s)

        sbx = obs.pop("sandbox", None)

        extra_counts = self._redact_observation(obs)
        thought, t_counts = self._redactor.redact(thought)
        redactions = merge_counts(obs.get("redactions", {}), extra_counts, t_counts)
        obs["redactions"] = redactions

        step = {
            "session_id": self.session_id,
            "step_index": self.step_index,
            "thought": thought,
            **obs,
            "redactions": redactions,
        }

        if self.agent_id:
            step["agent_id"] = self.agent_id

        if tool:
            step["tool"] = tool

        if parent_step is not None:
            step["parent_step_index"] = int(parent_step)

        if usage:
            step["usage"] = {
                str(k): int(v) for k, v in usage.items()
            }

        self.writer.append("step", step)

        if sbx:
            metrics = {
                k: sbx.get(k)
                for k in (
                    "mem_bytes",
                    "mem_limit_bytes",
                    "mem_pct",
                    "cpu_pct",
                    "pids",
                )
            }

            self.writer.append(
                "sandbox.resource",
                {"step_index": self.step_index, **metrics},
            )

            kind = _crash_kind(sbx)

            if kind:
                self.writer.append(
                    "sandbox.crash",
                    {
                        "step_index": self.step_index,
                        "kind": kind,
                        "exit_code": obs.get("exit_code"),
                        **sbx,
                    },
                )

        egress_events = obs.pop("egress_events", None)

        if egress_events:
            for event in egress_events:
                self.writer.append(
                    "network.egress",
                    {"step_index": self.step_index, **event},
                )

        self.cumulative_duration_ms += obs.get("duration_ms", 0)
        signals = list(self.detector.observe(step))
        if self.semantic_detector and thought:
            signals.extend(self.semantic_detector.observe(thought, self.step_index))

        for signal in signals:
            self.writer.append(
                "analysis.signal",
                {"step_index": self.step_index, **signal},
            )

        self._enforce_contract_budgets()

        return {
            "observation": obs,
            "signals": signals,
            "sandbox": sbx,
        }

    def _policy_event(self, command, thought, decision, approval, tool, parent_step, usage):
        """Build the (redacted) data for a policy.blocked / policy.approved event."""
        cmd, _out, _err, redactions = self._redactor.redact_all(command, "", "")
        thought, t_counts = self._redactor.redact(thought)
        matched, m_counts = self._redactor.redact(decision.matched or "")

        event = {
            "session_id": self.session_id,
            "step_index": self.step_index,
            "thought": thought,
            "command": cmd,
            "command_fingerprint": fingerprint(cmd),
            "action": decision.action.value,
            "rule": decision.rule,
            "reason": decision.reason,
            "approval": approval,
            "redactions": merge_counts(redactions, t_counts, m_counts),
        }

        if decision.matched:
            event["matched"] = matched

        if self.agent_id:
            event["agent_id"] = self.agent_id

        if tool:
            event["tool"] = tool

        if parent_step is not None:
            event["parent_step_index"] = int(parent_step)

        if usage:
            event["usage"] = {str(k): int(v) for k, v in usage.items()}

        return event

    def _apply_policy(self, command, thought, *, tool, parent_step, usage):
        """Evaluate the policy before execution.

        Returns None when the command may run. Otherwise the command is NOT executed: a signed
        policy.blocked event is written and a simulated error observation is returned.
        """
        decision = self.policy.evaluate(command, self.workspace)
        if decision.action is PolicyAction.ALLOW:
            return None

        approval = None
        if decision.action is PolicyAction.REQUIRE_APPROVAL:
            handler = self.approver or (self.policy.approver if isinstance(getattr(self.policy, "approver", None), ApprovalHandler) else None)
            if handler is not None:
                # HITL approval workflow: emit approval.requested, await operator, emit approval.decision
                req = ApprovalRequest(
                    command=command,
                    command_fingerprint=fingerprint(command),
                    rule=decision.rule,
                    reason=decision.reason,
                    step_index=self.step_index,
                    thought=thought,
                    tool=tool,
                    timeout_s=getattr(handler, "timeout_s", None),
                )
                self.writer.append("approval.requested", req.to_dict())

                dec = handler.request_approval(req)
                self.writer.append("approval.decision", dec.to_dict())
                approval = "approved" if dec.approved else "denied"
            else:
                approval = self.policy.request_approval(command, decision)

        event = self._policy_event(
            command, thought, decision, approval, tool, parent_step, usage
        )

        if approval == "approved":
            self.writer.append("policy.approved", event)
            return None

        self.writer.append("policy.blocked", event)

        message = (
            f"agentbox policy blocked this command ({decision.rule}): {decision.reason}."
        )
        if decision.action is PolicyAction.REQUIRE_APPROVAL:
            message += " Approval is required and was not granted."

        ws_hash = workspace_hash(self.workspace)
        sig = f"PolicyViolation:{fingerprint(decision.rule)}"
        obs = {
            "command": event["command"],
            "command_fingerprint": event["command_fingerprint"],
            "exit_code": 126,
            "timed_out": False,
            "output_limit_exceeded": False,
            "stdout": _make_stream_record(""),
            "stderr": _make_stream_record(message),
            "error_signature": sig,
            "error_class": "PolicyViolation",
            "workspace_hash": ws_hash,
            "duration_ms": 0,
            "redactions": event["redactions"],
        }

        # A blocked attempt still counts as a step and feeds the loop detector.
        observed = {
            "command_fingerprint": obs["command_fingerprint"],
            "workspace_hash": ws_hash,
            "exit_code": 126,
            "error_signature": sig,
        }
        signals = list(self.detector.observe(observed))
        if self.semantic_detector and event["thought"]:
            signals.extend(
                self.semantic_detector.observe(event["thought"], self.step_index)
            )

        for signal in signals:
            self.writer.append(
                "analysis.signal",
                {"step_index": self.step_index, **signal},
            )

        self._enforce_contract_budgets()

        return {
            "observation": obs,
            "signals": signals,
            "sandbox": None,
            "blocked": True,
            "policy": decision.to_dict(),
        }

    def _register_exit_handlers(self) -> None:
        """Register atexit and signal handlers (SIGTERM, SIGINT) to seal session on unexpected termination."""
        def _cleanup():
            if not self.closed:
                try:
                    self.close(reason="process_exit")
                except Exception:
                    pass

        self._atexit_cleanup = _cleanup
        atexit.register(_cleanup)

        try:
            for sig in (_signal.SIGINT, _signal.SIGTERM):
                prev_h = _signal.getsignal(sig)

                def _signal_handler(signum, frame, old_h=prev_h):
                    if not self.closed:
                        try:
                            sig_name = _signal.Signals(signum).name.lower()
                            self.close(reason=f"signal_{sig_name}")
                        except Exception:
                            pass
                    if callable(old_h):
                        old_h(signum, frame)
                    elif old_h == _signal.SIG_DFL:
                        _signal.signal(signum, _signal.SIG_DFL)
                        os.kill(os.getpid(), signum)

                _signal.signal(sig, _signal_handler)
        except (ValueError, AttributeError, RuntimeError):
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.close(reason=f"exception:{exc_type.__name__}")
        else:
            self.close(reason="done")
        return False

    def close(self, reason: str = "done") -> None:
        """Close the recording session and write the signed manifest and receipt.

        Args:
            reason: Explanation of why the session finished.
        """
        if self.closed:
            return

        self.closed = True

        if hasattr(self, "_atexit_cleanup"):
            try:
                atexit.unregister(self._atexit_cleanup)
            except Exception:
                pass

        if self.contract:
            elapsed_wall_s = time.monotonic() - self.start_wall_clock
            cumulative_duration_s = self.cumulative_duration_ms / 1000.0

            self.contract_verdict = self.contract.evaluate(
                workspace=self.workspace,
                steps=self.step_index,
                cumulative_duration_s=cumulative_duration_s,
                elapsed_wall_clock_s=elapsed_wall_s,
                sandbox=self.sandbox,
            )

            self.writer.append(
                "contract.verdict",
                self.contract_verdict.to_dict(),
            )

        end_data: dict[str, Any] = {"reason": reason, "steps": self.step_index}
        if not self.ed25519_key:
            end_data["receipt_created"] = False
            end_data["receipt_skipped_reason"] = "no_ed25519_key"

        self.writer.append("session.end", end_data)

        self.writer.write_manifest()

        receipt_error: RuntimeError | None = None
        if self.ed25519_key:
            self.writer.write_receipt(session_id=self.session_id)
        else:
            if self.require_receipt:
                receipt_error = RuntimeError(
                    "agentbox: require_receipt=True, but no Ed25519 key is available; "
                    "cannot create receipt. Run 'agentbox keygen' or pass ed25519_key_path."
                )
            else:
                warnings.warn(
                    "agentbox: no Ed25519 key found, receipt not created. "
                    "Run 'agentbox keygen' to enable third-party verification.",
                    UserWarning,
                    stacklevel=2,
                )

        if self.sandbox:
            self.sandbox.stop()

        if receipt_error is not None:
            raise receipt_error
