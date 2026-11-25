"""Unit and integration tests for gVisor zero-trust sandbox backend (Issue #103)."""
import json

import pytest
from agentbox import (
    GVisorNotAvailable,
    GVisorSandbox,
    MicroVMSandbox,
    Recorder,
    gvisor_available,
)
from agentbox.signer import load_or_create_key, verify_log


def test_gvisor_available_boolean_check():
    """Verify gvisor_available() returns a boolean and does not crash."""
    available = gvisor_available()
    assert isinstance(available, bool)


def test_gvisor_sandbox_descriptor():
    """Verify GVisorSandbox.describe() attests to kernel_userspace isolation."""
    sb = GVisorSandbox(
        workspace="./ws",
        image="python:3.12-slim",
        runtime="runsc",
        memory="1g",
        cpus="2",
    )
    desc = sb.describe()
    assert desc["backend"] == "gvisor"
    assert desc["runtime"] == "runsc"
    assert desc["virtualized"] is True
    assert desc["isolation_level"] == "kernel_userspace"
    assert desc["read_only_rootfs"] is True
    assert desc["cap_drop"] == "ALL"
    assert desc["memory"] == "1g"
    assert desc["cpus"] == "2"


def test_microvm_sandbox_descriptor():
    """Verify MicroVMSandbox.describe() attests to microvm backend."""
    sb = MicroVMSandbox(workspace="./ws")
    desc = sb.describe()
    assert desc["backend"] == "microvm"
    assert desc["virtualized"] is True


def test_gvisor_not_available_raises_when_required(monkeypatch):
    """When gVisor is not present and require_gvisor=True, start() raises GVisorNotAvailable."""
    monkeypatch.setattr("agentbox.gvisor_backend.docker_available", lambda: True)
    monkeypatch.setattr("agentbox.gvisor_backend.gvisor_available", lambda rt: False)

    sb = GVisorSandbox(workspace="./ws", require_gvisor=True, fallback_to_docker=False)
    with pytest.raises(GVisorNotAvailable, match="not installed or configured"):
        sb.start()


def test_gvisor_fallback_to_docker_mode(monkeypatch):
    """When fallback_to_docker=True and gVisor is missing, falls back with a warning."""
    monkeypatch.setattr("agentbox.gvisor_backend.docker_available", lambda: True)
    monkeypatch.setattr("agentbox.gvisor_backend.gvisor_available", lambda rt: False)

    calls = []

    def mock_run(cmd, **kwargs):
        calls.append(cmd)
        class Dummy:
            returncode = 0
            stdout = ""
            stderr = ""
        return Dummy()

    monkeypatch.setattr("subprocess.run", mock_run)

    sb = GVisorSandbox(workspace="./ws", fallback_to_docker=True)
    monkeypatch.setattr(sb, "_start_event_watcher", lambda: None)
    with pytest.warns(UserWarning, match="falling back to standard Docker"):
        sb.start()

    assert sb.started is True
    assert sb._active_runtime == "runc"
    run_cmd = calls[0]
    assert "--runtime" not in run_cmd

    assert sb._active_runtime == "runc"
    assert sb.describe()["backend"] == "docker"
    assert sb.describe()["virtualized"] is False
    sb.stop()


def test_recorder_records_gvisor_attestation_in_signed_log(tmp_path):
    """Recorder records gVisor isolation parameters into signed session.start and verifies."""
    class FakeGVisor(GVisorSandbox):
        def start(self):
            self.started = True

        def run(self, cmd, timeout_s=60, **_):
            return {
                "exit_code": 0,
                "stdout": {"text": "hello from gvisor", "total_bytes": 19, "truncated": False},
                "stderr": {"text": "", "total_bytes": 0, "truncated": False},
                "duration_ms": 15,
                "timed_out": False,
                "output_limit_exceeded": False,
                "command": cmd,
                "command_fingerprint": "fp123",
                "error_signature": None,
                "error_class": None,
                "workspace_hash": "ws_hash",
                "redactions": {},
            }

        def stop(self):
            self.started = False

    sb = FakeGVisor(workspace=str(tmp_path / "ws"))
    key_path = tmp_path / "key"
    rec = Recorder("gvisor-audit-sess", workspace=str(tmp_path / "ws"), log_dir=str(tmp_path / "runs"),
                   key_path=key_path, sandbox=sb)

    out = rec.run("echo test")
    assert out["observation"]["stdout"]["text"] == "hello from gvisor"
    rec.close()

    lines = [json.loads(line) for line in rec.log_path.read_text(encoding="utf-8").splitlines()]
    start_event = next(r for r in lines if r["event"]["event_type"] == "session.start")

    isolation = start_event["event"]["data"]["isolation"]
    assert isolation["backend"] == "gvisor"
    assert isolation["runtime"] == "runsc"
    assert isolation["virtualized"] is True
    assert isolation["isolation_level"] == "kernel_userspace"

    problems, incomplete = verify_log(rec.log_path, load_or_create_key(key_path))
    assert not problems and not incomplete
