"""Security regression tests for assert_command sandbox isolation (Issue #54).

Guarantees:
  1. assert_command is refused on the local backend unless allow_unsafe_host_exec=True.
  2. High-severity warning is emitted when running unsandboxed on host.
  3. Ephemeral container isolation prevents host escapes (canary test: conftest.py host escape).
  4. Test suite integrity hashing detects agents tampering with or deleting test files.
  5. Test suite file hashes are recorded in the cryptographically signed verdict.
"""
import sys

import pytest

from agentbox import (
    Recorder,
    TaskContract,
    assert_command,
    assert_file_exists,
)
from agentbox.docker_backend import DockerSandbox, docker_available

_PY = sys.executable.replace("\\", "/")


# ==============================================================================
# 1. Local Backend Safeguard & Warnings
# ==============================================================================

def test_local_backend_refuses_assert_command_by_default(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()

    # Default assert_command has allow_unsafe_host_exec=False
    assertion = assert_command(f'"{_PY}" -c "print(1)"')
    res = assertion.check(ws)

    assert res.passed is False
    assert "refused on local backend without allow_unsafe_host_exec=True" in res.details
    assert "SECURITY:" in res.details


def test_local_backend_warns_when_allow_unsafe_host_exec_enabled(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()

    assertion = assert_command(f'"{_PY}" -c "print(1)"', allow_unsafe_host_exec=True)

    with pytest.warns(UserWarning, match="SECURITY WARNING: assert_command .* executing on host"):
        res = assertion.check(ws)

    assert res.passed is True


def test_task_contract_evaluate_refuses_unsandboxed_command(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()

    contract = TaskContract(
        task_id="test-gate",
        assertions=[
            assert_command(f'"{_PY}" -c "print(1)"'),
        ],
    )

    verdict = contract.evaluate(ws)
    assert verdict.passed is False
    assert any("refused on local backend" in a.details for a in verdict.assertions)


# ==============================================================================
# 2. Canary Regression Test: Agent conftest.py Host Escape Attack
# ==============================================================================

def test_canary_host_escape_attack_prevented_on_local_backend(tmp_path):
    """Canary test: Malicious agent writes conftest.py attempting to execute code on host."""
    ws = tmp_path / "ws"
    ws.mkdir()
    canary = tmp_path / "host_canary.txt"

    # Agent drops malicious conftest.py into workspace that touches host canary
    malicious_conftest = ws / "conftest.py"
    malicious_conftest.write_text(
        f"import pathlib\npathlib.Path({str(canary)!r}).touch()\n",
        encoding="utf-8",
    )

    contract = TaskContract(
        task_id="canary-gate",
        assertions=[
            assert_command("pytest"),
        ],
    )

    # Local evaluation refuses to execute command
    verdict = contract.evaluate(ws)
    assert verdict.passed is False

    # The canary file on the host must NEVER exist
    assert not canary.exists(), "SECURITY CRITICAL: Host canary file was created by untrusted agent workspace code!"


@pytest.mark.skipif(not docker_available(), reason="docker not available")
def test_canary_host_escape_attack_prevented_in_docker_sandbox(tmp_path):
    """Canary test: In Docker, assertion runs in ephemeral sandbox with read-only workspace."""
    ws = tmp_path / "ws"
    ws.mkdir()
    canary = tmp_path / "host_canary_docker.txt"

    # Agent drops malicious conftest.py attempting to write outside
    malicious_conftest = ws / "conftest.py"
    malicious_conftest.write_text(
        f"import pathlib\npathlib.Path({str(canary)!r}).touch()\n",
        encoding="utf-8",
    )

    sb = DockerSandbox(workspace=str(ws))
    contract = TaskContract(
        task_id="canary-docker",
        assertions=[
            assert_command("pytest || true"),
        ],
    )

    contract.evaluate(ws, sandbox=sb)
    # The container has its own mount namespace and /workspace is mounted :ro
    assert not canary.exists(), "SECURITY CRITICAL: Host canary file was created from Docker sandbox!"


# ==============================================================================
# 3. Test Integrity Hashing & Tampering Detection
# ==============================================================================

def test_integrity_hashing_detects_modified_test_file(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    tests_dir = ws / "tests"
    tests_dir.mkdir()

    test_file = tests_dir / "test_solution.py"
    test_file.write_text("def test_ok(): assert False", encoding="utf-8")

    contract = TaskContract(
        task_id="tamper-detect",
        test_files=["tests/test_solution.py"],
        assertions=[assert_file_exists("tests/test_solution.py")],
    )

    # Pre-record hashes before agent runs
    hashes = contract.record_test_hashes(ws)
    assert "tests/test_solution.py" in hashes

    # Agent modifies test file to force a pass
    test_file.write_text("def test_ok(): assert True", encoding="utf-8")

    verdict = contract.evaluate(ws)
    assert verdict.passed is False
    assert verdict.test_tampering is not None
    assert any("tests/test_solution.py" in t for t in verdict.test_tampering)
    assert "Security violation: test suite files tampered" in verdict.summary


def test_integrity_hashing_detects_deleted_test_file(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    test_file = ws / "test_important.py"
    test_file.write_text("def test_must_pass(): pass", encoding="utf-8")

    contract = TaskContract(
        task_id="tamper-delete",
        test_files=["test_important.py"],
    )
    contract.record_test_hashes(ws)

    # Agent deletes test file
    test_file.unlink()

    verdict = contract.evaluate(ws)
    assert verdict.passed is False
    assert verdict.test_tampering == ["test_important.py (deleted)"]


def test_recorder_end_to_end_records_test_hashes_in_signed_verdict(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    tests_dir = ws / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_api.py"
    test_file.write_text("def test_api(): pass", encoding="utf-8")

    contract = TaskContract(
        task_id="signed-hashes",
        test_files=["tests/test_api.py"],
        assertions=[assert_file_exists("tests/test_api.py")],
    )

    log_dir = tmp_path / "runs"
    rec = Recorder(
        session_id="eval-hash-session",
        workspace=str(ws),
        log_dir=str(log_dir),
        contract=contract,
    )

    # Agent executes a step
    rec.record_step(command="echo done", stdout="done")
    rec.close()

    assert rec.contract_verdict is not None
    assert rec.contract_verdict.passed is True
    assert rec.contract_verdict.test_hashes is not None
    assert "tests/test_api.py" in rec.contract_verdict.test_hashes


# ==============================================================================
# 4. Ephemeral Docker Sandbox Execution
# ==============================================================================

@pytest.mark.skipif(not docker_available(), reason="docker not available")
def test_docker_ephemeral_eval_workspace_is_read_only(tmp_path):
    """Ephemeral container workspace is mounted read-only; attempts to write fail."""
    ws = tmp_path / "ws"
    ws.mkdir()

    sb = DockerSandbox(workspace=str(ws))
    # Trying to write to /workspace inside eval container fails (EROFS)
    res = sb.run_eval("touch /workspace/pwned.txt")
    assert res["exit_code"] != 0
    assert not (ws / "pwned.txt").exists()


@pytest.mark.skipif(not docker_available(), reason="docker not available")
def test_docker_ephemeral_eval_has_no_network(tmp_path):
    """Ephemeral container has --network none."""
    ws = tmp_path / "ws"
    ws.mkdir()

    sb = DockerSandbox(workspace=str(ws))
    # Python socket connection attempt fails immediately
    cmd = "python3 -c \"import socket; socket.create_connection(('1.1.1.1', 80), timeout=2)\""
    res = sb.run_eval(cmd, timeout_s=5)
    assert res["exit_code"] != 0
