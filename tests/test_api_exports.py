"""Tests for top-level package API exports (Issue #102)."""
import agentbox
from agentbox import (
    DockerNotAvailable,
    DockerSandbox,
    Recorder,
    docker_available,
)
import agentbox.docker_backend as backend


def test_top_level_docker_sandbox_exports():
    """Verify DockerSandbox, docker_available, and DockerNotAvailable are exported at root."""
    assert DockerSandbox is backend.DockerSandbox
    assert docker_available is backend.docker_available
    assert DockerNotAvailable is backend.DockerNotAvailable


def test_all_contains_docker_sandbox_symbols():
    """Verify __all__ explicitly includes the Docker sandbox symbols."""
    assert "DockerSandbox" in agentbox.__all__
    assert "docker_available" in agentbox.__all__
    assert "DockerNotAvailable" in agentbox.__all__


def test_backward_compatibility_of_submodule():
    """Verify importing from agentbox.docker_backend remains 100% functional."""
    from agentbox.docker_backend import (
        DockerNotAvailable as SubNotAvailable,
        DockerSandbox as SubSandbox,
        docker_available as sub_available,
    )
    assert SubSandbox is DockerSandbox
    assert sub_available is docker_available
    assert SubNotAvailable is DockerNotAvailable


def test_recorder_accepts_top_level_sandbox_type(tmp_path):
    """Verify Recorder type annotations and runtime accept top-level DockerSandbox."""
    class FakeDocker(DockerSandbox):
        def __init__(self, ws):
            self.workspace = ws

        def describe(self):
            return {"backend": "docker", "image": "python:3.12-slim"}

        def run(self, cmd, timeout_s=60, **_):
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        def stop(self):
            pass

    sb = FakeDocker(str(tmp_path / "ws"))
    rec = Recorder("test-sess", workspace=str(tmp_path / "ws"), log_dir=str(tmp_path / "runs"), sandbox=sb)
    assert rec.sandbox is sb
    rec.close()
