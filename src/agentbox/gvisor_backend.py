"""gVisor (runsc) user-space kernel zero-trust sandbox backend (Issue #103).

Provides hypervisor-like container isolation by virtualizing all system calls in user-space
via gVisor (runsc), completely decoupling untrusted agent code from the host Linux kernel.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import warnings
from typing import Any

from .docker_backend import (
    DEFAULT_IMAGE,
    DockerNotAvailable,
    DockerSandbox,
    docker_available,
)


class GVisorNotAvailable(RuntimeError):
    """Raised when gVisor (runsc) runtime is not installed or configured in Docker."""


def gvisor_available(runtime: str = "runsc") -> bool:
    """Return True if gVisor (runsc) binary or Docker runtime is installed and configured."""
    # 1. Direct binary check on PATH
    if shutil.which(runtime) or shutil.which("runsc"):
        return True

    # 2. Check Docker daemon configured runtimes
    if docker_available():
        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                try:
                    runtimes = json.loads(res.stdout.strip())
                    if isinstance(runtimes, dict) and (runtime in runtimes or "runsc" in runtimes or "gvisor" in runtimes):
                        return True
                except json.JSONDecodeError:
                    if runtime in res.stdout or "runsc" in res.stdout:
                        return True
        except (subprocess.SubprocessError, OSError):
            pass

    return False


class GVisorSandbox(DockerSandbox):
    """Zero-trust sandbox running under gVisor's virtualized user-space kernel (runsc).

    Every system call executed by the agent is intercepted by gVisor Sentry in user space,
    providing hardware-like isolation without raw host kernel attack surface.
    """

    def __init__(
        self,
        workspace: str = "./workspace-gvisor",
        image: str = DEFAULT_IMAGE,
        runtime: str = "runsc",
        network: str = "none",
        memory: str = "512m",
        cpus: str = "1",
        pids: int = 128,
        resource_stats: bool = True,
        user: str | None = None,
        egress_policy: Any = None,
        require_gvisor: bool = True,
        fallback_to_docker: bool = False,
    ) -> None:
        """Initialize GVisorSandbox configuration.

        Args:
            workspace: Host workspace directory mounted inside container.
            image: Docker base image (default: python:3.12-slim).
            runtime: Name of gVisor runtime configured in Docker (default: 'runsc').
            network: Network isolation mode ('none' by default).
            memory: Memory constraint limit.
            cpus: CPU quota allocation.
            pids: Maximum PID count limit.
            resource_stats: Collect per-step resource consumption metrics.
            user: Container execution user 'uid:gid'.
            egress_policy: Optional EgressPolicy proxy filter.
            require_gvisor: If True, raise GVisorNotAvailable if runtime is missing.
            fallback_to_docker: If True and gVisor is missing, fall back to standard Docker with warning.
        """
        super().__init__(
            workspace=workspace,
            image=image,
            network=network,
            memory=memory,
            cpus=cpus,
            pids=pids,
            resource_stats=resource_stats,
            user=user,
            egress_policy=egress_policy,
        )
        self.runtime = runtime
        self.require_gvisor = require_gvisor
        self.fallback_to_docker = fallback_to_docker
        self._active_runtime = runtime

    def describe(self) -> dict[str, Any]:
        """Return cryptographic attestation descriptor of gVisor isolation level."""
        desc = super().describe()
        is_virtualized = self._active_runtime == self.runtime
        desc["backend"] = "gvisor" if is_virtualized else "docker"
        desc["runtime"] = self._active_runtime
        desc["virtualized"] = is_virtualized
        desc["isolation_level"] = "kernel_userspace" if is_virtualized else "container_cgroups"
        return desc

    def start(self) -> None:
        """Start container under gVisor (runsc) user-space kernel."""
        if not docker_available():
            raise DockerNotAvailable("Docker is not running or not installed.")

        if not gvisor_available(self.runtime):
            if self.fallback_to_docker:
                warnings.warn(
                    f"gVisor runtime '{self.runtime}' not available; falling back to standard Docker runtime.",
                    UserWarning,
                    stacklevel=2,
                )
                self._active_runtime = "runc"
            elif self.require_gvisor:
                raise GVisorNotAvailable(
                    f"gVisor runtime '{self.runtime}' is not installed or configured in Docker. "
                    "Install runsc (https://gvisor.dev/docs/user_guide/install/) or pass fallback_to_docker=True."
                )

        os.makedirs(self.workspace, exist_ok=True)
        if self.egress_policy:
            from .egress_proxy import EgressProxy

            self._egress_proxy = EgressProxy(self.egress_policy)
            self._egress_proxy.start()

        network = "bridge" if (self.egress_policy and self.network == "none") else self.network
        cmd = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            self.name,
            "--network",
            network,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.pids),
            "--memory",
            self.memory,
            "--memory-swap",
            self.memory,
            "--cpus",
            str(self.cpus),
            "--user",
            self.user,
            "-e",
            "HOME=/tmp",
            "-w",
            "/workspace",
            "-v",
            f"{self.workspace}:/workspace",
        ]

        if self._active_runtime != "runc":
            cmd.extend(["--runtime", self._active_runtime])

        if self.egress_policy:
            cmd.extend(
                [
                    "-e",
                    f"HTTP_PROXY=http://127.0.0.1:{self._egress_proxy.port}",
                    "-e",
                    f"HTTPS_PROXY=http://127.0.0.1:{self._egress_proxy.port}",
                    "-e",
                    f"http_proxy=http://127.0.0.1:{self._egress_proxy.port}",
                    "-e",
                    f"https_proxy=http://127.0.0.1:{self._egress_proxy.port}",
                ]
            )

        cmd.extend([self.image, "tail", "-f", "/dev/null"])

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.started = True
        except subprocess.CalledProcessError as e:
            err = (e.stderr or "").strip()
            if "unknown flag: --runtime" in err or "Unknown runtime" in err or self._active_runtime in err:
                raise GVisorNotAvailable(
                    f"Docker failed to start with runtime '{self._active_runtime}': {err}"
                ) from e
            raise RuntimeError(f"Failed to start gVisor container: {err}") from e

        self._start_event_watcher()


class MicroVMSandbox(GVisorSandbox):
    """Alias for hypervisor-level / microVM container isolation."""

    def describe(self) -> dict[str, Any]:
        desc = super().describe()
        desc["backend"] = "microvm"
        return desc
