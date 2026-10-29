"""Isolated Docker sandbox runner (Slice S2)."""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

from contracts import RunResult


class SandboxConfigError(ValueError):
    """Raised when sandbox invocation parameters violate safety policy."""


class DockerSandbox:
    """Runs commands inside a network-isolated, read-only, resource-capped Docker container."""

    def __init__(
        self,
        image: str = "psa-sandbox:latest",
        agent_tag: str = "main",
        memory_limit: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 128,
        user: str = "1000:1000",
    ) -> None:
        self.image = image
        self.agent_tag = agent_tag
        self.memory_limit = memory_limit
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.user = user

    def run(self, workspace: Path, command: list[str], timeout_s: float = 30.0) -> RunResult:
        if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
            raise SandboxConfigError("command must be a non-empty list of non-empty strings")
        if timeout_s <= 0:
            raise SandboxConfigError("timeout_s must be positive")

        resolved_ws = workspace.resolve()
        if not resolved_ws.exists() or not resolved_ws.is_dir():
            raise SandboxConfigError(f"workspace directory does not exist: {resolved_ws}")

        container_name = f"psa-{self.agent_tag}-{uuid.uuid4().hex[:10]}"
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            self.memory_limit,
            "--cpus",
            self.cpus,
            "--user",
            self.user,
            "-e",
            "AUTH_TOKEN_SECRET=sandbox-ephemeral-test-secret",
            "-e",
            "WEBHOOK_API_KEY=sandbox-ephemeral-webhook-key",
            "-e",
            "ALLOWED_ORIGIN=https://app.internal.example",
            "-v",
            f"{resolved_ws}:/workspace:rw",
            "-w",
            "/workspace",
            self.image,
            *command,
        ]

        start = time.perf_counter()
        proc = subprocess.Popen(
            docker_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            duration_ms = int((time.perf_counter() - start) * 1000)
            return RunResult(
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                duration_ms=duration_ms,
            )
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            duration_ms = int((time.perf_counter() - start) * 1000)
            return RunResult(
                exit_code=124,
                stdout=stdout or "",
                stderr=stderr or "",
                timed_out=True,
                duration_ms=duration_ms,
            )
