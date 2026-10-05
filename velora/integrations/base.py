"""Base class for safe external-tool adapters."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..scope.manager import ScopeManager
from ..utils.errors import IntegrationError, ScopeViolation
from ..utils.logging import get_logger

log = get_logger("integrations")

_MAX_OUTPUT = 2_000_000  # cap captured output at ~2MB


@dataclass
class ToolResult:
    tool: str
    available: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    command: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.available and not self.timed_out and self.returncode == 0 and self.error is None


class ToolAdapter:
    """Common safe-execution machinery for CLI tools."""

    tool_name: str = "tool"
    executable: str = "tool"

    def __init__(self, scope: ScopeManager | None = None, executable: str | None = None) -> None:
        self.scope = scope
        if executable:
            self.executable = executable

    def resolve_executable(self) -> str | None:
        """Return the absolute path to the executable, or None if not found."""
        # Absolute/relative path provided explicitly.
        if os.path.sep in self.executable:
            path = os.path.abspath(self.executable)
            return path if os.path.isfile(path) and os.access(path, os.X_OK) else None
        return shutil.which(self.executable)

    def available(self) -> bool:
        return self.resolve_executable() is not None

    def _authorize_target(self, target: str) -> None:
        """Ensure the target host is within scope before invoking an external tool."""
        if self.scope is None:
            return
        # Build a URL for the scope check if a bare host was passed.
        candidate = target if "://" in target else f"http://{target}"
        decision = self.scope.check(candidate)
        if not decision.allowed:
            # For non-web tools (nmap) also try https and the raw host acceptance.
            host = urlsplit(candidate).hostname or target
            https_decision = self.scope.check(f"https://{host}")
            if not https_decision.allowed:
                log.security("EXTERNAL_TOOL_TARGET_OUT_OF_SCOPE tool=%s target=%s reason=%s",
                             self.tool_name, target, decision.reason)
                raise ScopeViolation(target, f"external-tool-scope:{decision.reason}")

    def _run(self, args: list[str], timeout: float = 120.0) -> ToolResult:
        """Execute ``[executable, *args]`` safely with a timeout and process-group kill."""
        exe = self.resolve_executable()
        if exe is None:
            return ToolResult(tool=self.tool_name, available=False,
                              error=f"{self.executable} not found on PATH")
        # Defensive: reject any arg that is not a string (no injection via odd types).
        if not all(isinstance(a, str) for a in args):
            raise IntegrationError("all tool arguments must be strings")
        command = [exe, *args]
        try:
            proc = subprocess.Popen(  # noqa: S603 - args is a validated list, shell=False
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # own process group so we can kill children
            )
        except (OSError, ValueError) as exc:
            return ToolResult(tool=self.tool_name, available=True, command=command,
                              error=f"failed to start: {exc}")
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return ToolResult(tool=self.tool_name, available=True, returncode=proc.returncode,
                              stdout=(stdout or "")[:_MAX_OUTPUT],
                              stderr=(stderr or "")[:_MAX_OUTPUT], command=command)
        except subprocess.TimeoutExpired:
            self._kill(proc)
            return ToolResult(tool=self.tool_name, available=True, timed_out=True,
                              command=command, error=f"timed out after {timeout}s")
        except BaseException:
            # Includes KeyboardInterrupt / cancellation — ensure the child is killed.
            self._kill(proc)
            raise

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
