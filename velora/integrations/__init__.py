"""Safe adapters for external tools (nmap, OWASP ZAP, nuclei).

Safety rules enforced by ``base.ToolAdapter``:
  * Commands are executed as argument *arrays* — never a shell string. No user input is
    ever concatenated into a shell command.
  * The executable path is resolved and validated before execution.
  * The target host is validated against the scan's ScopeManager first; out-of-scope
    targets are refused.
  * Every run has a timeout; the child process (and its group) is killed on timeout or
    cancellation.
  * stdout/stderr are captured with a size cap and returned safely.
"""
from .base import ToolAdapter, ToolResult
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .zap import ZapAdapter

__all__ = ["ToolAdapter", "ToolResult", "NmapAdapter", "ZapAdapter", "NucleiAdapter"]
