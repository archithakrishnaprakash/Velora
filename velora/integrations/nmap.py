"""nmap adapter — safe, scope-restricted service discovery.

Only a conservative, non-intrusive default is exposed (``-sT -Pn --top-ports``). No
aggressive/OS-detection/script flags are enabled by default. Ports are validated as
integers; the host is scope-checked before invocation.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .base import ToolAdapter, ToolResult


class NmapAdapter(ToolAdapter):
    tool_name = "nmap"
    executable = "nmap"

    def scan_host(self, target: str, *, top_ports: int = 100, timeout: float = 180.0) -> ToolResult:
        host = urlsplit(target).hostname or target
        self._authorize_target(host)
        if not isinstance(top_ports, int) or not (1 <= top_ports <= 65535):
            top_ports = 100
        # -sT connect scan (no raw sockets/root), -Pn skip host discovery, -T3 polite.
        args = ["-sT", "-Pn", "-T3", "--top-ports", str(top_ports), "-oX", "-", host]
        return self._run(args, timeout=timeout)
