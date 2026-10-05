"""OWASP ZAP adapter — baseline (passive) scan via zap-baseline.py or the CLI.

Runs ZAP's baseline (passive) scan, which does not perform active attacks. The target URL
is scope-checked first. If ZAP is not installed, the adapter reports unavailability.
"""
from __future__ import annotations

from .base import ToolAdapter, ToolResult


class ZapAdapter(ToolAdapter):
    tool_name = "zap"
    executable = "zap-baseline.py"

    def baseline_scan(self, url: str, *, timeout: float = 600.0) -> ToolResult:
        self._authorize_target(url)
        # -t target, -I do not fail on warnings, -j use the ZAP AJAX spider off by default.
        args = ["-t", url, "-I", "-s"]
        return self._run(args, timeout=timeout)
