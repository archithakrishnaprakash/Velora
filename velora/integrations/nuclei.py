"""nuclei adapter — scope-restricted template scanning.

Defaults to informational/low templates and JSON output. The URL is scope-checked first.
Users may pass an explicit, validated severity set; arbitrary flags are not accepted.
"""
from __future__ import annotations

from .base import ToolAdapter, ToolResult

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiAdapter(ToolAdapter):
    tool_name = "nuclei"
    executable = "nuclei"

    def scan_url(self, url: str, *, severities: list[str] | None = None,
                 timeout: float = 300.0) -> ToolResult:
        self._authorize_target(url)
        sevs = [s for s in (severities or ["info", "low", "medium"]) if s in _ALLOWED_SEVERITIES]
        args = ["-u", url, "-jsonl", "-severity", ",".join(sevs), "-silent",
                "-rate-limit", "20", "-timeout", "10"]
        return self._run(args, timeout=timeout)
