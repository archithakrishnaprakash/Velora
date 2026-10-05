"""Security-check plugin framework.

A ``SecurityCheck`` is a deterministic detector. It receives a ``ScanContext`` (the
scope-gated HTTP client plus already-collected recon/crawl data) and returns zero or more
``CheckOutput`` objects, each carrying its own evidence. Checks NEVER decide a finding is
Confirmed and NEVER perform destructive or exploitative actions; they observe and report.

The AI layer runs later and only *explains* these evidence-backed outputs.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..core.http import SafeHTTPClient
from ..crawler import CrawlResult
from ..models.enums import Confidence, Severity
from ..reconnaissance import ReconResult
from ..scope.manager import ScopeManager


@dataclass
class ScanContext:
    """Everything a check needs, all scope-gated."""

    target: str
    client: SafeHTTPClient
    scope: ScopeManager
    recon: ReconResult | None = None
    crawl: CrawlResult | None = None
    profile: str = "safe"

    def endpoints(self) -> list[str]:
        urls = {self.target}
        if self.crawl:
            urls.update(e.url for e in self.crawl.endpoints)
        return sorted(urls)


@dataclass
class EvidenceItem:
    """A single piece of evidence attached to a CheckOutput."""

    test_name: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    content_type: str = ""
    response_size: int = 0
    excerpt: str = ""
    confidence: float = 0.5


@dataclass
class CheckOutput:
    """A deterministic detection produced by a SecurityCheck."""

    title: str
    category: str
    severity: Severity
    confidence: Confidence
    endpoint: str
    description: str
    remediation: str
    method: str = "GET"
    impact: str = ""
    references: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_base_score: float | None = None
    cvss_version: str | None = None


class SecurityCheck(abc.ABC):
    """Base class for all deterministic security checks."""

    id: str = "base"
    name: str = "Base Check"
    description: str = ""
    category: str = "general"
    severity: Severity = Severity.INFO
    safe_mode: bool = True  # True => runs in the default 'safe' profile
    references: list[str] = []

    #: JSON-schema-like description of the evidence this check emits (documentation aid).
    evidence_schema: dict[str, Any] = {}

    #: Default remediation guidance (a check may override per-output).
    remediation: str = ""

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        """Return zero or more evidence-backed detections. Must not raise on findings."""
        raise NotImplementedError

    def applies_to_profile(self, profile: str) -> bool:
        if profile == "safe":
            return self.safe_mode
        return True  # standard/lab profiles run all checks


class CheckRegistry:
    """Registry of available security checks."""

    def __init__(self) -> None:
        self._checks: dict[str, type[SecurityCheck]] = {}

    def register(self, check_cls: type[SecurityCheck]) -> type[SecurityCheck]:
        if check_cls.id in self._checks:
            raise ValueError(f"duplicate check id: {check_cls.id}")
        self._checks[check_cls.id] = check_cls
        return check_cls

    def all(self) -> list[type[SecurityCheck]]:
        return sorted(self._checks.values(), key=lambda c: c.id)

    def get(self, check_id: str) -> type[SecurityCheck] | None:
        return self._checks.get(check_id)

    def for_profile(self, profile: str) -> list[type[SecurityCheck]]:
        return [c for c in self.all() if c().applies_to_profile(profile)]


registry = CheckRegistry()


def register(check_cls: type[SecurityCheck]) -> type[SecurityCheck]:
    """Decorator to register a check with the global registry."""
    return registry.register(check_cls)
