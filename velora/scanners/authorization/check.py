"""Basic authorization consistency indicators (passive, conservative).

This check does NOT attempt privilege escalation. It only observes that paths whose
names suggest privileged functionality returned success without any authentication being
supplied, and reports them as indicators that REQUIRE manual validation.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

_SENSITIVE_HINTS = ("admin", "manage", "config", "settings", "internal", "dashboard",
                    "debug", "console", "backup")


@register
class AuthorizationConsistencyCheck(SecurityCheck):
    id = "authz.consistency"
    name = "Authorization consistency indicators"
    description = "Flags privileged-looking paths reachable without authentication (needs review)."
    category = "authorization"
    severity = Severity.MEDIUM
    safe_mode = True
    references = ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        if not ctx.crawl:
            return []
        outputs: list[CheckOutput] = []
        for ep in ctx.crawl.endpoints:
            path = urlsplit(ep.url).path.lower()
            if ep.status_code == 200 and any(h in path for h in _SENSITIVE_HINTS):
                outputs.append(
                    CheckOutput(
                        title=f"Privileged-looking path reachable without authentication: {path}",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        endpoint=ep.url,
                        description=(
                            f"The path '{path}' returned HTTP 200 during an unauthenticated crawl "
                            "and its name suggests privileged functionality. This is an INDICATOR "
                            "that requires manual validation — it may be an intentionally public "
                            "page or a genuine access-control gap."
                        ),
                        impact="Potential broken access control (OWASP A01) — must be verified.",
                        remediation=(
                            "Verify the endpoint enforces authentication/authorization; "
                            "restrict access if it exposes privileged functionality."
                        ),
                        references=self.references,
                        evidence=[EvidenceItem(test_name=self.id,
                                               excerpt=f"GET {ep.url} -> {ep.status_code} (unauthenticated)",
                                               status_code=ep.status_code,
                                               confidence=Confidence.TENTATIVE.score)],
                    )
                )
        return outputs
