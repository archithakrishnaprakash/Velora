"""Authentication configuration indicators (passive)."""
from __future__ import annotations

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register


@register
class AuthenticationIndicatorsCheck(SecurityCheck):
    id = "auth.indicators"
    name = "Authentication configuration indicators"
    description = "Flags credential forms served over HTTP and forms without CSRF tokens."
    category = "authentication"
    severity = Severity.MEDIUM
    safe_mode = True
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        if not ctx.crawl:
            return []
        outputs: list[CheckOutput] = []
        for form in ctx.crawl.forms:
            inputs = form.get("inputs", [])
            names = [(i.get("name") or "").lower() for i in inputs]
            types = [(i.get("type") or "").lower() for i in inputs]
            has_password = "password" in types or any("pass" in n for n in names)
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            if has_password and action.lower().startswith("http://"):
                outputs.append(
                    self._make(
                        title="Credentials submitted over plaintext HTTP",
                        severity=Severity.HIGH,
                        endpoint=action,
                        description=(
                            "A form containing a password field submits over HTTP, exposing "
                            "credentials to network eavesdroppers."
                        ),
                        remediation="Serve and submit all authentication forms exclusively over HTTPS.",
                        excerpt=f"{method} {action} contains a password field over HTTP.",
                    )
                )
            if has_password and method == "POST":
                token_like = any(
                    any(t in n for t in ("csrf", "token", "authenticity", "nonce"))
                    for n in names
                )
                if not token_like:
                    outputs.append(
                        self._make(
                            title="Authentication form without an apparent CSRF token",
                            severity=Severity.LOW,
                            endpoint=action,
                            description=(
                                "A POST authentication form has no field that looks like a CSRF "
                                "token. This is an indicator only and requires manual validation "
                                "(the app may use header-based or cookie-based CSRF defenses)."
                            ),
                            remediation="Ensure state-changing forms are protected against CSRF.",
                            excerpt=f"Form inputs: {[i.get('name') for i in inputs]}",
                            confidence=Confidence.TENTATIVE,
                        )
                    )
        return outputs

    def _make(self, *, title, severity, endpoint, description, remediation, excerpt,
              confidence=Confidence.FIRM):
        return CheckOutput(
            title=title, category=self.category, severity=severity, confidence=confidence,
            endpoint=endpoint, method="POST", description=description,
            impact="Affects the confidentiality/integrity of authentication.",
            remediation=remediation, references=self.references,
            evidence=[EvidenceItem(test_name=self.id, excerpt=excerpt, confidence=confidence.score)],
        )
