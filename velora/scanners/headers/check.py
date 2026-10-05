"""Security-header and server-version-disclosure checks (passive)."""
from __future__ import annotations

import re

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

# header -> (severity, human description, remediation)
_EXPECTED_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy is missing; the browser has no policy restricting "
        "script/style/frame sources, increasing XSS and data-injection impact.",
        "Define a restrictive Content-Security-Policy (e.g. default-src 'self') and tune it.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS) is missing; clients may connect over plaintext "
        "HTTP and are exposed to protocol-downgrade / SSL-strip attacks.",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options is missing; browsers may MIME-sniff responses.",
        "Send X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options (or a CSP frame-ancestors directive) is missing; the page may be "
        "framed, enabling clickjacking.",
        "Send X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Referrer-Policy is missing; full URLs may leak in the Referer header.",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Permissions-Policy is missing; powerful browser features are not restricted.",
        "Send a Permissions-Policy limiting features your app does not use.",
    ),
}

_HSTS_ONLY_HTTPS = "strict-transport-security"

_REF = [
    "https://owasp.org/www-project-secure-headers/",
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
]


@register
class SecurityHeadersCheck(SecurityCheck):
    id = "headers.security_headers"
    name = "Missing security headers"
    description = "Detects missing HTTP response security headers on the base response."
    category = "configuration"
    severity = Severity.MEDIUM
    safe_mode = True
    references = _REF
    evidence_schema = {"missing": "list[str]", "present": "list[str]"}

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        resp = await ctx.client.safe_get(ctx.target)
        if resp is None or resp.error:
            return []
        is_https = ctx.target.lower().startswith("https://")
        present = {k.lower() for k in resp.headers}
        outputs: list[CheckOutput] = []
        for header, (sev, desc, remediation) in _EXPECTED_HEADERS.items():
            if header == _HSTS_ONLY_HTTPS and not is_https:
                continue  # HSTS is only meaningful over HTTPS
            if header in present:
                continue
            ev = EvidenceItem(
                test_name=self.id,
                request=resp.evidence_request(),
                response=resp.evidence_response(),
                headers={k: v for k, v in resp.headers.items()},
                status_code=resp.status_code,
                content_type=resp.content_type,
                response_size=resp.response_size,
                excerpt=f"Response headers did not include '{header}'.",
                confidence=Confidence.CERTAIN.score,
            )
            outputs.append(
                CheckOutput(
                    title=f"Missing security header: {header}",
                    category=self.category,
                    severity=sev,
                    confidence=Confidence.CERTAIN,
                    endpoint=resp.final_url,
                    description=desc,
                    impact="Weakens defense-in-depth against common client-side attacks.",
                    remediation=remediation,
                    references=self.references,
                    evidence=[ev],
                )
            )
        return outputs


_VERSION_RE = re.compile(r"/\d")


@register
class ServerVersionDisclosureCheck(SecurityCheck):
    id = "headers.server_version"
    name = "Server / technology version disclosure"
    description = "Flags Server / X-Powered-By / X-AspNet-Version headers exposing versions."
    category = "information_disclosure"
    severity = Severity.LOW
    safe_mode = True
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        resp = await ctx.client.safe_get(ctx.target)
        if resp is None or resp.error:
            return []
        outputs: list[CheckOutput] = []
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            value = resp.header(header)
            if not value:
                continue
            discloses_version = bool(_VERSION_RE.search(value))
            sev = Severity.LOW if discloses_version else Severity.INFO
            ev = EvidenceItem(
                test_name=self.id,
                request=resp.evidence_request(),
                response=resp.evidence_response(),
                headers={header: value},
                status_code=resp.status_code,
                excerpt=f"{header}: {value}",
                confidence=Confidence.CERTAIN.score,
            )
            outputs.append(
                CheckOutput(
                    title=f"Version/technology disclosure via '{header}' header",
                    category=self.category,
                    severity=sev,
                    confidence=Confidence.CERTAIN,
                    endpoint=resp.final_url,
                    description=(
                        f"The '{header}' response header advertises server/framework "
                        f"details ('{value}'), aiding an attacker in targeting known issues."
                    ),
                    impact="Assists attackers in fingerprinting and locating version-specific exploits.",
                    remediation=f"Suppress or genericize the '{header}' header.",
                    references=self.references,
                    evidence=[ev],
                )
            )
        return outputs
