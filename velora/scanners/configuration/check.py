"""Configuration checks: risky HTTP methods, directory exposure, security.txt availability."""
from __future__ import annotations

from urllib.parse import urlsplit

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

_RISKY_METHODS = {
    "PUT": (Severity.MEDIUM, "PUT may allow uploading/overwriting resources."),
    "DELETE": (Severity.MEDIUM, "DELETE may allow removing resources."),
    "TRACE": (Severity.LOW, "TRACE can enable Cross-Site Tracing (XST)."),
    "CONNECT": (Severity.LOW, "CONNECT may allow the server to be used as a proxy."),
    "PATCH": (Severity.LOW, "PATCH may allow partial resource modification."),
}


@register
class HttpMethodsCheck(SecurityCheck):
    id = "config.http_methods"
    name = "HTTP methods"
    description = "Reports risky HTTP methods advertised via OPTIONS/Allow."
    category = "configuration"
    severity = Severity.LOW
    safe_mode = True
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        methods = list(ctx.recon.allowed_methods) if ctx.recon else []
        if not methods:
            resp = await ctx.client.options(ctx.target)
            allow = resp.header("allow") if resp and not resp.error else None
            if allow:
                methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if not methods:
            return []
        risky = [m for m in methods if m in _RISKY_METHODS]
        if not risky:
            return []
        sev = max((_RISKY_METHODS[m][0] for m in risky), key=lambda s: s.rank)
        detail = "; ".join(f"{m}: {_RISKY_METHODS[m][1]}" for m in risky)
        return [
            CheckOutput(
                title=f"Risky HTTP methods enabled: {', '.join(risky)}",
                category=self.category,
                severity=sev,
                confidence=Confidence.FIRM,
                endpoint=ctx.target,
                description=f"The server advertises potentially dangerous methods. {detail}",
                impact="May permit unintended write/delete/proxy behavior depending on config.",
                remediation="Disable HTTP methods the application does not require.",
                references=self.references,
                evidence=[EvidenceItem(test_name=self.id, excerpt=f"Allow: {', '.join(methods)}",
                                       confidence=Confidence.FIRM.score)],
            )
        ]


@register
class DirectoryExposureCheck(SecurityCheck):
    id = "config.directory_exposure"
    name = "Directory listing exposure indicators"
    description = "Detects auto-index 'Index of /' directory listings in responses."
    category = "configuration"
    severity = Severity.MEDIUM
    safe_mode = True
    references = ["https://owasp.org/www-community/vulnerabilities/Directory_indexing"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        urls = [ctx.target]
        if ctx.crawl:
            urls += [e.url for e in ctx.crawl.endpoints if e.url != ctx.target]
        outputs: list[CheckOutput] = []
        seen: set[str] = set()
        for url in urls[:20]:
            resp = await ctx.client.safe_get(url)
            if resp is None or resp.error:
                continue
            if "<title>Index of /" in resp.body or "Directory listing for" in resp.body:
                if resp.final_url in seen:
                    continue
                seen.add(resp.final_url)
                outputs.append(
                    CheckOutput(
                        title="Directory listing enabled",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        endpoint=resp.final_url,
                        description="An auto-generated directory index is exposed, revealing file names.",
                        impact="Exposes file/directory structure and potentially sensitive files.",
                        remediation="Disable automatic directory indexing (e.g. Options -Indexes).",
                        references=self.references,
                        evidence=[EvidenceItem(test_name=self.id, excerpt="Directory index page detected",
                                               status_code=resp.status_code,
                                               confidence=Confidence.FIRM.score)],
                    )
                )
        return outputs


@register
class SecurityTxtCheck(SecurityCheck):
    id = "config.security_txt"
    name = "security.txt availability"
    description = "Informational: whether a security.txt disclosure policy is published."
    category = "configuration"
    severity = Severity.INFO
    safe_mode = True
    references = ["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        present = ctx.recon.security_txt if ctx.recon else False
        if not present:
            origin = _origin(ctx.target)
            for path in ("/.well-known/security.txt", "/security.txt"):
                resp = await ctx.client.safe_get(origin + path)
                if resp and resp.ok and "html" not in resp.content_type:
                    present = True
                    break
        if present:
            return []
        return [
            CheckOutput(
                title="No security.txt disclosure policy published",
                category=self.category,
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                endpoint=_origin(ctx.target) + "/.well-known/security.txt",
                description="No security.txt file was found; researchers lack a defined disclosure channel.",
                impact="Not a vulnerability; a missing best-practice for coordinated disclosure.",
                remediation="Publish /.well-known/security.txt per RFC 9116.",
                references=self.references,
                evidence=[EvidenceItem(test_name=self.id, excerpt="security.txt not found",
                                       confidence=Confidence.CERTAIN.score)],
            )
        ]


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
