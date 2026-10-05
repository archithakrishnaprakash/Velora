"""Information-disclosure indicators (passive).

Two signals:
  1. Secret-like tokens present in responses. The HTTP client redacts secrets before
     returning bodies, so the presence of ``[REDACTED]`` markers is itself evidence that a
     secret pattern was served in the response (the actual value is never stored).
  2. Verbose error / stack-trace / debug output in responses.
A very small, GET-only probe of common sensitive metadata files is included; it does NOT
brute-force paths.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

_ERROR_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"fatal error:|parse error:|warning:\s.+ on line \d+", re.I), "PHP error output"),
    (re.compile(r"SQLSTATE\[|SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR", re.I), "SQL error output"),
    (re.compile(r"Exception in thread|\bat [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)", re.I), "Java stack trace"),
    (re.compile(r"<b>Notice</b>:|Microsoft OLE DB Provider", re.I), "Framework debug output"),
]

# Small, curated, GET-only list of commonly-exposed metadata files (no brute force).
_SENSITIVE_PATHS = ["/.env", "/.git/config", "/server-status", "/.svn/entries", "/phpinfo.php"]


@register
class InformationDisclosureCheck(SecurityCheck):
    id = "infodisc.indicators"
    name = "Information disclosure indicators"
    description = "Detects secrets, verbose errors, and exposed metadata files in responses."
    category = "information_disclosure"
    severity = Severity.MEDIUM
    safe_mode = True
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        outputs: list[CheckOutput] = []
        # 1 + 2: inspect the base page and a few crawled pages.
        urls = [ctx.target]
        if ctx.crawl:
            urls += [e.url for e in ctx.crawl.endpoints if e.url != ctx.target]
        for url in urls[:20]:
            resp = await ctx.client.safe_get(url)
            if resp is None or resp.error:
                continue
            if "[REDACTED]" in resp.body:
                count = resp.body.count("[REDACTED]")
                outputs.append(
                    self._make(
                        title="Possible secret disclosed in response",
                        severity=Severity.HIGH,
                        endpoint=resp.final_url,
                        description=(
                            f"The response contained {count} token(s) matching secret patterns "
                            "(API keys / JWTs / credentials). Values were redacted and not stored."
                        ),
                        remediation="Remove secrets from responses; rotate any exposed credential.",
                        excerpt="Secret pattern(s) detected and redacted in response body.",
                        confidence=Confidence.FIRM,
                    )
                )
            for pattern, label in _ERROR_SIGNATURES:
                if pattern.search(resp.body):
                    outputs.append(
                        self._make(
                            title=f"Verbose error output ({label})",
                            severity=Severity.LOW,
                            endpoint=resp.final_url,
                            description=(
                                f"The response exposes {label}, revealing internal details "
                                "(paths, queries, framework versions) useful to an attacker."
                            ),
                            remediation="Disable debug mode in production; return generic error pages.",
                            excerpt=f"Matched error signature: {label}",
                            confidence=Confidence.FIRM,
                        )
                    )
                    break

        # 3: curated sensitive-path probe (safe, GET-only).
        origin = _origin(ctx.target)
        for path in _SENSITIVE_PATHS:
            resp = await ctx.client.safe_get(origin + path)
            if resp is None or resp.error or resp.status_code != 200:
                continue
            if "html" in resp.content_type and "<html" in resp.body.lower():
                continue  # likely a custom 200 error page, not the raw file
            outputs.append(
                self._make(
                    title=f"Exposed sensitive file: {path}",
                    severity=Severity.HIGH,
                    endpoint=resp.final_url,
                    description=f"The path {path} is accessible and returned non-HTML content.",
                    remediation=f"Block access to {path}; keep such files out of the web root.",
                    excerpt=f"GET {path} -> {resp.status_code} ({resp.content_type})",
                    confidence=Confidence.FIRM,
                )
            )
        return outputs

    def _make(self, *, title, severity, endpoint, description, remediation, excerpt, confidence):
        return CheckOutput(
            title=title,
            category=self.category,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            description=description,
            impact="May reveal sensitive information aiding further attacks.",
            remediation=remediation,
            references=self.references,
            evidence=[EvidenceItem(test_name=self.id, excerpt=excerpt, confidence=confidence.score)],
        )


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
