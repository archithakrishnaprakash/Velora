"""Example PASSIVE plugin: caching directives on responses that set a session cookie.

A response that establishes a session and is still cacheable can be stored by a shared
cache or a browser's back/forward cache and served to someone else. This plugin reports
that combination. It reads only what the scan already collected — it issues no requests
of its own, which is what makes it PASSIVE.

What it does NOT claim: that a cache actually stored the response, or that anyone
retrieved it. That would need a second observation point, and the plugin says so in the
detection's description rather than asserting impact it has not seen.
"""
from __future__ import annotations

from velora.models.enums import Confidence, Severity
from velora.plugins import PluginMetadata, ScannerType, VeloraPlugin, register_plugin
from velora.scanners.base import CheckOutput, EvidenceItem, ScanContext

#: Directives that keep a response out of shared and private caches.
_SUFFICIENT = ("no-store",)
_SESSION_COOKIE_HINTS = ("session", "sess", "sid", "auth", "token", "jwt")


@register_plugin
class CacheControlOnSessionResponses(VeloraPlugin):
    metadata = PluginMetadata(
        id="example.cache_control",
        name="Caching of session-establishing responses",
        version="1.0.0",
        author="Velora examples",
        description=(
            "Reports responses that set a session-like cookie while remaining "
            "cacheable. Observation only: no cache is probed and no retrieval is "
            "attempted."),
        category="configuration",
        scanner_type=ScannerType.PASSIVE,
        severity=Severity.LOW,
        expected_evidence=("response headers", "set-cookie directive", "cache-control directive"),
        remediation=(
            "Send 'Cache-Control: no-store' on any response that establishes or "
            "refreshes a session, and avoid 'public' on authenticated responses."),
        references=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ),
        cwe_id="CWE-525",
        owasp_category="A05:2021",
    )

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        # PASSIVE: re-read the target only, using the scope-gated client, and rely on
        # the crawl for everything else the scan already fetched.
        urls = [ctx.target]
        if ctx.crawl:
            urls += [e.url for e in ctx.crawl.endpoints if e.url != ctx.target]

        self.check_method("GET")   # refuses anything this plugin did not declare
        outputs: list[CheckOutput] = []
        seen: set[str] = set()
        for url in urls[:25]:
            if url in seen:
                continue
            seen.add(url)
            resp = await ctx.client.safe_get(url)
            if resp is None or resp.error:
                continue

            cookie = resp.header("set-cookie") or ""
            if not cookie:
                continue
            name = cookie.split("=", 1)[0].strip().lower()
            if not any(hint in name for hint in _SESSION_COOKIE_HINTS):
                continue

            directive = (resp.header("cache-control") or "").lower()
            if any(token in directive for token in _SUFFICIENT):
                continue

            outputs.append(CheckOutput(
                title="Session-establishing response is cacheable",
                category=self.metadata.category,
                severity=self.metadata.severity,
                confidence=Confidence.FIRM,
                endpoint=url,
                description=(
                    f"The response to {url} sets the cookie '{name}' but its "
                    f"Cache-Control directive is "
                    f"{directive or 'absent'}. A shared or private cache is therefore "
                    "permitted to store it. Velora observed the headers only; it did "
                    "not verify that any cache stored or served this response."),
                impact=(
                    "If a shared cache stores the response, a later request from a "
                    "different user could be served the session-bearing copy."),
                remediation=self.metadata.remediation,
                references=list(self.metadata.references),
                evidence=[EvidenceItem(
                    test_name=self.metadata.id,
                    request=resp.evidence_request(),
                    response=resp.evidence_response(),
                    headers={"cache-control": directive or "(absent)",
                             "set-cookie": f"{name}=<redacted>"},
                    status_code=resp.status_code,
                    excerpt=f"set-cookie: {name}=<redacted>; cache-control: "
                            f"{directive or '(absent)'}",
                    confidence=Confidence.FIRM.score)],
            ))
        return outputs
