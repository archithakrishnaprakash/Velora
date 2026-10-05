"""Example ACTIVE_SAFE plugin: reachability of well-known metadata paths.

This plugin issues extra plain GETs — which is what makes it ACTIVE_SAFE rather than
PASSIVE — for a configurable list of conventional paths. Every request goes through the
scan's scope-gated client, so a path that resolves outside scope is blocked and audited
like any other request; the plugin has no way around that and does not try.

It reports what was *reachable*. Reachability is not a vulnerability: `/robots.txt` is
supposed to be there. The detection says what was observed and leaves the judgement to
a reviewer, which is why its severity is informational.

It also demonstrates the SDK's configuration schema: unknown keys are refused at load
time rather than silently ignored, and every value is type- and range-checked.
"""
from __future__ import annotations

from urllib.parse import urljoin

from velora.models.enums import Confidence, Severity
from velora.plugins import (
    ConfigField,
    PluginMetadata,
    ScannerType,
    VeloraPlugin,
    register_plugin,
)
from velora.scanners.base import CheckOutput, EvidenceItem, ScanContext

#: Conventional, non-sensitive metadata paths. Nothing here is an exploit attempt.
DEFAULT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/humans.txt",
]

#: Paths that would be a content-discovery sweep rather than a metadata read.
_REFUSED_PREFIXES = ("/admin", "/backup", "/.git", "/.env", "/config")


@register_plugin
class WellKnownPathsPlugin(VeloraPlugin):
    metadata = PluginMetadata(
        id="example.wellknown_paths",
        name="Well-known metadata paths",
        version="1.1.0",
        author="Velora examples",
        description=(
            "Reports which conventional metadata paths are reachable. Reachability is "
            "recorded as an observation, not as a weakness."),
        category="information_disclosure",
        scanner_type=ScannerType.ACTIVE_SAFE,
        severity=Severity.INFO,
        allowed_methods=("GET",),
        expected_evidence=("request url", "response status", "content type"),
        remediation=(
            "Publish /.well-known/security.txt with a contact address, and confirm that "
            "every other reachable metadata path is intended to be public."),
        references=("https://www.rfc-editor.org/rfc/rfc9116",),
        cwe_id="UNKNOWN",
        owasp_category="UNKNOWN",
        config_schema={
            "paths": ConfigField(
                type="list[str]", default=None,
                description="Absolute paths to request. Defaults to the built-in list."),
            "max_paths": ConfigField(
                type="int", default=10, minimum=1, maximum=25,
                description="Upper bound on requests this plugin issues."),
            "report_missing": ConfigField(
                type="bool", default=False,
                description="Also record paths that returned 404."),
        },
    )

    def on_configure(self) -> None:
        paths = self.config.get("paths") or DEFAULT_PATHS
        cleaned: list[str] = []
        for path in paths:
            if not path.startswith("/"):
                continue                      # relative paths could escape the origin
            if path.lower().startswith(_REFUSED_PREFIXES):
                # Keep this plugin a metadata reader, not a content-discovery sweep.
                continue
            cleaned.append(path)
        self._paths = cleaned[: self.config["max_paths"]]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        self.check_method("GET")
        reachable: list[tuple[str, int, str]] = []
        missing: list[str] = []

        for path in getattr(self, "_paths", DEFAULT_PATHS[:10]):
            url = urljoin(ctx.target, path)
            resp = await ctx.client.safe_get(url)   # None when scope blocks it
            if resp is None or resp.error:
                continue
            if 200 <= resp.status_code < 300:
                reachable.append((url, resp.status_code, resp.content_type))
            elif resp.status_code == 404:
                missing.append(url)

        if not reachable and not (missing and self.config.get("report_missing")):
            return []

        lines = [f"{url} -> {status} ({ctype or 'no content-type'})"
                 for url, status, ctype in reachable]
        if self.config.get("report_missing"):
            lines += [f"{url} -> 404" for url in missing]

        return [CheckOutput(
            title=f"{len(reachable)} well-known metadata path(s) reachable",
            category=self.metadata.category,
            severity=self.metadata.severity,
            confidence=Confidence.CERTAIN,
            endpoint=ctx.target,
            description=(
                "The following conventional metadata paths responded within scope. "
                "Their presence is expected for most sites and is recorded here as an "
                "attack-surface observation, not as a weakness:\n" + "\n".join(lines)),
            impact=(
                "No impact is claimed. Review each path to confirm its contents are "
                "intended to be public."),
            remediation=self.metadata.remediation,
            references=list(self.metadata.references),
            evidence=[EvidenceItem(
                test_name=self.metadata.id,
                request={"method": "GET", "paths": [u for u, _, _ in reachable]},
                response={"statuses": [s for _, s, _ in reachable]},
                excerpt="\n".join(lines)[:600],
                confidence=Confidence.CERTAIN.score)],
        )]
