"""TLS configuration check (passive, read-only handshake via recon data or a probe)."""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit

from ...models.enums import Confidence, Severity
from ..base import CheckOutput, EvidenceItem, ScanContext, SecurityCheck, register

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@register
class TLSConfigurationCheck(SecurityCheck):
    id = "tls.configuration"
    name = "TLS configuration"
    description = "Reports negotiated TLS protocol/cipher and certificate validity issues."
    category = "tls"
    severity = Severity.MEDIUM
    safe_mode = True
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ]

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        parts = urlsplit(ctx.target)
        if parts.scheme != "https":
            return []  # nothing to assess for plaintext HTTP here
        host = parts.hostname or ""
        port = parts.port or 443

        info = ctx.recon.tls if (ctx.recon and ctx.recon.tls) else self._probe(host, port)
        if not info or info.get("error"):
            return []

        outputs: list[CheckOutput] = []
        protocol = str(info.get("protocol") or "")
        if protocol in _WEAK_PROTOCOLS:
            outputs.append(
                self._make(
                    title=f"Weak TLS protocol negotiated: {protocol}",
                    severity=Severity.HIGH,
                    endpoint=ctx.target,
                    description=(
                        f"The server negotiated {protocol}, a deprecated protocol with known "
                        "cryptographic weaknesses."
                    ),
                    remediation="Disable SSLv3/TLS 1.0/1.1; require TLS 1.2+ (prefer TLS 1.3).",
                    excerpt=f"Negotiated protocol: {protocol}; cipher: {info.get('cipher')}",
                )
            )
        if info.get("expired") is True:
            outputs.append(
                self._make(
                    title="Expired TLS certificate",
                    severity=Severity.HIGH,
                    endpoint=ctx.target,
                    description="The presented TLS certificate is expired.",
                    remediation="Renew the certificate and automate renewal.",
                    excerpt=f"notAfter: {info.get('not_after')}",
                )
            )
        # Always emit an informational summary of the TLS posture.
        outputs.append(
            self._make(
                title="TLS configuration summary",
                severity=Severity.INFO,
                endpoint=ctx.target,
                description=(
                    f"Negotiated {protocol or 'unknown'} with cipher "
                    f"{info.get('cipher') or 'unknown'}."
                ),
                remediation="Maintain TLS 1.2+/1.3 with strong ciphers; monitor certificate expiry.",
                excerpt=str({k: info.get(k) for k in ("protocol", "cipher", "issuer", "not_after")}),
                confidence=Confidence.FIRM,
            )
        )
        return outputs

    def _probe(self, host: str, port: int) -> dict:
        info: dict = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    info["protocol"] = ssock.version()
                    info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
        except (ssl.SSLError, OSError, ValueError) as exc:
            info["error"] = str(exc)
        return info

    def _make(
        self,
        *,
        title: str,
        severity: Severity,
        endpoint: str,
        description: str,
        remediation: str,
        excerpt: str,
        confidence: Confidence = Confidence.FIRM,
    ) -> CheckOutput:
        return CheckOutput(
            title=title,
            category=self.category,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            description=description,
            impact="Affects confidentiality/integrity of data in transit.",
            remediation=remediation,
            references=self.references,
            evidence=[EvidenceItem(test_name=self.id, excerpt=excerpt, confidence=confidence.score)],
        )
