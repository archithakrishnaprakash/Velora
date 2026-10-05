"""Reconnaissance engine.

Performs only safe, low-touch collection against in-scope targets: base-page fetch,
headers/cookies, HTTP method enumeration via OPTIONS, robots.txt and sitemap.xml,
security.txt, TLS metadata, and DNS resolution. Every request is gated by the
ScopeManager. It does NOT brute-force paths or enumerate the public internet.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..core.http import HttpResponse, SafeHTTPClient
from ..fingerprint import FingerprintEngine, TechDetection
from ..utils.errors import ScopeViolation
from ..utils.logging import get_logger
from ..utils.urlutil import normalize_host

log = get_logger("recon")

COMMON_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"]


@dataclass
class ReconResult:
    target: str
    base_status: int | None = None
    server: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)
    tls: dict[str, object] = field(default_factory=dict)
    allowed_methods: list[str] = field(default_factory=list)
    robots: str | None = None
    sitemap_urls: list[str] = field(default_factory=list)
    security_txt: bool = False
    technologies: list[TechDetection] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class ReconEngine:
    def __init__(self, client: SafeHTTPClient, fingerprinter: FingerprintEngine | None = None) -> None:
        self.client = client
        self.fp = fingerprinter or FingerprintEngine()

    async def run(self, target: str) -> ReconResult:
        parts = urlsplit(target)
        host = normalize_host(parts.hostname or "")
        result = ReconResult(target=target)

        result.dns = self._resolve(host)
        if parts.scheme == "https":
            result.tls = self._tls_info(host, parts.port or 443)

        base = await self.client.safe_get(target)
        if base is not None:
            result.base_status = base.status_code
            result.headers = base.headers
            result.server = base.header("server")
            result.cookies = _split_cookies(base)
            result.technologies = self.fp.analyze(base, result.cookies)

        result.allowed_methods = await self._methods(target)
        result.robots, result.sitemap_urls = await self._robots(target)
        result.security_txt = await self._security_txt(target)
        return result

    def _resolve(self, host: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {"A": [], "AAAA": []}
        if not host:
            return out
        try:
            for info in socket.getaddrinfo(host, None):
                family, addr = info[0], info[4][0]
                if family == socket.AF_INET and addr not in out["A"]:
                    out["A"].append(addr)
                elif family == socket.AF_INET6 and addr not in out["AAAA"]:
                    out["AAAA"].append(addr)
        except socket.gaierror:
            pass
        return out

    def _tls_info(self, host: str, port: int) -> dict[str, object]:
        info: dict[str, object] = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.client.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info["protocol"] = ssock.version()
                    info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                    if cert:
                        info["subject"] = _flatten_name(cert.get("subject"))
                        info["issuer"] = _flatten_name(cert.get("issuer"))
                        info["not_after"] = cert.get("notAfter")
                        info["expired"] = _cert_expired(cert.get("notAfter"))
        except (ssl.SSLError, OSError, ValueError) as exc:
            info["error"] = str(exc)
        return info

    async def _methods(self, target: str) -> list[str]:
        allowed: list[str] = []
        try:
            resp = await self.client.options(target)
        except ScopeViolation:
            return allowed
        allow = resp.header("allow")
        if allow:
            allowed = [m.strip().upper() for m in allow.split(",") if m.strip()]
        return allowed

    async def _robots(self, target: str) -> tuple[str | None, list[str]]:
        base = _origin(target)
        resp = await self.client.safe_get(base + "/robots.txt")
        if resp is None or not resp.ok or "html" in resp.content_type:
            return None, []
        sitemaps = [
            line.split(":", 1)[1].strip()
            for line in resp.body.splitlines()
            if line.lower().startswith("sitemap:")
        ]
        return resp.body, sitemaps

    async def _security_txt(self, target: str) -> bool:
        base = _origin(target)
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = await self.client.safe_get(base + path)
            if resp is not None and resp.ok and "html" not in resp.content_type:
                return True
        return False


def _split_cookies(resp: HttpResponse) -> list[str]:
    raw = resp.header("set-cookie")
    if not raw:
        return []
    return [c.strip() for c in raw.split("\n") if c.strip()] or [raw]


def _origin(url: str) -> str:
    p = urlsplit(url)
    netloc = p.netloc
    return f"{p.scheme}://{netloc}"


def _flatten_name(name: object) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:  # type: ignore[union-attr]
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _cert_expired(not_after: str | None) -> bool | None:
    if not not_after:
        return None
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)
    except ValueError:
        return None
