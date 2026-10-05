"""ScopeManager — runtime enforcement of a ScopePolicy with SSRF protection.

Every outbound request in Velora is gated by ``ScopeManager.authorize(url)``.
The manager performs, in order:

  1. Scheme allow-list check.
  2. Port allow-list check.
  3. Path exclusion check.
  4. Host-in-scope check (deny by default).
  5. SSRF / address-safety check: the host is resolved to IP address(es) and every
     resolved address must be a public, non-reserved address unless private targets
     are explicitly allowed. Cloud metadata addresses are always blocked.
  6. Request-budget check (max_requests).

A blocked request raises ``ScopeViolation`` and emits a SECURITY log event. The
manager never silently continues.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from ..utils.errors import RateLimitExceeded, ScopeViolation
from ..utils.logging import get_logger
from ..utils.redaction import redact_url
from ..utils.urlutil import effective_port, normalize_host, same_origin
from .policy import RedirectPolicy, ScopePolicy

log = get_logger("scope")

# Addresses that must never be contacted (cloud instance metadata services).
_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # AWS/GCP/Azure IMDS
        "fd00:ec2::254",  # AWS IMDSv6
        "100.100.100.200",  # Alibaba Cloud
    }
)

# Resolver signature: host -> list of IP strings. Injectable for testing.
Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of a scope check."""

    allowed: bool
    url: str
    reason: str
    resolved_ips: tuple[str, ...] = ()

    def raise_if_blocked(self) -> "ScopeDecision":
        if not self.allowed:
            raise ScopeViolation(self.url, self.reason)
        return self


class ScopeManager:
    """Thread-safe enforcement of a single ScopePolicy for a scan."""

    def __init__(
        self,
        policy: ScopePolicy,
        *,
        resolver: Resolver | None = None,
        scan_id: str | None = None,
    ) -> None:
        self.policy = policy
        self._resolver = resolver or _default_resolver
        self._scan_id = scan_id
        self._request_count = 0
        self._blocked_count = 0
        self._lock = threading.Lock()

    # ---- counters -------------------------------------------------------
    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    def remaining_budget(self) -> int:
        return max(0, self.policy.max_requests - self._request_count)

    # ---- core checks ----------------------------------------------------
    def check(self, url: str) -> ScopeDecision:
        """Return a ScopeDecision without consuming budget or raising."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return ScopeDecision(False, url, "malformed-url")

        scheme = (parts.scheme or "").lower()
        host = normalize_host(parts.hostname or "")

        if not scheme or not host:
            return ScopeDecision(False, url, "missing-scheme-or-host")
        if scheme not in self.policy.allowed_schemes:
            return ScopeDecision(False, url, f"scheme-not-allowed:{scheme}")

        port = effective_port(scheme, parts.port)
        if port is not None and port not in self.policy.allowed_ports:
            return ScopeDecision(False, url, f"port-not-allowed:{port}")

        if self.policy.path_excluded(parts.path or "/"):
            return ScopeDecision(False, url, f"path-excluded:{parts.path}")

        # Determine whether the host is a literal IP or a name.
        literal_ip = _as_ip(host)
        if literal_ip is not None:
            ip_decision = self._check_addresses(url, host, [str(literal_ip)])
            if not ip_decision.allowed:
                return ip_decision
            if not self._ip_in_scope(literal_ip):
                return ScopeDecision(False, url, f"ip-not-in-scope:{host}")
            return ScopeDecision(True, url, "in-scope-ip", (str(literal_ip),))

        # Named host: must match an allowed domain.
        if not self.policy.domain_in_scope(host):
            return ScopeDecision(False, url, f"domain-not-in-scope:{host}")

        # SSRF protection: resolve and validate every address.
        resolved = self._resolver(host)
        if not resolved:
            return ScopeDecision(False, url, f"dns-resolution-failed:{host}")
        addr_decision = self._check_addresses(url, host, resolved)
        if not addr_decision.allowed:
            return addr_decision
        # When the operator pinned allowed IPs/CIDRs, they constrain a named host too.
        # Without this, a domain in scope that resolves (or is made to resolve) to an
        # address outside the pinned range would still be reached.
        if self.policy.allowed_ips:
            for addr in resolved:
                ip = _as_ip(addr)
                if ip is None or not self._ip_in_scope(ip):
                    return ScopeDecision(
                        False, url, f"resolved-address-outside-allowed-ips:{addr}")
        return ScopeDecision(True, url, "in-scope", tuple(resolved))

    def _check_addresses(self, url: str, host: str, addresses: list[str]) -> ScopeDecision:
        """SSRF guard: reject metadata and (unless allowed) private/reserved IPs."""
        for addr in addresses:
            ip = _as_ip(addr)
            if ip is None:
                return ScopeDecision(False, url, f"unparseable-address:{addr}")
            # Link-local is where cloud metadata services live, on both families.
            # It is blocked even in lab mode, exactly like 169.254.0.0/16 on IPv4:
            # allowing a private lab target is not a reason to expose IMDS.
            if str(ip) in _METADATA_ADDRESSES or (
                ip.version == 4 and str(ip).startswith("169.254.")
            ) or (ip.version == 6 and ip.is_link_local):
                if self.policy.block_cloud_metadata or _is_reserved(ip):
                    return ScopeDecision(False, url, f"metadata-address-blocked:{addr}")
            if _is_dangerous(ip) and not self.policy.allow_private_targets:
                return ScopeDecision(False, url, f"private-or-reserved-address-blocked:{addr}")
        return ScopeDecision(True, url, "addresses-ok", tuple(addresses))

    def _ip_in_scope(self, ip: ipaddress._BaseAddress) -> bool:
        for entry in self.policy.allowed_ips:
            try:
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ipaddress.ip_address(entry) == ip:
                    return True
            except ValueError:
                continue
        return False

    # ---- authorization (consumes budget) --------------------------------
    def authorize(self, url: str) -> ScopeDecision:
        """Check ``url``, consume one unit of request budget, and raise if blocked.

        Must be called immediately before every outbound request.
        """
        with self._lock:
            if self._request_count >= self.policy.max_requests:
                raise RateLimitExceeded(
                    f"request budget exhausted ({self.policy.max_requests})"
                )
            decision = self.check(url)
            if not decision.allowed:
                self._blocked_count += 1
                # The URL is redacted before it reaches the log: a blocked request is
                # often the one carrying a token in its query string, and the audit
                # trail must record the attempt without recording the credential.
                log.security(
                    "OUT_OF_SCOPE_REQUEST_BLOCKED url=%s reason=%s scan=%s",
                    redact_url(url),
                    decision.reason,
                    self._scan_id or "-",
                )
                decision.raise_if_blocked()
            self._request_count += 1
            return decision

    def check_redirect(self, from_url: str, to_url: str) -> ScopeDecision:
        """Apply the redirect policy to a Location header target."""
        policy = self.policy.redirect_policy
        if policy == RedirectPolicy.NEVER:
            return ScopeDecision(False, to_url, "redirects-disabled")
        if policy == RedirectPolicy.SAME_ORIGIN and not same_origin(from_url, to_url):
            return ScopeDecision(False, to_url, "redirect-crosses-origin")
        # SAME_SCOPE (and same-origin that passed) still run the full scope check.
        decision = self.check(to_url)
        if not decision.allowed:
            log.security(
                "OUT_OF_SCOPE_REDIRECT_BLOCKED from=%s to=%s reason=%s",
                from_url,
                to_url,
                decision.reason,
            )
        return decision


def _as_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_reserved(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_reserved or ip.is_multicast or ip.is_unspecified or getattr(ip, "is_link_local", False)
    )


def _is_dangerous(ip: ipaddress._BaseAddress) -> bool:
    """True for addresses that should not be reached in a normal authorized web test."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )
