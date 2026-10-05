"""ScopePolicy — the declarative description of what a scan is authorized to touch.

A policy is intentionally *deny-by-default*: a host must match an allowed domain or
IP entry to be in scope. Wildcards are supported only as leading-label wildcards
(``*.example.com``) which match subdomains but not the apex unless it is also listed.
"""
from __future__ import annotations

import fnmatch
from urllib.parse import unquote
from enum import Enum

from pydantic import BaseModel, Field, field_validator

from ..utils.urlutil import normalize_host


class RedirectPolicy(str, Enum):
    NEVER = "never"
    SAME_ORIGIN = "same-origin"
    SAME_SCOPE = "same-scope"


class ScopePolicy(BaseModel):
    """Authorized scope for a single target/scan."""

    allowed_domains: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    allowed_schemes: list[str] = Field(default_factory=lambda: ["http", "https"])
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)

    max_requests: int = 500
    max_concurrency: int = 5
    request_delay: float = 0.2
    timeout: float = 15.0
    redirect_policy: RedirectPolicy = RedirectPolicy.SAME_SCOPE

    # Safety flags. Private/loopback/link-local targets are blocked unless a lab
    # operator explicitly opts in (e.g. for juice-shop.local on a lab network).
    allow_private_targets: bool = False
    block_cloud_metadata: bool = True  # always keep 169.254.169.254 etc. blocked

    @field_validator("allowed_domains", "excluded_domains", mode="after")
    @classmethod
    def _normalize_domains(cls, domains: list[str]) -> list[str]:
        out: list[str] = []
        for d in domains:
            d = d.strip().lower()
            if not d:
                continue
            if d.startswith("*."):
                out.append("*." + normalize_host(d[2:]))
            else:
                out.append(normalize_host(d))
        return out

    @field_validator("allowed_schemes", mode="after")
    @classmethod
    def _lower_schemes(cls, schemes: list[str]) -> list[str]:
        return [s.strip().lower() for s in schemes if s.strip()]

    def domain_in_scope(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        for pattern in self.excluded_domains:
            if _host_matches(host, pattern):
                return False
        return any(_host_matches(host, pattern) for pattern in self.allowed_domains)

    @staticmethod
    def normalize_path(path: str) -> str:
        """Collapse a URL path to the form an exclusion rule is compared against.

        An exclusion is the operator saying "do not touch this". It must therefore
        survive the obvious spellings of the same path: percent-encoding, ``.`` and
        ``..`` segments, duplicate slashes, and case. ``/x/../admin`` and ``/ADMIN``
        reach the same resource as ``/admin``, so they match the same rule.
        """
        raw = unquote(path or "/")
        # A second decode catches double-encoding (%252e%252e -> %2e%2e -> ..).
        if "%" in raw:
            raw = unquote(raw)
        raw = raw.replace("\\", "/")
        segments: list[str] = []
        for segment in raw.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if segments:
                    segments.pop()
                continue
            segments.append(segment)
        normalized = "/" + "/".join(segments)
        return normalized.lower()

    def path_excluded(self, path: str) -> bool:
        normalized = self.normalize_path(path)
        for pattern in self.excluded_paths:
            rule = self.normalize_path(pattern)
            if normalized == rule or normalized.startswith(rule.rstrip("/") + "/"):
                return True
            if fnmatch.fnmatch(normalized, rule):
                return True
        return False

    def summary(self) -> str:
        return (
            f"domains={self.allowed_domains or '-'} ips={self.allowed_ips or '-'} "
            f"ports={self.allowed_ports} schemes={self.allowed_schemes} "
            f"max_requests={self.max_requests} redirects={self.redirect_policy.value} "
            f"private_allowed={self.allow_private_targets}"
        )


def _host_matches(host: str, pattern: str) -> bool:
    """Match a host against an allowed/excluded domain entry.

    ``example.com`` matches the apex only. ``*.example.com`` matches any subdomain
    but not the apex. Exact matches always win.
    """
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix[1:]
    return False
