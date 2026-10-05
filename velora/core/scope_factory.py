"""Build scope-engine ScopePolicy objects from stored records / targets / settings."""
from __future__ import annotations

from urllib.parse import urlsplit

from ..config.settings import Settings
from ..models.domain import ScopePolicyRecord, Target
from ..models.enums import AuthorizationStatus
from ..scope.policy import RedirectPolicy, ScopePolicy
from ..utils.urlutil import effective_port, normalize_host


def policy_from_record(record: ScopePolicyRecord) -> ScopePolicy:
    return ScopePolicy(
        allowed_domains=record.allowed_domains,
        allowed_ips=record.allowed_ips,
        allowed_ports=record.allowed_ports,
        allowed_schemes=record.allowed_schemes,
        excluded_paths=record.excluded_paths,
        excluded_domains=record.excluded_domains,
        max_requests=record.max_requests,
        max_concurrency=record.max_concurrency,
        request_delay=record.request_delay,
        timeout=record.timeout,
        redirect_policy=RedirectPolicy(record.redirect_policy),
        allow_private_targets=record.allow_private_targets,
    )


def default_policy_for_target(target: Target, settings: Settings) -> ScopePolicy:
    """Derive a conservative default scope from a target URL and settings defaults.

    The target's own host is the only allowed domain. Private targets are allowed only for
    LAB_ONLY targets (an explicit lab authorization).
    """
    parts = urlsplit(target.url)
    host = normalize_host(parts.hostname or "")
    scheme = parts.scheme or "http"
    port = effective_port(scheme, parts.port)
    d = settings.scope
    ports = sorted(set(d.allowed_ports) | ({port} if port else set()))
    is_lab = target.authorization_status == AuthorizationStatus.LAB_ONLY
    return ScopePolicy(
        allowed_domains=[host] if host and not _is_ip(host) else [],
        allowed_ips=[host] if _is_ip(host) else [],
        allowed_ports=ports,
        allowed_schemes=d.allowed_schemes,
        max_requests=d.max_requests,
        max_concurrency=d.max_concurrency,
        request_delay=d.request_delay,
        timeout=d.timeout,
        redirect_policy=RedirectPolicy(d.redirect_policy),
        allow_private_targets=d.allow_private_targets or is_lab,
    )


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
