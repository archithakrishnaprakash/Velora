"""Shared CLI helpers used by both the 1.x commands and the 2.0 command groups."""
from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

import click

from ..config.settings import Settings
from ..models.domain import ScopePolicyRecord, Target
from ..models.enums import AuthorizationStatus
from ..scope.manager import ScopeManager
from ..scope.policy import ScopePolicy
from ..utils.urlutil import normalize_host
from .context import AppContext

AUTH_HELP = "Confirm you are authorized to test this target (required)."


def app_ctx(click_ctx: click.Context) -> AppContext:
    """Return the AppContext attached to the root click context."""
    obj = click_ctx.obj
    if obj is None and click_ctx.parent is not None:
        obj = click_ctx.parent.obj
    return obj


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def require_authorization(authorized: bool) -> None:
    """Uniform authorization gate for every command that sends requests."""
    if not authorized:
        raise click.ClickException(
            "pass --i-am-authorized to confirm you are permitted to test this target"
        )


def adhoc_scope(
    target_url: str,
    scope: tuple[str, ...],
    allow_private: bool,
    ports: tuple[int, ...],
    max_requests: int,
) -> ScopePolicy:
    """Build a conservative ad-hoc ScopePolicy for a one-off command."""
    parts = urlsplit(target_url)
    host = normalize_host(parts.hostname or "")
    domains = list(scope) or ([host] if host and not is_ip(host) else [])
    ips = [host] if is_ip(host) else []
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return ScopePolicy(
        allowed_domains=[normalize_host(d) for d in domains],
        allowed_ips=ips,
        allowed_ports=sorted(set(ports) | {port, 80, 443}),
        allow_private_targets=allow_private,
        max_requests=max_requests,
    )


def scope_manager_for(
    target_url: str,
    scope: tuple[str, ...],
    allow_private: bool,
    settings: Settings,
    max_requests: int = 200,
    scan_id: str | None = None,
) -> ScopeManager:
    policy = adhoc_scope(target_url, scope, allow_private,
                         tuple(settings.scope.allowed_ports), max_requests)
    return ScopeManager(policy, scan_id=scan_id)


def resolve_or_create_target(
    app: AppContext,
    target_arg: str,
    scope: tuple[str, ...],
    allow_private: bool,
    operator: str,
    ports: tuple[int, ...],
    engagement_id: str | None = None,
) -> Target:
    """Resolve a stored target by id/name, else create one from a URL."""
    repo = app.repo
    existing = repo.get_target(target_arg) or repo.get_target_by_name(target_arg)
    if existing:
        return existing
    if not target_arg.lower().startswith(("http://", "https://")):
        raise click.BadParameter("target must be a stored id/name or a full http(s) URL")
    parts = urlsplit(target_arg)
    host = normalize_host(parts.hostname or "")
    domains = list(scope) or ([host] if host and not is_ip(host) else [])
    ips = [host] if is_ip(host) else []
    port = parts.port or (443 if parts.scheme == "https" else 80)
    rec = ScopePolicyRecord(
        allowed_domains=[normalize_host(d) for d in domains],
        allowed_ips=ips,
        allowed_ports=sorted(set(ports) | {port, 80, 443}),
        allow_private_targets=allow_private,
    )
    repo.add_scope(rec)
    auth = AuthorizationStatus.LAB_ONLY if allow_private else AuthorizationStatus.AUTHORIZED
    target = Target(
        name=host or target_arg, url=target_arg, owner=operator,
        authorization_status=auth, scope_policy_id=rec.id,
        engagement_id=engagement_id,
        authorization_note="created via CLI with explicit authorization ack",
    )
    repo.add_target(target)
    return target


def parse_headers(pairs: tuple[str, ...]) -> dict[str, str]:
    """Parse repeated ``--header 'Name: value'`` options."""
    out: dict[str, str] = {}
    for raw in pairs:
        if ":" not in raw:
            raise click.BadParameter(f"header must be 'Name: value', got: {raw}")
        name, _, value = raw.partition(":")
        out[name.strip()] = value.strip()
    return out


def echo_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def run_async(coro):
    """Run a coroutine from a synchronous click command."""
    return asyncio.run(coro)
