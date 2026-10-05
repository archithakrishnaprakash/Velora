"""Loading authorization test plans from YAML.

A plan declares the identities and the resources under test. Credentials are never
written here — only ``secret_ref``, the *name* of an environment variable.

Example::

    identities:
      - name: anonymous
        role: anonymous
      - name: alice
        role: user_a
        secret_ref: VELORA_IDENTITY_ALICE
        auth_scheme: bearer
      - name: admin
        role: admin
        secret_ref: VELORA_IDENTITY_ADMIN

    resources:
      - url: http://lab.local/api/orders/1
        owner: alice
        method: GET
      - url: http://lab.local/admin
        requires_role: admin
      - url: http://lab.local/api/public
        expectations: {anonymous: ALLOW}
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models.domain import Identity
from ..models.enums import IdentityRole
from ..utils.errors import ConfigError
from .matrix import ResourceSpec

# Keys that must never appear in a plan file — credentials belong in the environment.
FORBIDDEN_KEYS = frozenset({"password", "secret", "token", "api_key", "credential", "cookie_value"})


def _check_no_secrets(node: Any, path: str = "") -> None:
    """Refuse to load a plan that embeds credential material."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.lower() in FORBIDDEN_KEYS:
                raise ConfigError(
                    f"plan contains a forbidden key '{key}' at {path or '<root>'}. "
                    "Credentials must be supplied via an environment variable named by "
                    "'secret_ref', never written into the plan file."
                )
            _check_no_secrets(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _check_no_secrets(item, f"{path}[{i}]")


def load_plan(path: str | Path) -> tuple[list[Identity], list[ResourceSpec]]:
    """Parse a plan file into identities and resource specs."""
    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"authorization plan not found: {file_path}")
    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{file_path} must contain a mapping at the top level")

    _check_no_secrets(data)

    identities: list[Identity] = []
    for raw in data.get("identities", []) or []:
        if not isinstance(raw, dict) or "name" not in raw:
            raise ConfigError("each identity requires at least a 'name'")
        try:
            role = IdentityRole(str(raw.get("role", "anonymous")).lower())
        except ValueError as exc:
            valid = [r.value for r in IdentityRole]
            raise ConfigError(f"invalid role '{raw.get('role')}'; valid roles: {valid}") from exc
        identities.append(Identity(
            name=str(raw["name"]),
            role=role,
            description=str(raw.get("description", "")),
            secret_ref=str(raw.get("secret_ref", "")),
            auth_scheme=str(raw.get("auth_scheme", "none" if role == IdentityRole.ANONYMOUS
                                    else "bearer")),
            auth_header_name=str(raw.get("auth_header_name", "Authorization")),
            owned_resource_hints=[str(h) for h in raw.get("owned_resource_hints", []) or []],
        ))

    resources: list[ResourceSpec] = []
    for raw in data.get("resources", []) or []:
        if not isinstance(raw, dict) or "url" not in raw:
            raise ConfigError("each resource requires at least a 'url'")
        requires = raw.get("requires_role")
        required_role = None
        if requires:
            try:
                required_role = IdentityRole(str(requires).lower())
            except ValueError as exc:
                raise ConfigError(f"invalid requires_role '{requires}'") from exc
        expectations = raw.get("expectations", {}) or {}
        if not isinstance(expectations, dict):
            raise ConfigError("'expectations' must be a mapping of identity name -> ALLOW/DENY")
        resources.append(ResourceSpec(
            url=str(raw["url"]),
            method=str(raw.get("method", "GET")).upper(),
            name=str(raw.get("name", "")),
            owner=str(raw["owner"]) if raw.get("owner") else None,
            requires_role=required_role,
            expectations={str(k): str(v) for k, v in expectations.items()},
        ))

    if not identities:
        raise ConfigError("plan defines no identities")
    if not resources:
        raise ConfigError("plan defines no resources")

    names = [i.name for i in identities]
    if len(names) != len(set(names)):
        raise ConfigError("identity names must be unique")
    for resource in resources:
        if resource.owner and resource.owner not in names:
            raise ConfigError(
                f"resource {resource.url} declares owner '{resource.owner}' "
                f"which is not a defined identity"
            )
    return identities, resources


TEMPLATE = """\
# Velora authorization test plan.
# Credentials are NEVER stored here — 'secret_ref' names an environment variable.
#
#   export VELORA_IDENTITY_ALICE='<token>'
#   export VELORA_IDENTITY_ADMIN='<token>'

identities:
  - name: anonymous
    role: anonymous

  - name: alice
    role: user_a
    secret_ref: VELORA_IDENTITY_ALICE
    auth_scheme: bearer          # bearer | header | cookie | none

  - name: bob
    role: user_b
    secret_ref: VELORA_IDENTITY_BOB
    auth_scheme: bearer

  - name: admin
    role: admin
    secret_ref: VELORA_IDENTITY_ADMIN
    auth_scheme: bearer

resources:
  # Horizontal test: alice owns it, so bob and anonymous are expected to be denied.
  - name: alice's order
    url: http://localhost:8099/api/orders/1
    method: GET
    owner: alice

  # Vertical test: only admin should reach it.
  - name: admin console
    url: http://localhost:8099/admin
    method: GET
    requires_role: admin

  # Explicit expectation overrides derived ones.
  - name: public health endpoint
    url: http://localhost:8099/api/public
    method: GET
    expectations:
      anonymous: ALLOW
"""
