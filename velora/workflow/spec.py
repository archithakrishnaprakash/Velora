"""Workflow definitions.

A workflow models an application's business process as an explicit state machine. Velora
will only execute a workflow that an operator has written down and authorized — it never
discovers and drives business operations on its own.

Example (``examples/labs/workflow-checkout.yaml``)::

    name: checkout
    description: register -> login -> add item -> checkout
    identity: alice
    authorized: true
    initial_state: anonymous
    steps:
      - name: login
        method: POST
        url: http://localhost:8099/login
        from_state: anonymous
        to_state: authenticated
        required: true
        assertion: a session cookie is issued
        assert_status_in: [200, 302]
      - name: checkout
        method: POST
        url: http://localhost:8099/checkout
        from_state: cart_filled
        to_state: ordered
        assertion: checkout must be refused unless payment has completed
        assert_status_in: [200]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..utils.errors import ConfigError

# Methods a workflow may use. Destructive verbs are refused outright: Velora models
# business processes, it does not delete data on a target.
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"})
REFUSED_METHODS = frozenset({"DELETE", "CONNECT", "TRACE"})


@dataclass
class StepSpec:
    name: str
    url: str
    method: str = "GET"
    from_state: str = ""
    to_state: str = ""
    required: bool = False
    assertion: str = ""
    assert_status_in: list[int] = field(default_factory=list)
    assert_body_contains: str = ""
    assert_body_absent: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "method": self.method, "url": self.url,
            "from_state": self.from_state, "to_state": self.to_state,
            "required": self.required, "assertion": self.assertion,
            "assert_status_in": self.assert_status_in,
        }


@dataclass
class WorkflowSpec:
    name: str
    description: str = ""
    identity: str = ""
    authorized: bool = False
    initial_state: str = "start"
    steps: list[StepSpec] = field(default_factory=list)

    @property
    def terminal_state(self) -> str:
        return self.steps[-1].to_state if self.steps else self.initial_state

    @property
    def required_steps(self) -> list[StepSpec]:
        return [s for s in self.steps if s.required]

    def validate(self) -> list[str]:
        """Static coherence checks. Returns a list of problems (empty == valid)."""
        problems: list[str] = []
        if not self.steps:
            problems.append("workflow defines no steps")
            return problems

        seen_names: set[str] = set()
        state = self.initial_state
        for index, step in enumerate(self.steps):
            if step.name in seen_names:
                problems.append(f"duplicate step name '{step.name}'")
            seen_names.add(step.name)
            if step.method.upper() in REFUSED_METHODS:
                problems.append(
                    f"step '{step.name}' uses {step.method}, which Velora refuses to "
                    "execute in a workflow (destructive or diagnostic verb)")
            elif step.method.upper() not in ALLOWED_METHODS:
                problems.append(f"step '{step.name}' uses unsupported method {step.method}")
            if not step.url.lower().startswith(("http://", "https://")):
                problems.append(f"step '{step.name}' has a non-http(s) url")
            if step.from_state and step.from_state != state:
                problems.append(
                    f"step {index + 1} '{step.name}' expects from_state "
                    f"'{step.from_state}' but the machine is in '{state}'")
            if not step.to_state:
                problems.append(f"step '{step.name}' has no to_state")
            state = step.to_state or state
            if not step.assertion:
                problems.append(f"step '{step.name}' has no security assertion")
        return problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "description": self.description,
            "identity": self.identity, "authorized": self.authorized,
            "initial_state": self.initial_state,
            "terminal_state": self.terminal_state,
            "steps": [s.to_dict() for s in self.steps],
        }


def load_workflow(path: str | Path) -> WorkflowSpec:
    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"workflow definition not found: {file_path}")
    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    if not isinstance(data, dict) or "name" not in data:
        raise ConfigError(f"{file_path} must be a mapping containing 'name'")

    spec = WorkflowSpec(
        name=str(data["name"]),
        description=str(data.get("description", "")),
        identity=str(data.get("identity", "")),
        authorized=bool(data.get("authorized", False)),
        initial_state=str(data.get("initial_state", "start")),
    )
    for raw in data.get("steps", []) or []:
        if not isinstance(raw, dict) or "url" not in raw or "name" not in raw:
            raise ConfigError("each workflow step requires 'name' and 'url'")
        spec.steps.append(StepSpec(
            name=str(raw["name"]),
            url=str(raw["url"]),
            method=str(raw.get("method", "GET")).upper(),
            from_state=str(raw.get("from_state", "")),
            to_state=str(raw.get("to_state", "")),
            required=bool(raw.get("required", False)),
            assertion=str(raw.get("assertion", "")),
            assert_status_in=[int(s) for s in raw.get("assert_status_in", []) or []],
            assert_body_contains=str(raw.get("assert_body_contains", "")),
            assert_body_absent=str(raw.get("assert_body_absent", "")),
            headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
            body=str(raw.get("body", "")),
        ))
    if not spec.steps:
        raise ConfigError(f"{file_path} defines no steps")
    return spec


TEMPLATE = """\
# Velora business-logic workflow definition.
# Velora executes ONLY what is written here, and only when authorized: true.
name: checkout
description: A shopping flow modelled as a state machine.
identity: alice          # optional: an identity name from the authz plan
authorized: false        # set true to permit execution against an authorized target
initial_state: anonymous

steps:
  - name: login
    method: POST
    url: http://localhost:8099/login
    from_state: anonymous
    to_state: authenticated
    required: true
    assertion: authentication must succeed before any cart operation
    assert_status_in: [200, 302]

  - name: add-item
    method: POST
    url: http://localhost:8099/cart/add
    from_state: authenticated
    to_state: cart_filled
    required: true
    assertion: items may only be added by an authenticated principal
    assert_status_in: [200]

  - name: checkout
    method: POST
    url: http://localhost:8099/checkout
    from_state: cart_filled
    to_state: ordered
    assertion: checkout must be refused unless every required prior step completed
    assert_status_in: [200]
"""
