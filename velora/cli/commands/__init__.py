"""Velora 2.0 CLI command groups.

Each module exposes a click group that ``velora.cli.main`` registers onto the root CLI.
Keeping them separate avoids a single oversized CLI module and keeps feature boundaries
clean. ``GROUPS`` is the registration list.
"""
from __future__ import annotations

import importlib
from typing import Any

import click

# Module name -> attribute holding the click group.
_GROUP_MODULES: list[tuple[str, str]] = [
    ("diff", "diff"),
    ("authz", "authz"),
    ("benchmark", "benchmark"),
    ("remediation", "remediation"),
    ("regression", "regression"),
    ("posture", "posture"),
    ("workflow", "workflow"),
    ("plan", "plan"),
    ("engagement", "engagement"),
    ("gate", "gate"),
    ("reproduce", "reproduce"),
    ("integrations", "integrations"),
]


def _load() -> list[Any]:
    groups: list[Any] = []
    for module_name, attr in _GROUP_MODULES:
        module = importlib.import_module(f"{__name__}.{module_name}")
        group = getattr(module, attr)
        if isinstance(group, click.Command):
            groups.append(group)
    return groups


GROUPS: list[Any] = _load()

__all__ = ["GROUPS"]
