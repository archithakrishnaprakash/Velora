"""`velora reproduce` — reproducibility packages for findings."""
from __future__ import annotations

import json
from pathlib import Path

import click

from ...reproduce import ReproductionService
from ...utils import console
from ..helpers import app_ctx, echo_json


@click.group(invoke_without_command=True)
@click.option("--finding", "finding_id", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--output", default=None, type=click.Path())
@click.pass_context
def reproduce(click_ctx, finding_id, as_json, output):
    """Build a reproducibility package for a finding (no secrets included)."""
    if click_ctx.invoked_subcommand is not None:
        return
    if not finding_id:
        raise click.UsageError("--finding is required (or use a subcommand)")
    _emit(click_ctx, finding_id, as_json, output)


@reproduce.command("show")
@click.argument("finding_id")
@click.option("--json", "as_json", is_flag=True)
@click.option("--output", default=None, type=click.Path())
@click.pass_context
def reproduce_show(click_ctx, finding_id, as_json, output):
    """Show the reproducibility package for a finding."""
    _emit(click_ctx, finding_id, as_json, output)


def _emit(click_ctx, finding_id: str, as_json: bool, output: str | None) -> None:
    app = app_ctx(click_ctx)
    finding = app.repo.get_finding(finding_id)
    if finding is None:
        raise click.ClickException(f"finding not found: {finding_id}")
    service = ReproductionService(app.repo)
    record = service.build(finding)
    payload = service.to_dict(record)

    if output:
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        console.ok(f"wrote reproducibility package: {output}")
    if as_json:
        echo_json(payload)
        return

    console.header(f"Reproducibility package for {finding.id}")
    console.table([
        ["Velora version", payload["velora_version"]],
        ["Detecting check", payload["scanner"]],
        ["Scan", f"{payload['scan_id']} ({payload['scan_profile']})"],
        ["Scope policy hash", payload["scope_policy_hash"]],
        ["Validation state", payload["validation_state"]],
        ["Evidence ids", ", ".join(payload["evidence_ids"]) or "-"],
        ["Fingerprint", finding.fingerprint or "(not computed)"],
    ], ["FIELD", "VALUE"])
    console.header("Scope in force")
    click.echo("  " + payload["scope_summary"])
    console.header("Steps")
    for i, step in enumerate(payload["steps"], start=1):
        click.echo(f"  {i}. {step}")
    console.header("Note")
    click.echo("  " + payload["note"])
