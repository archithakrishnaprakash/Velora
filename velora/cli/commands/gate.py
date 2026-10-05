"""`velora gate` — CI/CD security gate with an explicit exit-code contract."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from ...gate import DEFAULT_POLICY_YAML, GatePolicy, SecurityGate
from ...models.enums import GateDecision, Severity
from ...utils import console
from ...utils.errors import ConfigError
from ..helpers import app_ctx, echo_json


@click.group()
def gate() -> None:
    """Evaluate a scan against a CI/CD security policy.

    Exit codes: 0 = PASS, 1 = SECURITY GATE FAILURE, 2 = CONFIGURATION/EXECUTION ERROR.
    """


@gate.command("init")
@click.option("--output", "-o", default="velora-gate.yaml", type=click.Path())
def gate_init(output):
    """Write a starter gate policy."""
    path = Path(output)
    if path.exists():
        raise click.ClickException(f"refusing to overwrite existing file: {path}")
    path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    console.ok(f"wrote gate policy: {path}")


@gate.command("evaluate")
@click.option("--scan", "scan_id", required=True)
@click.option("--policy", "policy_path", default=None, type=click.Path(),
              help="Gate policy YAML. Defaults to inline options.")
@click.option("--fail-on", multiple=True,
              type=click.Choice([s.value.lower() for s in Severity]),
              help="Severity that fails the build (repeatable).")
@click.option("--max-cvss", type=float, default=None)
@click.option("--max-priority-score", type=float, default=None)
@click.option("--max-new-findings", type=int, default=None)
@click.option("--baseline", "baseline_scan_id", default=None,
              help="Baseline scan for new-finding and regression rules.")
@click.option("--no-fail-on-regression", is_flag=True)
@click.option("--ignore-unvalidated", is_flag=True,
              help="Count only human-validated findings.")
@click.option("--json", "as_json", is_flag=True)
@click.option("--output", default=None, type=click.Path(), help="Write the JSON result here.")
@click.pass_context
def gate_evaluate(click_ctx, scan_id, policy_path, fail_on, max_cvss, max_priority_score,
                  max_new_findings, baseline_scan_id, no_fail_on_regression,
                  ignore_unvalidated, as_json, output):
    """Evaluate the gate and exit with the corresponding process status."""
    app = app_ctx(click_ctx)
    try:
        if policy_path:
            policy = GatePolicy.from_file(policy_path)
        else:
            policy = GatePolicy.from_dict({"gate": {
                "fail_on": list(fail_on) or ["critical", "high"],
                "max_cvss": max_cvss,
                "max_priority_score": max_priority_score,
                "max_new_findings": max_new_findings,
                "fail_on_regression": not no_fail_on_regression,
                "ignore_unvalidated": ignore_unvalidated,
            }})
    except ConfigError as exc:
        click.echo(click.style(f"gate configuration error: {exc}", fg="red"), err=True)
        sys.exit(GateDecision.ERROR.exit_code)

    evaluation = SecurityGate(app.repo).evaluate(
        scan_id, policy, baseline_scan_id=baseline_scan_id)

    payload = evaluation.to_dict()
    if output:
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    if as_json:
        echo_json(payload)
    else:
        console.header("Velora security gate")
        click.echo(f"scan      : {scan_id}")
        click.echo(f"policy    : {json.dumps(policy.to_dict())}")
        click.echo(f"considered: {evaluation.considered} finding(s)")
        if evaluation.violations:
            console.header(f"Violations ({len(evaluation.violations)})")
            console.table([[v.rule, v.severity or "-", v.detail[:70]]
                           for v in evaluation.violations],
                          ["RULE", "SEVERITY", "DETAIL"])
        colour = {"PASS": "green", "FAIL": "red", "ERROR": "yellow"}[evaluation.decision.value]
        click.echo()
        click.echo(click.style(f"  {evaluation.decision.value}  ", fg=colour, bold=True)
                   + evaluation.summary)
        click.echo(click.style(f"  exit code {evaluation.exit_code}", fg="bright_black"))

    sys.exit(evaluation.exit_code)


@gate.command("history")
@click.option("--scan", "scan_id", default=None)
@click.pass_context
def gate_history(click_ctx, scan_id):
    """Show recorded gate evaluations."""
    app = app_ctx(click_ctx)
    results = app.repo.list_gate_results(scan_id)
    if not results:
        console.warn("no gate evaluations recorded")
        return
    console.table(
        [[r.id, r.scan_id, r.decision.value, str(len(r.violations)), r.summary[:44]]
         for r in results],
        ["ID", "SCAN", "DECISION", "VIOLATIONS", "SUMMARY"])
