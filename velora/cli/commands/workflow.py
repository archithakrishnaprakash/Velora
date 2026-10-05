"""`velora workflow` — business-logic workflow assessment."""
from __future__ import annotations

from pathlib import Path

import click

from ...core.http import SafeHTTPClient
from ...models.domain import Scan
from ...models.enums import ScanProfile, ScanStatus, WorkflowStepOutcome
from ...utils import console
from ...utils.errors import AuthorizationError
from ...workflow import WorkflowEngine, load_workflow
from ...workflow.spec import TEMPLATE
from ..helpers import (
    AUTH_HELP,
    app_ctx,
    echo_json,
    require_authorization,
    run_async,
    scope_manager_for,
)

_OUTCOME_COLOR = {
    WorkflowStepOutcome.PASSED: "green",
    WorkflowStepOutcome.ASSERTION_FAILED: "red",
    WorkflowStepOutcome.UNEXPECTED_STATE: "yellow",
    WorkflowStepOutcome.BLOCKED_BY_SCOPE: "magenta",
    WorkflowStepOutcome.ERROR: "red",
    WorkflowStepOutcome.PENDING: "bright_black",
}


def _style(outcome: WorkflowStepOutcome) -> str:
    return click.style(outcome.value, fg=_OUTCOME_COLOR.get(outcome, "white"))


@click.group()
def workflow() -> None:
    """Model an application's business process and test that it enforces its own order."""


@workflow.command("create")
@click.option("--output", "-o", default="workflow.yaml", type=click.Path())
def workflow_create(output):
    """Write a starter workflow definition."""
    path = Path(output)
    if path.exists():
        raise click.ClickException(f"refusing to overwrite existing file: {path}")
    path.write_text(TEMPLATE, encoding="utf-8")
    console.ok(f"wrote workflow template: {path}")
    click.echo("Edit the steps, set 'authorized: true', then run:")
    click.echo(f"  velora workflow validate --config {path}")


@workflow.command("validate")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True)
def workflow_validate(config_path, as_json):
    """Statically validate a workflow definition. Sends no requests."""
    spec = load_workflow(config_path)
    problems = spec.validate()
    if as_json:
        echo_json({"workflow": spec.to_dict(), "problems": problems,
                   "valid": not problems, "authorized": spec.authorized})
        return
    console.header(f"Workflow '{spec.name}'")
    click.echo(f"identity={spec.identity or '-'}  authorized={spec.authorized}  "
               f"{spec.initial_state} -> {spec.terminal_state}")
    console.table([[str(i + 1), s.name, s.method, s.url[:40],
                    f"{s.from_state}->{s.to_state}", "yes" if s.required else "",
                    s.assertion[:34]]
                   for i, s in enumerate(spec.steps)],
                  ["#", "STEP", "METHOD", "URL", "TRANSITION", "REQUIRED", "ASSERTION"])
    if problems:
        console.header("Problems")
        for problem in problems:
            console.fail(problem)
        raise SystemExit(1)
    console.ok("definition is valid")
    if not spec.authorized:
        console.warn("authorized: false — Velora will refuse to execute this workflow")


@workflow.command("run")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--target", "target_arg", default=None, help="Stored target to anchor evidence.")
@click.option("--scope", multiple=True)
@click.option("--allow-private", is_flag=True)
@click.option("--operator", default="")
@click.option("--engagement", "engagement_id", default=None)
@click.option("--no-skip-probe", is_flag=True,
              help="Do not probe whether required steps can be skipped.")
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def workflow_run(click_ctx, config_path, target_arg, scope, allow_private, operator,
                 engagement_id, no_skip_probe, authorized):
    """Execute an authorized workflow and probe for skippable required steps."""
    require_authorization(authorized)
    app = app_ctx(click_ctx)
    spec = load_workflow(config_path)

    target = None
    if target_arg:
        target = app.repo.get_target(target_arg) or app.repo.get_target_by_name(target_arg)
        if target is None:
            raise click.ClickException(f"target not found: {target_arg}")

    scan = None
    if target is not None:
        scan = Scan(target_id=target.id, engagement_id=engagement_id,
                    profile=ScanProfile.LAB, status=ScanStatus.RUNNING,
                    operator=operator, authorization_ack=True)
        app.repo.add_scan(scan)

    first_url = spec.steps[0].url

    async def _run():
        sm = scope_manager_for(first_url, scope, allow_private, app.settings,
                               max_requests=max(60, len(spec.steps) * 6),
                               scan_id=scan.id if scan else None)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=sm.policy.request_delay) as client:
            engine = WorkflowEngine(client, app.repo)
            result = await engine.assess(spec, scan=scan, authorization_ack=True,
                                         probe_skips=not no_skip_probe)
            engine.persist(spec, result, engagement_id=engagement_id,
                           target_id=target.id if target else None)
            return result

    try:
        result = run_async(_run())
    except AuthorizationError as exc:
        if scan is not None:
            scan.status = ScanStatus.FAILED
            app.repo.update_scan(scan)
        raise click.ClickException(str(exc)) from exc

    if scan is not None:
        scan.status = ScanStatus.COMPLETED
        scan.stats = {"workflow": spec.name, "completed": result.completed,
                      "findings": len(result.findings)}
        app.repo.update_scan(scan)

    console.header(f"Workflow '{spec.name}' execution")
    console.table([[s.step.name, s.step.method, _style(s.outcome),
                    str(s.observed_status or "-"), s.observed_state, s.detail[:40]]
                   for s in result.steps],
                  ["STEP", "METHOD", "OUTCOME", "STATUS", "STATE", "DETAIL"])
    click.echo(f"\nfinal state: {result.final_state}   completed: {result.completed}")

    if result.skip_probes:
        console.header("Step-skip probes")
        console.table([[p["omitted_step"], p["terminal_step"],
                        click.style("BYPASSED", fg="red", bold=True)
                        if p["terminal_reached"] else click.style("blocked", fg="green"),
                        str(p["terminal_status"] or "-")]
                       for p in result.skip_probes],
                      ["OMITTED STEP", "TERMINAL STEP", "RESULT", "STATUS"])

    if result.findings:
        console.warn(f"{len(result.findings)} Potential finding(s) — all require validation:")
        for f in result.findings:
            click.echo(f"  {f.id}  [{f.severity.value}] {f.title}")
    if scan is not None:
        click.echo(f"\nscan: {scan.id}")


@workflow.command("report")
@click.option("--workflow", "workflow_name", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def workflow_report(click_ctx, workflow_name, as_json):
    """Show stored workflow executions and their step outcomes."""
    app = app_ctx(click_ctx)
    workflows = app.repo.list_workflows()
    if workflow_name:
        workflows = [w for w in workflows if w.name == workflow_name]
    if not workflows:
        console.warn("no workflow executions recorded")
        return
    if as_json:
        echo_json([{**w.model_dump(),
                    "steps": [s.model_dump() for s in app.repo.list_workflow_steps(w.id)]}
                   for w in workflows])
        return
    for w in workflows:
        console.header(f"{w.name}  ({w.id})")
        steps = app.repo.list_workflow_steps(w.id)
        console.table([[str(s.order_index + 1), s.name, s.method,
                        _style(s.outcome), str(s.observed_status or "-"),
                        s.assertion[:38]] for s in steps],
                      ["#", "STEP", "METHOD", "OUTCOME", "STATUS", "ASSERTION"])
