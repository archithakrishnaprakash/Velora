"""`velora authz` — multi-identity authorization testing."""
from __future__ import annotations

from pathlib import Path

import click

from ...authz import AuthorizationTestingService, AuthzRunner, IdentityResolver, build_matrix
from ...authz.plan_io import TEMPLATE, load_plan
from ...utils.errors import ConfigError
from ...core.http import SafeHTTPClient
from ...models.domain import Scan
from ...models.enums import AuthzOutcome, ScanProfile, ScanStatus
from ...utils import console
from ..helpers import (
    AUTH_HELP,
    app_ctx,
    echo_json,
    require_authorization,
    run_async,
    scope_manager_for,
)


def _load_plan_or_fail(config_path):
    """Load an authorization plan, turning a rejected plan into a clean CLI error.

    The plan loader refuses plans that embed credentials. That refusal carries a
    carefully worded explanation, and it should reach the operator as a message rather
    than as a Python traceback.
    """
    try:
        return load_plan(config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    except FileNotFoundError as exc:
        raise click.ClickException(f"authorization plan not found: {config_path}") from exc


@click.group()
def authz() -> None:
    """Plan and run controlled multi-identity authorization tests."""


@authz.command("init")
@click.option("--output", "-o", default="authz-plan.yaml", type=click.Path())
def authz_init(output):
    """Write a starter authorization plan file."""
    path = Path(output)
    if path.exists():
        raise click.ClickException(f"refusing to overwrite existing file: {path}")
    path.write_text(TEMPLATE, encoding="utf-8")
    console.ok(f"wrote plan template: {path}")
    click.echo("Set each identity's credential in the environment, then run:")
    click.echo(f"  velora authz plan --config {path}")


@authz.command("plan")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True),
              help="Authorization plan YAML.")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def authz_plan(click_ctx, config_path, as_json):
    """Build and display the identity x resource matrix without sending any request."""
    identities, resources = _load_plan_or_fail(config_path)
    matrix = build_matrix(identities, resources)
    resolver = IdentityResolver()

    if as_json:
        echo_json({
            "identities": [i.safe_summary() if hasattr(i, "safe_summary")
                           else {"name": i.name, "role": i.role.value,
                                 "secret_ref": i.secret_ref or "(none)",
                                 "credential_available": resolver.available(i)}
                           for i in identities],
            "cases": [{"identity": c.identity.name, "role": c.identity.role.value,
                       "method": c.resource.method, "url": c.resource.url,
                       "expected": c.expected.value, "rationale": c.rationale}
                      for c in matrix.cases],
        })
        return

    console.header(f"Identities ({len(identities)})")
    console.table(
        [[i.name, i.role.value, i.auth_scheme, i.secret_ref or "(none)",
          "yes" if resolver.available(i) else click.style("MISSING", fg="yellow")]
         for i in identities],
        ["NAME", "ROLE", "SCHEME", "SECRET REF", "CREDENTIAL"],
    )
    missing = [i.name for i in identities if not resolver.available(i)]
    if missing:
        console.warn(f"credential not set for: {', '.join(missing)} — "
                     "those identities would run unauthenticated (use --strict to refuse)")

    console.header(f"Authorization matrix ({len(matrix)} cases)")
    console.table(
        [[c.identity.name, c.identity.role.value, c.resource.method,
          c.resource.url[:48], c.expected.value, c.rationale[:46]]
         for c in matrix.cases],
        ["IDENTITY", "ROLE", "METHOD", "RESOURCE", "EXPECTED", "WHY"],
    )
    click.echo("\nNo requests were sent. Run with:  velora authz run --config "
               f"{config_path} --i-am-authorized")


@authz.command("run")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--target", "target_arg", default=None,
              help="Stored target id/name to attach the scan to (optional).")
@click.option("--scope", multiple=True, help="Additional in-scope domain (repeatable).")
@click.option("--allow-private", is_flag=True, help="Permit private/loopback targets (lab).")
@click.option("--operator", default="")
@click.option("--engagement", "engagement_id", default=None)
@click.option("--strict", is_flag=True,
              help="Fail if any identity's credential is missing (recommended).")
@click.option("--no-findings", is_flag=True, help="Record tests but do not create findings.")
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def authz_run(click_ctx, config_path, target_arg, scope, allow_private, operator,
              engagement_id, strict, no_findings, authorized):
    """Execute the authorization matrix and record the results.

    Every request is scope-gated. Weaknesses are recorded as Potential findings that
    require human validation; nothing is auto-confirmed.
    """
    require_authorization(authorized)
    app = app_ctx(click_ctx)
    identities, resources = _load_plan_or_fail(config_path)

    # Persist identities so findings and tests can reference them.
    for identity in identities:
        existing = app.repo.get_identity_by_name(identity.name)
        if existing is None:
            identity.engagement_id = engagement_id
            app.repo.add_identity(identity)
        else:
            identity.id = existing.id

    matrix = build_matrix(identities, resources)
    first_url = resources[0].url

    # A scan row anchors the evidence produced by this run.
    target = None
    if target_arg:
        target = app.repo.get_target(target_arg) or app.repo.get_target_by_name(target_arg)
        if target is None:
            raise click.ClickException(f"target not found: {target_arg}")
    scan = Scan(
        target_id=target.id if target else "",
        engagement_id=engagement_id,
        profile=ScanProfile.STANDARD,
        status=ScanStatus.RUNNING,
        operator=operator,
        authorization_ack=True,
    )
    if target is not None:
        app.repo.add_scan(scan)
    else:
        # Without a target there is no scan to anchor evidence or findings to. The run
        # still executes and prints its results, but nothing is persisted — say so,
        # rather than printing a weakness count that quietly went nowhere.
        scan = None
        console.warn(
            "no --target given: results will be shown but NOT persisted. No scan, "
            "evidence or findings will be recorded. Re-run with --target <id|name> to "
            "keep them.")

    service = AuthorizationTestingService(app.repo)

    async def _run():
        sm = scope_manager_for(first_url, scope, allow_private, app.settings,
                               max_requests=max(50, len(matrix) * 3),
                               scan_id=scan.id if scan else None)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=sm.policy.request_delay) as client:
            runner = AuthzRunner(client)
            return await runner.run(matrix, strict_credentials=strict)

    try:
        results = run_async(_run())
    except Exception as exc:  # noqa: BLE001 - surface config errors cleanly
        if scan is not None:
            scan.status = ScanStatus.FAILED
            app.repo.update_scan(scan)
        raise click.ClickException(str(exc)) from exc

    summary = service.record(results, scan=scan, engagement_id=engagement_id,
                             create_findings=not no_findings)
    if scan is not None:
        scan.status = ScanStatus.COMPLETED
        scan.stats = {"authz_cases": summary.total, "authz_weaknesses": summary.weaknesses}
        app.repo.update_scan(scan)

    console.header("Authorization test results")
    console.table(
        [[r.case.identity.name, r.case.resource.method, r.case.resource.url[:40],
          r.case.expected.value, r.observed.value,
          _style_outcome(r.outcome), str(r.status_code or "-")]
         for r in results],
        ["IDENTITY", "METHOD", "RESOURCE", "EXPECTED", "OBSERVED", "OUTCOME", "CODE"],
    )
    click.echo(f"\ncases={summary.total}  as_expected={summary.as_expected}  "
               f"weaknesses={summary.weaknesses}  inconclusive={summary.inconclusive}")
    if summary.findings:
        console.warn(f"{len(summary.findings)} Potential finding(s) created — "
                     "all require human validation:")
        for f in summary.findings:
            click.echo(f"  {f.id}  [{f.severity.value}] {f.title}")
    if scan is not None:
        click.echo(f"\nscan: {scan.id}")


def _style_outcome(outcome: AuthzOutcome) -> str:
    if outcome.is_weakness:
        return click.style(outcome.value, fg="red", bold=True)
    if outcome == AuthzOutcome.AS_EXPECTED:
        return click.style(outcome.value, fg="green")
    return click.style(outcome.value, fg="bright_black")


@authz.command("compare")
@click.option("--scan", "scan_id", default=None, help="Filter to one scan.")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def authz_compare(click_ctx, scan_id, as_json):
    """Show recorded expected-vs-observed access for every tested pair."""
    app = app_ctx(click_ctx)
    tests = app.repo.list_authz_tests(scan_id)
    if not tests:
        console.warn("no authorization tests recorded")
        return
    if as_json:
        echo_json([t.model_dump() for t in tests])
        return
    console.table(
        [[t.id, t.identity_role.value, t.method, t.url[:40], t.expected.value,
          t.observed.value, _style_outcome(t.outcome), str(t.status_code or "-")]
         for t in tests],
        ["ID", "ROLE", "METHOD", "RESOURCE", "EXPECTED", "OBSERVED", "OUTCOME", "CODE"],
    )


@authz.command("report")
@click.option("--scan", "scan_id", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def authz_report(click_ctx, scan_id, as_json):
    """Summarize authorization testing coverage and outcomes."""
    app = app_ctx(click_ctx)
    tests = app.repo.list_authz_tests(scan_id)
    if not tests:
        console.warn("no authorization tests recorded")
        return
    by_outcome: dict[str, int] = {}
    for t in tests:
        by_outcome[t.outcome.value] = by_outcome.get(t.outcome.value, 0) + 1
    weaknesses = [t for t in tests if t.outcome.is_weakness]
    resources = sorted({t.url for t in tests})
    roles = sorted({t.identity_role.value for t in tests})

    payload = {
        "total_tests": len(tests),
        "resources_covered": len(resources),
        "roles_covered": roles,
        "by_outcome": by_outcome,
        "weaknesses": [{"id": t.id, "url": t.url, "role": t.identity_role.value,
                        "outcome": t.outcome.value, "notes": t.notes} for t in weaknesses],
        "note": ("Outcomes are evidence-backed indicators. A weakness is Potential until a "
                 "human validates it; 'AS_EXPECTED' does not prove the control is complete."),
    }
    if as_json:
        echo_json(payload)
        return

    console.header("Authorization testing report")
    click.echo(f"tests={len(tests)}  resources={len(resources)}  roles={', '.join(roles)}")
    console.header("Outcomes")
    console.table([[k, str(v)] for k, v in sorted(by_outcome.items())], ["OUTCOME", "COUNT"])
    if weaknesses:
        console.header(f"Potential weaknesses ({len(weaknesses)})")
        for t in weaknesses:
            click.echo(f"  [{t.outcome.value}] {t.identity_role.value} -> {t.method} {t.url}")
            click.echo(f"      {t.notes[:150]}")
    else:
        console.ok("no authorization weaknesses observed in the tested matrix")
    click.echo(f"\n{payload['note']}")
