"""`velora remediation` — fix lifecycle and retest verification."""
from __future__ import annotations

import click

from ...core.orchestrator import ScanOrchestrator
from ...models.enums import RemediationStatus, ScanProfile
from ...remediation import RemediationService
from ...utils import console
from ..helpers import AUTH_HELP, app_ctx, echo_json, require_authorization, run_async

_STATUS_COLOR = {
    "OPEN": "yellow",
    "REMEDIATION_IN_PROGRESS": "cyan",
    "READY_FOR_RETEST": "bright_blue",
    "FIX_VERIFIED": "green",
    "FIX_FAILED": "red",
    "REGRESSION_DETECTED": "red",
}


def _style(status: str) -> str:
    return click.style(status, fg=_STATUS_COLOR.get(status, "white"),
                       bold=status in {"FIX_FAILED", "REGRESSION_DETECTED"})


@click.group()
def remediation() -> None:
    """Track fixes and verify them with targeted retests."""


@remediation.command("list")
@click.option("--status", "status_filter", default=None,
              type=click.Choice([s.value for s in RemediationStatus]))
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def remediation_list(click_ctx, status_filter, as_json):
    """List tracked remediations and their verification state."""
    app = app_ctx(click_ctx)
    rows = RemediationService(app.repo).status_table()
    if status_filter:
        rows = [r for r in rows if r["status"] == status_filter]
    if as_json:
        echo_json(rows)
        return
    if not rows:
        console.warn("no remediations tracked yet — use `velora remediation start`")
        return
    console.table(
        [[r["finding_id"], r["title"][:38], r["severity"], _style(r["status"]),
          r["owner"] or "-", r["last_retest_id"] or "-"] for r in rows],
        ["FINDING", "TITLE", "SEVERITY", "STATUS", "OWNER", "LAST RETEST"])


@remediation.command("start")
@click.argument("finding_id")
@click.option("--owner", default="", help="Who is doing the work.")
@click.option("--note", default="")
@click.pass_context
def remediation_start(click_ctx, finding_id, owner, note):
    """Mark a finding as being remediated."""
    app = app_ctx(click_ctx)
    action = RemediationService(app.repo).start(finding_id, owner=owner, note=note)
    if action is None:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.ok(f"{finding_id} -> {action.status.value}")


@remediation.command("ready")
@click.argument("finding_id")
@click.option("--owner", default="")
@click.option("--note", default="")
@click.pass_context
def remediation_ready(click_ctx, finding_id, owner, note):
    """Mark a finding as ready for retest."""
    app = app_ctx(click_ctx)
    action = RemediationService(app.repo).ready_for_retest(finding_id, owner=owner, note=note)
    if action is None:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.ok(f"{finding_id} -> {action.status.value}")


@remediation.command("retest")
@click.argument("finding_id")
@click.option("--scan", "retest_scan_id", default=None,
              help="Use an existing scan as the retest (otherwise a new scan is run).")
@click.option("--profile", type=click.Choice([p.value for p in ScanProfile]), default="safe")
@click.option("--operator", default="")
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def remediation_retest(click_ctx, finding_id, retest_scan_id, profile, operator, authorized):
    """Retest a finding and record the verification verdict."""
    app = app_ctx(click_ctx)
    finding = app.repo.get_finding(finding_id)
    if finding is None:
        raise click.ClickException(f"finding not found: {finding_id}")

    if retest_scan_id:
        scan = app.repo.get_scan(retest_scan_id)
        if scan is None:
            raise click.ClickException(f"scan not found: {retest_scan_id}")
        # An existing scan used as a retest is a retest, and its lineage should say so.
        # Without this the scan is indistinguishable from a first-time assessment in
        # the database, in reports, and in every later regression comparison.
        if not scan.is_retest or not scan.baseline_scan_id:
            scan.is_retest = True
            scan.baseline_scan_id = scan.baseline_scan_id or finding.scan_id
            app.repo.update_scan(scan)
    else:
        require_authorization(authorized)
        original = app.repo.get_scan(finding.scan_id)
        if original is None:
            raise click.ClickException("original scan not found; pass --scan explicitly")
        target = app.repo.get_target(original.target_id)
        if target is None:
            raise click.ClickException("target not found; pass --scan explicitly")
        console.header(f"Running retest scan against {target.url}")
        scan = run_async(ScanOrchestrator(app.settings, app.db).run_scan(
            target, profile=ScanProfile(profile), operator=operator, authorization_ack=True))
        scan.is_retest = True
        scan.baseline_scan_id = finding.scan_id
        app.repo.update_scan(scan)

    result = RemediationService(app.repo).verify_against_scan(
        finding_id, scan, operator=operator)
    console.header(f"Retest verdict for {finding_id}")
    click.echo(f"  verdict          : {_style(result.verdict.value)}")
    click.echo(f"  still present    : {result.still_present}")
    click.echo(f"  endpoint covered : {result.covered}")
    click.echo(f"  retest scan      : {scan.id}")
    click.echo(f"\n  {result.detail}")
    if result.verdict == RemediationStatus.READY_FOR_RETEST:
        console.warn("retest was inconclusive — absence of detection is not proof of a fix")


@remediation.command("verify")
@click.option("--scan", "original_scan_id", required=True, help="Original scan to verify.")
@click.option("--retest-scan", "retest_scan_id", required=True)
@click.option("--operator", default="")
@click.pass_context
def remediation_verify(click_ctx, original_scan_id, retest_scan_id, operator):
    """Verify every finding of a scan against a retest scan."""
    app = app_ctx(click_ctx)
    retest = app.repo.get_scan(retest_scan_id)
    if retest is None:
        raise click.ClickException(f"retest scan not found: {retest_scan_id}")
    if app.repo.get_scan(original_scan_id) is None:
        raise click.ClickException(f"scan not found: {original_scan_id}")
    results = RemediationService(app.repo).verify_scan(
        original_scan_id, retest, operator=operator)
    console.header(f"Verification: {original_scan_id} -> {retest_scan_id}")
    console.table(
        [[r.finding_id, _style(r.verdict.value), str(r.still_present),
          "yes" if r.covered else "NO", r.detail[:48]] for r in results],
        ["FINDING", "VERDICT", "STILL PRESENT", "COVERED", "DETAIL"])
    verified = sum(1 for r in results if r.verdict == RemediationStatus.FIX_VERIFIED)
    failed = sum(1 for r in results if r.verdict == RemediationStatus.FIX_FAILED)
    inconclusive = len(results) - verified - failed
    click.echo(f"\nverified={verified}  failed={failed}  inconclusive={inconclusive}")
