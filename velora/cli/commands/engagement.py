"""`velora engagement` — the assessment workspace."""
from __future__ import annotations

import click

from ...models.domain import Engagement
from ...models.enums import EngagementStatus
from ...utils import console
from ..helpers import app_ctx, echo_json


@click.group()
def engagement() -> None:
    """Group targets, identities, scans, findings and reports into an engagement."""


@engagement.command("create")
@click.option("--name", required=True)
@click.option("--client", default="")
@click.option("--description", default="")
@click.option("--operator", default="")
@click.option("--authorization-reference", default="",
              help="Ticket/contract reference. Never a secret.")
@click.option("--granted-by", default="", help="Who authorized this engagement.")
@click.pass_context
def engagement_create(click_ctx, name, client, description, operator,
                      authorization_reference, granted_by):
    """Create an engagement."""
    app = app_ctx(click_ctx)
    if app.repo.get_engagement_by_name(name):
        raise click.ClickException(f"an engagement named '{name}' already exists")
    eng = Engagement(name=name, client=client, description=description, operator=operator,
                     authorization_reference=authorization_reference,
                     authorization_granted_by=granted_by,
                     status=EngagementStatus.PLANNED)
    app.repo.add_engagement(eng)
    console.ok(f"created engagement {eng.id}  ({eng.status.value})")
    if not authorization_reference:
        console.warn("no authorization reference recorded — add one before scanning")


@engagement.command("list")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def engagement_list(click_ctx, as_json):
    """List engagements."""
    app = app_ctx(click_ctx)
    items = app.repo.list_engagements()
    if as_json:
        echo_json([e.model_dump() for e in items])
        return
    if not items:
        console.warn("no engagements yet — `velora engagement create --name ...`")
        return
    console.table(
        [[e.id, e.name[:26], e.client[:18], e.status.value,
          str(len(app.repo.list_identities(e.id))),
          e.authorization_reference or "-"] for e in items],
        ["ID", "NAME", "CLIENT", "STATUS", "IDENTITIES", "AUTH REF"])


@engagement.command("show")
@click.argument("engagement_id")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def engagement_show(click_ctx, engagement_id, as_json):
    """Show an engagement and everything attached to it."""
    app = app_ctx(click_ctx)
    eng = app.repo.get_engagement(engagement_id) or \
        app.repo.get_engagement_by_name(engagement_id)
    if eng is None:
        raise click.ClickException(f"engagement not found: {engagement_id}")
    targets = [t for t in app.repo.list_targets() if t.engagement_id == eng.id]
    identities = app.repo.list_identities(eng.id)
    scans = [s for s in app.repo.list_scans() if s.engagement_id == eng.id]
    findings = [f for s in scans for f in app.repo.list_findings(s.id)]
    if as_json:
        echo_json({"engagement": eng.model_dump(),
                   "targets": [t.id for t in targets],
                   "identities": [i.name for i in identities],
                   "scans": [s.id for s in scans],
                   "findings": len(findings)})
        return
    console.header(f"{eng.name}  ({eng.id})")
    click.echo(f"client={eng.client or '-'}  status={eng.status.value}  "
               f"operator={eng.operator or '-'}")
    click.echo(f"authorization: {eng.authorization_reference or '(none recorded)'} "
               f"granted by {eng.authorization_granted_by or '-'}")
    console.header("Targets")
    console.table([[t.id, t.name, t.url, t.authorization_status.value] for t in targets],
                  ["ID", "NAME", "URL", "AUTHORIZATION"])
    console.header("Identities")
    console.table([[i.name, i.role.value, i.secret_ref or "(none)"] for i in identities],
                  ["NAME", "ROLE", "SECRET REF"])
    console.header("Scans")
    console.table([[s.id, s.profile.value, s.status.value,
                    str(s.stats.get("findings", "-"))] for s in scans],
                  ["SCAN", "PROFILE", "STATUS", "FINDINGS"])
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    console.header("Findings")
    console.table([[k, str(v)] for k, v in sorted(by_sev.items())], ["SEVERITY", "COUNT"])


@engagement.command("status")
@click.argument("engagement_id")
@click.option("--set", "new_status", required=True,
              type=click.Choice([s.value for s in EngagementStatus]))
@click.pass_context
def engagement_status(click_ctx, engagement_id, new_status):
    """Change an engagement's status."""
    app = app_ctx(click_ctx)
    eng = app.repo.get_engagement(engagement_id) or \
        app.repo.get_engagement_by_name(engagement_id)
    if eng is None:
        raise click.ClickException(f"engagement not found: {engagement_id}")
    eng.status = EngagementStatus(new_status)
    app.repo.update_engagement(eng)
    console.ok(f"{eng.id} -> {eng.status.value}")


@engagement.command("attach")
@click.argument("engagement_id")
@click.option("--target", "target_id", required=True)
@click.pass_context
def engagement_attach(click_ctx, engagement_id, target_id):
    """Attach an existing target to an engagement."""
    app = app_ctx(click_ctx)
    eng = app.repo.get_engagement(engagement_id) or \
        app.repo.get_engagement_by_name(engagement_id)
    if eng is None:
        raise click.ClickException(f"engagement not found: {engagement_id}")
    target = app.repo.get_target(target_id) or app.repo.get_target_by_name(target_id)
    if target is None:
        raise click.ClickException(f"target not found: {target_id}")
    target.engagement_id = eng.id
    app.repo.update(target)
    console.ok(f"target {target.id} attached to engagement {eng.id}")


@engagement.command("scope")
@click.argument("engagement_id")
@click.pass_context
def engagement_scope(click_ctx, engagement_id):
    """Show the scope boundary of every target in the engagement."""
    app = app_ctx(click_ctx)
    eng = app.repo.get_engagement(engagement_id) or \
        app.repo.get_engagement_by_name(engagement_id)
    if eng is None:
        raise click.ClickException(f"engagement not found: {engagement_id}")
    rows = []
    for target in app.repo.list_targets():
        if target.engagement_id != eng.id:
            continue
        record = app.repo.get_scope(target.scope_policy_id) if target.scope_policy_id else None
        rows.append([
            target.name[:22], target.url[:34],
            ",".join(record.allowed_domains) if record else "-",
            ",".join(str(p) for p in record.allowed_ports) if record else "-",
            "yes" if record and record.allow_private_targets else "no",
        ])
    console.header(f"Scope for engagement {eng.name}")
    console.table(rows, ["TARGET", "URL", "DOMAINS", "PORTS", "PRIVATE OK"])


@engagement.command("report")
@click.argument("engagement_id")
@click.option("--format", "formats", multiple=True, default=("html", "json"),
              type=click.Choice(["html", "json", "pdf", "sarif"]))
@click.option("--output-dir", default=None)
@click.pass_context
def engagement_report(click_ctx, engagement_id, formats, output_dir):
    """Generate a report for every scan in the engagement."""
    from ...reporting import ReportGenerator
    app = app_ctx(click_ctx)
    eng = app.repo.get_engagement(engagement_id) or \
        app.repo.get_engagement_by_name(engagement_id)
    if eng is None:
        raise click.ClickException(f"engagement not found: {engagement_id}")
    scans = [s for s in app.repo.list_scans() if s.engagement_id == eng.id]
    if not scans:
        console.warn("this engagement has no scans yet")
        return
    generator = ReportGenerator(app.repo, app.settings)
    for scan in scans:
        record = generator.generate(scan.id, list(formats), output_dir)
        for fmt, path in record.paths.items():
            console.ok(f"{scan.id} {fmt}: {path}")
