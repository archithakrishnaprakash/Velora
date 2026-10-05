"""Velora CLI entrypoint (click)."""
from __future__ import annotations

import asyncio
import json as _json
from pathlib import Path
from urllib.parse import urlsplit

import click

from .. import APP_NAME, __version__
from ..models.domain import ScopePolicyRecord, Target
from ..models.enums import AuthorizationStatus, ScanProfile
from ..utils import console
from ..utils.urlutil import normalize_host
from .context import AppContext, build_context
from .doctor import run_doctor

AUTH_HELP = "Confirm you are authorized to test this target (required)."


def _ctx(click_ctx) -> AppContext:
    return click_ctx.obj


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_or_create_target(app: AppContext, target_arg: str, scope: tuple[str, ...],
                              allow_private: bool, operator: str,
                              ports: tuple[int, ...]) -> Target:
    """Resolve a stored target by id/name, else create a transient one from a URL."""
    repo = app.repo
    existing = repo.get_target(target_arg) or repo.get_target_by_name(target_arg)
    if existing:
        return existing
    if not target_arg.lower().startswith(("http://", "https://")):
        raise click.BadParameter("target must be a stored id/name or a full http(s) URL")
    parts = urlsplit(target_arg)
    host = normalize_host(parts.hostname or "")
    domains = list(scope) or ([host] if host and not _is_ip(host) else [])
    ips = [host] if _is_ip(host) else []
    port = parts.port or (443 if parts.scheme == "https" else 80)
    all_ports = sorted(set(ports) | {port, 80, 443})
    rec = ScopePolicyRecord(allowed_domains=[normalize_host(d) for d in domains],
                            allowed_ips=ips, allowed_ports=all_ports,
                            allow_private_targets=allow_private)
    repo.add_scope(rec)
    auth = AuthorizationStatus.LAB_ONLY if allow_private else AuthorizationStatus.AUTHORIZED
    target = Target(name=host or target_arg, url=target_arg, owner=operator,
                    authorization_status=auth, scope_policy_id=rec.id,
                    authorization_note="created via CLI with explicit authorization ack")
    repo.add_target(target)
    return target


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", default=None, help="Path to config.yaml")
@click.version_option(__version__, prog_name=APP_NAME)
@click.pass_context
def cli(click_ctx, config_path):
    """Velora — AI-Assisted Web Vulnerability Assessment (authorized use only)."""
    click_ctx.obj = build_context(config_path)


# ---- basic -------------------------------------------------------------
@cli.command()
def version():
    """Show version."""
    click.echo(f"{APP_NAME} v{__version__}")


@cli.command()
@click.pass_context
def doctor(click_ctx):
    """Run environment and installation health checks."""
    raise SystemExit(run_doctor(_ctx(click_ctx).settings))


@cli.command()
@click.pass_context
def init(click_ctx):
    """Create the config file and initialize the database."""
    from ..config.settings import default_config_path
    import yaml
    app = _ctx(click_ctx)
    path = default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(yaml.safe_dump(app.settings.to_yaml_dict(), sort_keys=False), encoding="utf-8")
        console.ok(f"wrote config: {path}")
    else:
        console.warn(f"config already exists: {path}")
    console.ok(f"database ready: {app.settings.database.url}")


@cli.command()
@click.pass_context
def config(click_ctx):
    """Show effective configuration (secrets omitted)."""
    click.echo(_json.dumps(_ctx(click_ctx).settings.to_yaml_dict(), indent=2, default=str))


# ---- target ------------------------------------------------------------
@cli.group()
def target():
    """Manage targets."""


@target.command("add")
@click.option("--name", required=True)
@click.option("--url", required=True)
@click.option("--owner", default="")
@click.option("--authorization", type=click.Choice([a.value for a in AuthorizationStatus]),
              default=AuthorizationStatus.LAB_ONLY.value)
@click.option("--note", default="")
@click.option("--scope", "scope", multiple=True, help="Allowed domain (repeatable)")
@click.option("--allow-private", is_flag=True, help="Permit private/loopback targets (lab).")
@click.pass_context
def target_add(click_ctx, name, url, owner, authorization, note, scope, allow_private):
    """Add a target with its scope policy."""
    app = _ctx(click_ctx); repo = app.repo
    parts = urlsplit(url); host = normalize_host(parts.hostname or "")
    domains = list(scope) or ([host] if host and not _is_ip(host) else [])
    ips = [host] if _is_ip(host) else []
    port = parts.port or (443 if parts.scheme == "https" else 80)
    rec = ScopePolicyRecord(allowed_domains=[normalize_host(d) for d in domains], allowed_ips=ips,
                            allowed_ports=sorted({port, 80, 443, 8080, 3000}),
                            allow_private_targets=allow_private)
    repo.add_scope(rec)
    t = Target(name=name, url=url, owner=owner, authorization_status=AuthorizationStatus(authorization),
               authorization_note=note, scope_policy_id=rec.id)
    repo.add_target(t)
    console.ok(f"added target {t.id}  {t.name}  [{t.authorization_status.value}]")
    click.echo(f"scope: {rec.allowed_domains or rec.allowed_ips} ports={rec.allowed_ports}")


@target.command("list")
@click.pass_context
def target_list(click_ctx):
    """List targets."""
    rows = [[t.id, t.name, t.url, t.authorization_status.value] for t in _ctx(click_ctx).repo.list_targets()]
    console.table(rows, ["ID", "NAME", "URL", "AUTHORIZATION"])


@target.command("show")
@click.argument("target_id")
@click.pass_context
def target_show(click_ctx, target_id):
    """Show a target."""
    app = _ctx(click_ctx)
    t = app.repo.get_target(target_id) or app.repo.get_target_by_name(target_id)
    if not t:
        raise click.ClickException(f"target not found: {target_id}")
    click.echo(_json.dumps(t.model_dump(), indent=2, default=str))


# ---- scope -------------------------------------------------------------
@cli.command("scope")
@click.argument("action", type=click.Choice(["validate"]))
@click.option("--target", "target_arg", required=True)
@click.option("--url", "test_url", required=True, help="URL to test against the target's scope")
@click.pass_context
def scope_cmd(click_ctx, action, target_arg, test_url):
    """Validate whether a URL is in a target's scope."""
    from ..core.scope_factory import default_policy_for_target, policy_from_record
    from ..scope.manager import ScopeManager
    app = _ctx(click_ctx)
    t = app.repo.get_target(target_arg) or app.repo.get_target_by_name(target_arg)
    if not t:
        raise click.ClickException(f"target not found: {target_arg}")
    if t.scope_policy_id and (rec := app.repo.get_scope(t.scope_policy_id)):
        policy = policy_from_record(rec)
    else:
        policy = default_policy_for_target(t, app.settings)
    decision = ScopeManager(policy).check(test_url)
    if decision.allowed:
        console.ok(f"IN SCOPE: {test_url}  ({decision.reason})")
    else:
        console.fail(f"OUT OF SCOPE: {test_url}  ({decision.reason})")


# ---- recon / crawl / fingerprint (ad-hoc) ------------------------------
def _adhoc_scope(target_url, scope, allow_private, ports, max_requests):
    from ..scope.policy import ScopePolicy
    parts = urlsplit(target_url); host = normalize_host(parts.hostname or "")
    domains = list(scope) or ([host] if host and not _is_ip(host) else [])
    ips = [host] if _is_ip(host) else []
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return ScopePolicy(allowed_domains=[normalize_host(d) for d in domains], allowed_ips=ips,
                       allowed_ports=sorted(set(ports) | {port, 80, 443}),
                       allow_private_targets=allow_private, max_requests=max_requests)


@cli.command()
@click.option("--target", "target_url", required=True)
@click.option("--scope", multiple=True)
@click.option("--allow-private", is_flag=True)
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def recon(click_ctx, target_url, scope, allow_private, authorized):
    """Run safe reconnaissance against a target."""
    if not authorized:
        raise click.ClickException("pass --i-am-authorized to confirm authorization")
    app = _ctx(click_ctx)
    from ..scope.manager import ScopeManager
    from ..core.http import SafeHTTPClient
    from ..reconnaissance import ReconEngine

    async def _run():
        policy = _adhoc_scope(target_url, scope, allow_private, tuple(app.settings.scope.allowed_ports), 200)
        sm = ScopeManager(policy)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=policy.request_delay) as client:
            return await ReconEngine(client).run(target_url)

    r = asyncio.run(_run())
    console.header(f"Recon: {target_url}")
    console.table([["Status", str(r.base_status)], ["Server", r.server or "-"],
                   ["Methods", ", ".join(r.allowed_methods) or "-"],
                   ["robots.txt", "yes" if r.robots else "no"],
                   ["security.txt", "yes" if r.security_txt else "no"],
                   ["DNS A", ", ".join(r.dns.get("A", [])) or "-"]], ["FIELD", "VALUE"])
    if r.technologies:
        console.header("Technologies")
        console.table([[t.name, t.version or "-", f"{t.confidence:.2f}", t.evidence] for t in r.technologies],
                      ["TECH", "VERSION", "CONF", "EVIDENCE"])


@cli.command()
@click.option("--target", "target_url", required=True)
@click.option("--scope", multiple=True)
@click.option("--allow-private", is_flag=True)
@click.option("--depth", default=3)
@click.option("--max-pages", default=100)
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def crawl(click_ctx, target_url, scope, allow_private, depth, max_pages, authorized):
    """Crawl a target within scope."""
    if not authorized:
        raise click.ClickException("pass --i-am-authorized to confirm authorization")
    app = _ctx(click_ctx)
    from ..scope.manager import ScopeManager
    from ..core.http import SafeHTTPClient
    from ..crawler import Crawler

    async def _run():
        policy = _adhoc_scope(target_url, scope, allow_private, tuple(app.settings.scope.allowed_ports), max_pages * 3)
        sm = ScopeManager(policy)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=policy.request_delay) as client:
            res = await Crawler(client, max_depth=depth, max_pages=max_pages).crawl(target_url)
            return res, sm

    res, sm = asyncio.run(_run())
    console.header(f"Crawl: {target_url}")
    console.table([[e.method, e.url, str(e.status_code), "api" if e.is_api else ""] for e in res.endpoints],
                  ["METHOD", "URL", "STATUS", "TYPE"])
    click.echo(f"\npages={res.pages_fetched} blocked_out_of_scope={res.blocked} "
               f"off_origin={len(res.off_origin_links)} forms={len(res.forms)}")


@cli.command()
@click.option("--target", "target_url", required=True)
@click.option("--scope", multiple=True)
@click.option("--allow-private", is_flag=True)
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def fingerprint(click_ctx, target_url, scope, allow_private, authorized):
    """Fingerprint technologies on a target."""
    if not authorized:
        raise click.ClickException("pass --i-am-authorized to confirm authorization")
    app = _ctx(click_ctx)
    from ..scope.manager import ScopeManager
    from ..core.http import SafeHTTPClient
    from ..fingerprint import FingerprintEngine

    async def _run():
        policy = _adhoc_scope(target_url, scope, allow_private, tuple(app.settings.scope.allowed_ports), 20)
        sm = ScopeManager(policy)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=0) as client:
            resp = await client.safe_get(target_url)
            return FingerprintEngine().analyze(resp) if resp else []

    techs = asyncio.run(_run())
    console.header(f"Fingerprint: {target_url}")
    console.table([[t.name, t.version or "-", f"{t.confidence:.2f}", ", ".join(t.categories)] for t in techs],
                  ["TECH", "VERSION", "CONF", "CATEGORIES"])


# ---- scan --------------------------------------------------------------
@cli.command()
@click.option("--target", "target_arg", required=True, help="Stored target id/name, or a URL")
@click.option("--profile", type=click.Choice([p.value for p in ScanProfile]), default="safe")
@click.option("--scope", multiple=True, help="Allowed domain (repeatable, for URL targets)")
@click.option("--operator", default="")
@click.option("--allow-private", is_flag=True, help="Permit private/loopback targets (lab).")
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.option("--scan-id-file", default=None, type=click.Path(),
              help="Write the new scan id to this file (for CI pipelines).")
@click.pass_context
def scan(click_ctx, target_arg, profile, scope, operator, allow_private, authorized,
         scan_id_file):
    """Run a full assessment (recon + crawl + checks + findings + correlation)."""
    if not authorized:
        raise click.ClickException("pass --i-am-authorized to confirm authorization")
    app = _ctx(click_ctx)
    from ..core.orchestrator import ScanOrchestrator
    t = _resolve_or_create_target(app, target_arg, scope, allow_private, operator,
                                  tuple(app.settings.scope.allowed_ports))
    console.header(f"Scanning {t.url}  [profile={profile}]")
    orch = ScanOrchestrator(app.settings, app.db)
    scan_obj = asyncio.run(orch.run_scan(t, profile=ScanProfile(profile), operator=operator,
                                         authorization_ack=True))
    console.ok(f"scan {scan_obj.id} {scan_obj.status.value}")
    if scan_id_file:
        # A bare id on one line, so a pipeline can read it without parsing output.
        Path(scan_id_file).write_text(scan_obj.id + "\n", encoding="utf-8")
    click.echo(f"stats: {_json.dumps(scan_obj.stats, default=str)}")
    findings = app.repo.list_findings(scan_obj.id)
    findings.sort(key=lambda f: -(f.priority_score or 0))
    console.header("Findings")
    console.table([[f"{f.priority_score:.0f}", console.sev(f.severity.value), f.title, f.status.value]
                   for f in findings], ["PRIO", "SEVERITY", "TITLE", "STATUS"])
    click.echo(f"\nView details:  velora scan-show {scan_obj.id}")


@cli.command("scans")
@click.pass_context
def scans_list(click_ctx):
    """List scans."""
    app = _ctx(click_ctx)
    rows = [[s.id, s.target_id, s.profile.value, s.status.value,
             str(s.stats.get("findings", "-"))] for s in app.repo.list_scans()]
    console.table(rows, ["SCAN", "TARGET", "PROFILE", "STATUS", "FINDINGS"])


@cli.command("scan-show")
@click.argument("scan_id")
@click.pass_context
def scan_show(click_ctx, scan_id):
    """Show a scan and its findings."""
    app = _ctx(click_ctx)
    s = app.repo.get_scan(scan_id)
    if not s:
        raise click.ClickException(f"scan not found: {scan_id}")
    console.header(f"Scan {s.id}")
    click.echo(f"status={s.status.value} profile={s.profile.value} operator={s.operator}")
    click.echo(f"stats={_json.dumps(s.stats, default=str)}")
    findings = sorted(app.repo.list_findings(scan_id), key=lambda f: -(f.priority_score or 0))
    console.header("Findings")
    console.table([[f.id, f"{f.priority_score:.0f}", console.sev(f.severity.value), f.title, f.status.value]
                   for f in findings], ["ID", "PRIO", "SEVERITY", "TITLE", "STATUS"])


# ---- findings ----------------------------------------------------------
@cli.command()
@click.option("--scan", "scan_id", default=None)
@click.option("--severity", default=None, help="Filter by severity")
@click.pass_context
def findings(click_ctx, scan_id, severity):
    """List findings (optionally filtered)."""
    app = _ctx(click_ctx)
    items = app.repo.list_findings(scan_id)
    if severity:
        items = [f for f in items if f.severity.value.lower() == severity.lower()]
    items.sort(key=lambda f: -(f.priority_score or 0))
    console.table([[f.id, f"{f.priority_score:.0f}", console.sev(f.severity.value), f.title, f.status.value]
                   for f in items], ["ID", "PRIO", "SEVERITY", "TITLE", "STATUS"])


@cli.group()
def finding():
    """Inspect and validate individual findings."""


@finding.command("show")
@click.argument("finding_id")
@click.pass_context
def finding_show(click_ctx, finding_id):
    """Show a finding with evidence."""
    app = _ctx(click_ctx)
    f = app.repo.get_finding(finding_id)
    if not f:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.header(f"{f.title}  [{f.severity.value}]")
    click.echo(f"id={f.id} status={f.status.value} confidence={f.confidence.value} "
               f"priority={f.priority_score}")
    click.echo(f"endpoint={f.method} {f.endpoint}\ncategory={f.category} scanner={f.scanner}\n")
    click.echo(f"Description: {f.description}\n")
    click.echo(f"Impact: {f.impact}\n")
    click.echo(f"Remediation: {f.remediation}\n")
    if f.ai_analysis_id and (a := app.repo.get_ai_analysis(f.ai_analysis_id)):
        console.header("AI analysis (advisory — human validation required)")
        click.echo(f"[{a.provider}] {a.classification} (conf {a.confidence:.2f})\n{a.reasoning_summary}")
    console.header("Evidence")
    for e in app.repo.list_evidence_for_finding(finding_id):
        click.echo(f"- [{e.test_name}] status={e.status_code} conf={e.confidence:.2f}: {e.sanitized_excerpt}")


@finding.command("validate")
@click.argument("finding_id")
@click.option("--operator", required=True)
@click.option("--note", default="")
@click.pass_context
def finding_validate(click_ctx, finding_id, operator, note):
    """Confirm a finding (human action)."""
    from ..findings.service import FindingService
    app = _ctx(click_ctx)
    f = FindingService(app.repo).validate(finding_id, operator, note)
    if not f:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.ok(f"{finding_id} -> {f.status.value} by {operator}")


@finding.command("reject")
@click.argument("finding_id")
@click.option("--operator", required=True)
@click.option("--note", default="")
@click.pass_context
def finding_reject(click_ctx, finding_id, operator, note):
    """Reject a finding as a false positive."""
    from ..findings.service import FindingService
    app = _ctx(click_ctx)
    f = FindingService(app.repo).reject(finding_id, operator, note)
    if not f:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.ok(f"{finding_id} -> {f.status.value} by {operator}")


@finding.command("remediated")
@click.argument("finding_id")
@click.option("--operator", required=True)
@click.option("--note", default="")
@click.pass_context
def finding_remediated(click_ctx, finding_id, operator, note):
    """Mark a finding as remediated."""
    from ..findings.service import FindingService
    app = _ctx(click_ctx)
    f = FindingService(app.repo).mark_remediated(finding_id, operator, note)
    if not f:
        raise click.ClickException(f"finding not found: {finding_id}")
    console.ok(f"{finding_id} -> {f.status.value} by {operator}")


# ---- evidence / attack-map / analyze -----------------------------------
@cli.command()
@click.option("--scan", "scan_id", required=True)
@click.pass_context
def evidence(click_ctx, scan_id):
    """List evidence collected for a scan."""
    app = _ctx(click_ctx)
    rows = [[e.id, e.finding_id or "-", e.test_name, str(e.status_code), e.sanitized_excerpt[:60]]
            for e in app.repo.list_evidence(scan_id)]
    console.table(rows, ["ID", "FINDING", "TEST", "STATUS", "EXCERPT"])


@cli.group("attack-map", invoke_without_command=True)
@click.option("--scan", "scan_id", default=None)
@click.pass_context
def attack_map(click_ctx, scan_id):
    """Explore the evidence-aware attack graph.

    With no subcommand this prints the graph summary (1.x behaviour is preserved).
    """
    click_ctx.obj = _ctx(click_ctx) if click_ctx.obj is None else click_ctx.obj
    if click_ctx.invoked_subcommand is not None:
        return
    if not scan_id:
        raise click.UsageError("--scan is required (or use a subcommand: paths, explain)")
    app = _ctx(click_ctx)
    from ..attack_graph import AttackPathAnalyzer

    analyzer = AttackPathAnalyzer(app.repo.list_nodes(scan_id), app.repo.list_edges(scan_id))
    summary = analyzer.summary()
    console.header(f"Attack graph for {scan_id}")
    click.echo("nodes by kind: " + ", ".join(f"{k}={v}"
               for k, v in sorted(summary["nodes_by_kind"].items())))
    click.echo("edges by relation: " + ", ".join(f"{k}={v}"
               for k, v in sorted(summary["edges_by_relation"].items())))
    click.echo("edges by validation status: " + ", ".join(f"{k}={v}"
               for k, v in sorted(summary["edges_by_validation_status"].items())))
    if summary["hypothesis_edges"]:
        console.warn(f"{summary['hypothesis_edges']} hypothesis edge(s) present "
                     "(require manual validation)")


@attack_map.command("paths")
@click.option("--scan", "scan_id", required=True)
@click.option("--max-depth", default=6, show_default=True)
@click.option("--max-paths", default=25, show_default=True)
@click.option("--evidenced-only", is_flag=True, help="Hide hypothesis paths.")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def attack_map_paths(click_ctx, scan_id, max_depth, max_paths, evidenced_only, as_json):
    """Enumerate attack paths, weakest-link scored."""
    app = _ctx(click_ctx)
    from ..attack_graph import AttackPathAnalyzer

    analyzer = AttackPathAnalyzer(app.repo.list_nodes(scan_id), app.repo.list_edges(scan_id))
    paths = analyzer.find_paths(max_depth=max_depth, max_paths=max_paths)
    if evidenced_only:
        paths = [p for p in paths if not p.is_hypothesis]
    if as_json:
        click.echo(_json.dumps([p.to_dict() for p in paths], indent=2, default=str))
        return
    console.header(f"Attack paths for {scan_id} ({len(paths)} found)")
    if not paths:
        click.echo(click.style("no paths matched", fg="bright_black"))
        return
    for i, path in enumerate(paths, start=1):
        click.echo(f"\n{i}. {path.render()}")
    hypotheses = sum(1 for p in paths if p.is_hypothesis)
    click.echo(f"\n{hypotheses} of {len(paths)} path(s) are hypotheses requiring validation.")


@attack_map.command("explain")
@click.option("--scan", "scan_id", required=True)
@click.option("--index", default=1, show_default=True, help="1-based path index.")
@click.option("--max-depth", default=6, show_default=True)
@click.pass_context
def attack_map_explain(click_ctx, scan_id, index, max_depth):
    """Explain one attack path step by step, labelling observed vs asserted links."""
    app = _ctx(click_ctx)
    from ..attack_graph import AttackPathAnalyzer

    analyzer = AttackPathAnalyzer(app.repo.list_nodes(scan_id), app.repo.list_edges(scan_id))
    paths = analyzer.find_paths(max_depth=max_depth, max_paths=max(index, 25))
    if not paths:
        raise click.ClickException("no attack paths found for this scan")
    if index < 1 or index > len(paths):
        raise click.ClickException(f"path index out of range (1..{len(paths)})")
    path = paths[index - 1]
    console.header(f"Path {index} of {len(paths)}")
    click.echo(analyzer.explain(path))


@cli.command()
@click.option("--finding", "finding_id", required=True)
@click.pass_context
def analyze(click_ctx, finding_id):
    """Run AI-assisted analysis on a finding (advisory only)."""
    from ..ai.service import AIService
    app = _ctx(click_ctx)
    f = app.repo.get_finding(finding_id)
    if not f:
        raise click.ClickException(f"finding not found: {finding_id}")
    a = AIService(app.repo, app.settings.ai).analyze_finding(f)
    console.header(f"AI analysis for {finding_id}  (advisory)")
    click.echo(f"provider={a.provider} model={a.model}")
    click.echo(f"classification={a.classification} confidence={a.confidence:.2f}")
    click.echo(f"human_validation_required={a.human_validation_required}\n")
    click.echo(a.reasoning_summary)


# ---- report ------------------------------------------------------------
@cli.command()
@click.option("--scan", "scan_id", required=True)
@click.option("--format", "formats", multiple=True, default=("html", "json"),
              type=click.Choice(["html", "json", "pdf", "sarif"]))
@click.option("--output-dir", default=None)
@click.pass_context
def report(click_ctx, scan_id, formats, output_dir):
    """Generate a VAPT report."""
    from ..reporting import ReportGenerator
    app = _ctx(click_ctx)
    if not app.repo.get_scan(scan_id):
        raise click.ClickException(f"scan not found: {scan_id}")
    rec = ReportGenerator(app.repo, app.settings).generate(scan_id, list(formats), output_dir)
    for fmt, path in rec.paths.items():
        console.ok(f"{fmt}: {path}")
    for note in rec.unavailable:
        console.warn(note)
    if rec.unavailable:
        # A requested format that could not be produced is not a success. Exit non-zero
        # so a pipeline that asked for a PDF does not proceed as though it got one.
        raise SystemExit(1)


# ---- dashboard ---------------------------------------------------------
@cli.command()
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
@click.pass_context
def dashboard(click_ctx, host, port):
    """Launch the web dashboard/API."""
    import uvicorn
    app = _ctx(click_ctx)
    h = host or app.settings.api.host
    p = port or app.settings.api.port
    console.ok(f"starting Velora dashboard at http://{h}:{p}")
    uvicorn.run("velora.api.app:create_asgi_app", host=h, port=p, factory=True)


# ---- plugins -----------------------------------------------------------
@cli.group()
def plugins():
    """Manage scanner plugins."""


@plugins.command("list")
@click.option("--sdk-only", is_flag=True, help="Show only Plugin SDK 2.0 plugins.")
@click.pass_context
def plugins_list(click_ctx, sdk_only):
    """List available security checks / plugins."""
    from ..plugins import PluginManager
    pm = PluginManager(_ctx(click_ctx).repo)
    items = [p for p in pm.list() if not sdk_only or p.sdk_version != "1.x"]
    rows = [[p.id, p.name, p.category, p.scanner_type or ("safe" if p.safe_mode else "active"),
             p.version, f"sdk {p.sdk_version}", "enabled" if p.enabled else "disabled"]
            for p in items]
    console.table(rows, ["ID", "NAME", "CATEGORY", "TYPE", "VERSION", "SDK", "STATE"])


@plugins.command("load")
@click.option("--dir", "plugin_dir", required=True, type=click.Path(),
              help="Directory of external plugin modules (*.py).")
@click.option("--save", is_flag=True,
              help="Record the directory in the config so every command loads it.")
@click.pass_context
def plugins_load(click_ctx, plugin_dir, save):
    """Load external plugins from a directory.

    The registry is in-memory, so without --save a plugin loaded here is gone when the
    process exits and will NOT be available to `velora scan`. Use --save to record the
    directory in the configuration file; it is then loaded by every later command.

    Loading a plugin executes its Python in this process. Velora validates each SDK
    plugin's declared contract and refuses symlinks that escape the directory, but it
    cannot make untrusted code safe — read a plugin before you load it.
    """
    from pathlib import Path as _Path

    import yaml

    from ..config.settings import default_config_path
    from ..plugins import PluginManager
    app = _ctx(click_ctx)
    resolved = str(_Path(plugin_dir).expanduser().resolve())
    result = PluginManager.load_external_detailed(plugin_dir)
    for plugin_id in result.loaded:
        console.ok(f"loaded {plugin_id}")
    for name, reason in result.rejected.items():
        console.warn(f"rejected {name}: {reason}")
    if not result.loaded and not result.rejected:
        console.warn(f"no plugin modules found in {plugin_dir}")
        return

    if save:
        path = _Path(app.settings.config_path or default_config_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        # Merge into whatever is already in the file rather than writing out the whole
        # resolved settings object. Dumping the resolved settings would bake in values
        # that came from the environment — the database path most of all — and pin them
        # for every later run, which is not what "remember this plugin directory" means.
        existing: dict = {}
        if path.exists():
            try:
                existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise click.ClickException(
                    f"{path} is not valid YAML, refusing to overwrite it: {exc}") from exc
            if not isinstance(existing, dict):
                raise click.ClickException(f"{path} does not contain a YAML mapping")
        scanner = existing.setdefault("scanner", {})
        dirs = list(scanner.get("plugin_dirs") or [])
        if resolved not in dirs:
            dirs.append(resolved)
        scanner["plugin_dirs"] = dirs
        path.write_text(yaml.safe_dump(existing, sort_keys=False), encoding="utf-8")
        app.settings.scanner.plugin_dirs = dirs
        console.ok(f"recorded plugin directory in {path}; every command now loads it")
    elif result.loaded:
        console.warn("not saved: these plugins are loaded for this process only and will "
                     "NOT run in `velora scan`. Re-run with --save to persist.")


@plugins.command("enable")
@click.argument("plugin_id")
@click.pass_context
def plugins_enable(click_ctx, plugin_id):
    """Enable a plugin."""
    from ..plugins import PluginManager
    pm = PluginManager(_ctx(click_ctx).repo)
    if pm.set_enabled(plugin_id, True):
        console.ok(f"enabled {plugin_id}")
    else:
        raise click.ClickException(f"unknown plugin: {plugin_id}")


@plugins.command("disable")
@click.argument("plugin_id")
@click.pass_context
def plugins_disable(click_ctx, plugin_id):
    """Disable a plugin."""
    from ..plugins import PluginManager
    pm = PluginManager(_ctx(click_ctx).repo)
    if pm.set_enabled(plugin_id, False):
        console.ok(f"disabled {plugin_id}")
    else:
        raise click.ClickException(f"unknown plugin: {plugin_id}")


@plugins.command("show")
@click.argument("plugin_id")
@click.pass_context
def plugins_show(click_ctx, plugin_id):
    """Show a plugin's declared contract."""
    from ..plugins import PluginManager
    payload = PluginManager(_ctx(click_ctx).repo).describe(plugin_id)
    if payload is None:
        raise click.ClickException(f"plugin not found: {plugin_id}")
    click.echo(_json.dumps(payload, indent=2, default=str))


# ---- Velora 2.0 command groups ----------------------------------------
# Registered from velora.cli.commands so main.py stays readable. Existing 1.x
# commands above are untouched, preserving backward compatibility.
from .commands import GROUPS as _V2_GROUPS  # noqa: E402

for _group in _V2_GROUPS:
    cli.add_command(_group)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
