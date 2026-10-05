"""ASGI application factory for the Velora dashboard and JSON API.

Every page renders data that is actually stored in the Velora database. Nothing on
this dashboard is synthesised, estimated, or decorative: a widget with no underlying
rows renders an explicit empty state rather than a plausible-looking placeholder.

The dashboard is read-only by design. It never launches scans, never mutates
findings, and never performs a network request against a target — those actions go
through the CLI, where scope enforcement, authorization acknowledgement and audit
logging live.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from .. import __version__
from ..config.settings import Settings, load_settings
from ..database.db import Database
from ..database.repository import Repository
from ..posture import band_for
from ..scanners import registry
from . import charts

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_TEMPLATES.env.filters["sevclass"] = lambda s: {
    "Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium",
    "Low": "sev-low", "Informational": "sev-info"}.get(s, "sev-info")
_TEMPLATES.env.filters["shorten"] = lambda s, n=64: (
    str(s) if len(str(s)) <= n else str(s)[: n - 1] + "…")
_TEMPLATES.env.globals["charts"] = charts


# Navigation: (section title, [(href, label)]). Mirrors the documented page set.
NAV: list[tuple[str, list[tuple[str, str]]]] = [
    ("Engagement", [
        ("/", "Dashboard"),
        ("/engagements", "Engagements"),
        ("/targets", "Targets"),
        ("/scans", "Scans"),
    ]),
    ("Attack surface", [
        ("/attack-surface", "Attack Surface"),
        ("/attack-graph", "Attack Graph"),
        ("/differential", "Differential"),
    ]),
    ("Findings", [
        ("/findings", "Findings"),
        ("/evidence", "Evidence"),
        ("/ai-analyst", "AI Analyst"),
        ("/authorization", "Authorization Testing"),
        ("/workflows", "Workflows"),
    ]),
    ("Lifecycle", [
        ("/remediation", "Remediation"),
        ("/regression", "Regression"),
        ("/posture", "Security Posture"),
        ("/benchmarks", "Benchmarks"),
    ]),
    ("Delivery", [
        ("/plans", "Assessment Plans"),
        ("/reports", "Reports"),
        ("/ci-cd", "CI/CD Gate"),
        ("/plugins", "Plugins"),
        ("/audit", "Audit Log"),
        ("/settings", "Settings"),
    ]),
]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defensive headers for the dashboard itself (Feature 19)."""

    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        return resp


def _dump(items: Any) -> Any:
    """Serialise pydantic models to plain JSON-safe structures."""
    if isinstance(items, list):
        return [json.loads(i.model_dump_json()) for i in items]
    if items is None:
        return None
    return json.loads(items.model_dump_json())


def create_asgi_app(settings: Settings | None = None) -> Starlette:
    settings = settings or load_settings()
    db = Database(settings)
    db.init()

    def repo() -> Repository:
        return Repository(db.conn)

    # ------------------------------------------------------------------
    # shared helpers
    # ------------------------------------------------------------------
    def base_ctx(request: Request, page: str, **extra: Any) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "request": request,
            "title": settings.dashboard.title,
            "nav": NAV,
            "page": page,
            "version": __version__,
            "path": request.url.path,
        }
        ctx.update(extra)
        return ctx

    def scan_scope(request: Request, r: Repository) -> tuple[str | None, list]:
        """Resolve the selected scan from ?scan=, defaulting to the most recent."""
        scans = sorted(r.list_scans(), key=lambda s: s.started_at or s.id, reverse=True)
        wanted = request.query_params.get("scan", "").strip()
        if wanted and any(s.id == wanted for s in scans):
            return wanted, scans
        if wanted:
            return None, scans          # explicit but unknown: show nothing, not the wrong scan
        return (scans[0].id if scans else None), scans

    def render(request: Request, template: str, ctx: dict[str, Any]):
        return _TEMPLATES.TemplateResponse(request, template, ctx)

    # ==================================================================
    # Pages
    # ==================================================================
    async def page_dashboard(request: Request):
        r = repo()
        scans = sorted(r.list_scans(), key=lambda s: s.started_at or s.id)
        targets = r.list_targets()
        findings = r.list_findings()
        by_sev = Counter(f.severity.value for f in findings)
        by_status = Counter(f.status.value for f in findings)
        endpoints = sum(len(r.list_endpoints(s.id)) for s in scans)
        technologies: Counter = Counter()
        for s in scans:
            for tech in r.list_technologies(s.id):
                technologies[tech.name] += 1

        postures = sorted(r.list_postures(), key=lambda p: p.created_at)
        latest_posture = postures[-1] if postures else None
        # One band definition, shared with the CLI and the report.
        posture_band = band_for(latest_posture.overall) if latest_posture else ""

        history = [(s, len(r.list_findings(s.id))) for s in scans]
        regressions = r.list_regressions()
        reg_mix = Counter(x.change.value for x in regressions)
        new_findings = reg_mix.get("NEW_FINDING", 0)
        fixed_findings = reg_mix.get("FIXED_FINDING", 0)
        remediations = r.list_remediations()
        rem_mix = Counter(x.status.value for x in remediations)
        analyses = r.list_ai_analyses()
        ai_mix = Counter(a.validation_status.value for a in analyses)
        benchmark_runs = sorted(r.list_benchmark_runs(), key=lambda b: b.created_at)

        ctx = base_ctx(
            request, "dashboard",
            targets=targets, scans=list(reversed(scans)), findings_total=len(findings),
            by_sev=dict(by_sev), by_status=dict(by_status), endpoints=endpoints,
            technologies=dict(technologies), posture=latest_posture,
            posture_band=posture_band,
            history=[count for _, count in history],
            history_labels=[s.id for s, _ in history],
            new_findings=new_findings, fixed_findings=fixed_findings,
            regressions_total=len(regressions), rem_mix=dict(rem_mix),
            ai_total=len(analyses), ai_mix=dict(ai_mix),
            benchmark=benchmark_runs[-1] if benchmark_runs else None,
            confirmed=by_status.get("Confirmed", 0),
        )
        return render(request, "dashboard.html", ctx)

    async def page_engagements(request: Request):
        r = repo()
        engagements = r.list_engagements()
        rows = []
        for e in engagements:
            scans = [s for s in r.list_scans() if s.engagement_id == e.id]
            findings = [f for s in scans for f in r.list_findings(s.id)]
            rows.append({"engagement": e, "scans": len(scans), "findings": len(findings),
                         "identities": len(r.list_identities(e.id))})
        return render(request, "engagements.html",
                      base_ctx(request, "engagements", rows=rows))

    async def page_targets(request: Request):
        r = repo()
        rows = []
        for t in r.list_targets():
            scans = [s for s in r.list_scans() if s.target_id == t.id]
            rows.append({"target": t, "scans": len(scans),
                         "scope": r.get_scope(t.scope_policy_id) if t.scope_policy_id else None,
                         "last_scan": max((s.started_at for s in scans if s.started_at),
                                          default=None)})
        return render(request, "targets.html", base_ctx(request, "targets", rows=rows))

    async def page_scans(request: Request):
        r = repo()
        rows = []
        for s in sorted(r.list_scans(), key=lambda s: s.started_at or s.id, reverse=True):
            findings = r.list_findings(s.id)
            rows.append({"scan": s, "target": r.get_target(s.target_id),
                         "findings": len(findings),
                         "by_sev": dict(Counter(f.severity.value for f in findings))})
        return render(request, "scans.html", base_ctx(request, "scans", rows=rows))

    async def page_scan_detail(request: Request):
        r = repo()
        scan_id = request.path_params["scan_id"]
        scan = r.get_scan(scan_id)
        if not scan:
            return _TEMPLATES.TemplateResponse(
                request, "notfound.html",
                base_ctx(request, "scans", what=f"Scan {scan_id}"), status_code=404)
        findings = sorted(r.list_findings(scan_id), key=lambda f: -(f.priority_score or 0))
        gate = r.list_gate_results(scan_id)
        ctx = base_ctx(
            request, "scans", scan=scan, target=r.get_target(scan.target_id),
            findings=findings, by_sev=dict(Counter(f.severity.value for f in findings)),
            by_status=dict(Counter(f.status.value for f in findings)),
            endpoints=r.list_endpoints(scan_id),
            technologies=r.list_technologies(scan_id),
            hosts=r.list_hosts(scan_id),
            nodes=r.list_nodes(scan_id), edges=r.list_edges(scan_id),
            events=r.list_events(scan_id), reports=r.list_reports(scan_id),
            gate=gate[-1] if gate else None,
            regressions=r.list_regressions(scan_id),
        )
        return render(request, "scan.html", ctx)

    async def page_attack_surface(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        endpoints = r.list_endpoints(scan_id) if scan_id else []
        technologies = r.list_technologies(scan_id) if scan_id else []
        hosts = r.list_hosts(scan_id) if scan_id else []
        tech_counts: Counter = Counter()
        for t in technologies:
            for cat in (t.categories or ["uncategorised"]):
                tech_counts[cat] += 1
        method_counts = Counter(e.method for e in endpoints)
        ctx = base_ctx(request, "attack-surface", scans=scans, scan_id=scan_id,
                       endpoints=endpoints, technologies=technologies, hosts=hosts,
                       tech_counts=dict(tech_counts), method_counts=dict(method_counts),
                       api_endpoints=len([e for e in endpoints if e.is_api]),
                       param_endpoints=len([e for e in endpoints if e.parameters]))
        return render(request, "attack_surface.html", ctx)

    async def page_findings(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        severity = request.query_params.get("severity", "").strip()
        status = request.query_params.get("status", "").strip()
        findings = r.list_findings(scan_id) if scan_id else []
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
        if status:
            findings = [f for f in findings if f.status.value == status]
        findings.sort(key=lambda f: -(f.priority_score or 0))
        ctx = base_ctx(request, "findings", scans=scans, scan_id=scan_id,
                       findings=findings, severity=severity, status=status,
                       by_sev=dict(Counter(f.severity.value for f in findings)),
                       by_status=dict(Counter(f.status.value for f in findings)),
                       severities=charts.SEVERITY_ORDER)
        return render(request, "findings.html", ctx)

    async def page_finding_detail(request: Request):
        r = repo()
        finding_id = request.path_params["finding_id"]
        finding = r.get_finding(finding_id)
        if not finding:
            return _TEMPLATES.TemplateResponse(
                request, "notfound.html",
                base_ctx(request, "findings", what=f"Finding {finding_id}"),
                status_code=404)
        analyses = r.list_ai_analyses_for_finding(finding_id)
        ctx = base_ctx(
            request, "findings", finding=finding, scan=r.get_scan(finding.scan_id),
            evidence=r.list_evidence_for_finding(finding_id),
            analyses=analyses,
            remediation=r.get_remediation_for_finding(finding_id),
            retests=r.list_retests(finding_id),
            reproduction=r.get_reproduction_for_finding(finding_id),
            knowledge=r.list_knowledge_relationships(finding_id),
        )
        return render(request, "finding_detail.html", ctx)

    async def page_evidence(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        evidence = r.list_evidence(scan_id) if scan_id else []
        findings = {f.id: f for f in (r.list_findings(scan_id) if scan_id else [])}
        ctx = base_ctx(request, "evidence", scans=scans, scan_id=scan_id,
                       evidence=evidence, findings=findings,
                       by_test=dict(Counter(e.test_name or "unnamed" for e in evidence)))
        return render(request, "evidence.html", ctx)

    async def page_attack_graph(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        nodes = r.list_nodes(scan_id) if scan_id else []
        edges = r.list_edges(scan_id) if scan_id else []
        node_by_id = {n.id: n for n in nodes}
        ctx = base_ctx(request, "attack-graph", scans=scans, scan_id=scan_id,
                       nodes=nodes, edges=edges, node_by_id=node_by_id,
                       by_kind=dict(Counter(n.kind for n in nodes)),
                       by_relation=dict(Counter(e.relation for e in edges)),
                       hypothetical=len([e for e in edges if e.hypothesis]))
        return render(request, "attack_graph.html", ctx)

    async def page_differential(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        diffs = r.list_differentials(scan_id) if scan_id else []
        classes: Counter = Counter()
        for d in diffs:
            classes.update(d.classifications)
        ctx = base_ctx(request, "differential", scans=scans, scan_id=scan_id,
                       diffs=diffs, classes=dict(classes),
                       changed=len([d for d in diffs if d.differences]))
        return render(request, "differential.html", ctx)

    async def page_ai_analyst(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        analyses = r.list_ai_analyses(scan_id) if scan_id else []
        ctx = base_ctx(request, "ai-analyst", scans=scans, scan_id=scan_id,
                       analyses=analyses,
                       by_state=dict(Counter(a.validation_status.value for a in analyses)),
                       by_provider=dict(Counter(a.provider or "unknown" for a in analyses)),
                       unsanitized=len([a for a in analyses if not a.prompt_sanitized]))
        return render(request, "ai_analyst.html", ctx)

    async def page_authorization(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        tests = r.list_authz_tests(scan_id) if scan_id else []
        identities = {i.id: i for i in r.list_identities()}
        outcomes = Counter(t.outcome.value for t in tests)
        weaknesses = [t for t in tests if t.outcome.is_weakness]
        ctx = base_ctx(request, "authorization", scans=scans, scan_id=scan_id,
                       tests=tests, identities=identities, outcomes=dict(outcomes),
                       weaknesses=weaknesses,
                       by_role=dict(Counter(t.identity_role.value for t in tests)))
        return render(request, "authorization.html", ctx)

    async def page_workflows(request: Request):
        r = repo()
        rows = []
        for w in r.list_workflows():
            steps = r.list_workflow_steps(w.id)
            rows.append({"workflow": w, "steps": steps,
                         "outcomes": dict(Counter(s.outcome.value for s in steps))})
        return render(request, "workflows.html", base_ctx(request, "workflows", rows=rows))

    async def page_remediation(request: Request):
        r = repo()
        actions = r.list_remediations()
        rows = []
        for a in actions:
            finding = r.get_finding(a.finding_id)
            rows.append({"action": a, "finding": finding,
                         "retests": r.list_retests(a.finding_id)})
        ctx = base_ctx(request, "remediation", rows=rows,
                       by_status=dict(Counter(a.status.value for a in actions)))
        return render(request, "remediation.html", ctx)

    async def page_regression(request: Request):
        r = repo()
        scan_id, scans = scan_scope(request, r)
        results = r.list_regressions(scan_id) if scan_id else []
        ctx = base_ctx(request, "regression", scans=scans, scan_id=scan_id,
                       results=results,
                       by_change=dict(Counter(x.change.value for x in results)),
                       by_sev=dict(Counter(x.severity for x in results if x.severity)))
        return render(request, "regression.html", ctx)

    async def page_posture(request: Request):
        r = repo()
        snapshots = sorted(r.list_postures(), key=lambda p: p.created_at, reverse=True)
        latest = snapshots[0] if snapshots else None
        band = band_for(latest.overall) if latest else ""
        ctx = base_ctx(request, "posture", snapshots=snapshots, latest=latest, band=band,
                       trend=[int(round(p.overall)) for p in reversed(snapshots)])
        return render(request, "posture.html", ctx)

    async def page_benchmarks(request: Request):
        r = repo()
        runs = sorted(r.list_benchmark_runs(), key=lambda b: b.created_at, reverse=True)
        latest = runs[0] if runs else None
        ctx = base_ctx(request, "benchmarks", runs=runs, latest=latest,
                       cases=r.list_benchmark_cases())
        return render(request, "benchmarks.html", ctx)

    async def page_plans(request: Request):
        r = repo()
        rows = []
        for p in r.list_plans():
            steps = r.list_plan_steps(p.id)
            rows.append({"plan": p, "steps": steps,
                         "statuses": dict(Counter(s.status.value for s in steps))})
        return render(request, "plans.html", base_ctx(request, "plans", rows=rows))

    async def page_reports(request: Request):
        r = repo()
        rows = []
        for s in sorted(r.list_scans(), key=lambda s: s.started_at or s.id, reverse=True):
            for rep in r.list_reports(s.id):
                rows.append({"report": rep, "scan": s})
        return render(request, "reports.html", base_ctx(request, "reports", rows=rows))

    async def page_ci_cd(request: Request):
        r = repo()
        results = sorted(r.list_gate_results(), key=lambda g: g.created_at, reverse=True)
        ctx = base_ctx(request, "ci-cd", results=results,
                       by_decision=dict(Counter(g.decision.value for g in results)))
        return render(request, "ci_cd.html", ctx)

    async def page_plugins(request: Request):
        checks = registry.all()
        ctx = base_ctx(request, "plugins", checks=checks,
                       by_category=dict(Counter(c.category for c in checks)),
                       safe=len([c for c in checks if c.safe_mode]))
        return render(request, "plugins.html", ctx)

    async def page_audit(request: Request):
        r = repo()
        entries = r.list_audit(limit=500)
        ctx = base_ctx(request, "audit", entries=entries,
                       by_action=dict(Counter(e.action for e in entries)))
        return render(request, "audit.html", ctx)

    async def page_settings(request: Request):
        ctx = base_ctx(request, "settings", cfg=settings,
                       checks=len(registry.all()))
        return render(request, "settings.html", ctx)

    # ==================================================================
    # JSON API
    # ==================================================================
    async def api_health(request: Request):
        return JSONResponse({"status": "ok", "version": __version__,
                             "checks": len(registry.all())})

    async def api_scans(request: Request):
        return JSONResponse(_dump(repo().list_scans()))

    async def api_targets(request: Request):
        return JSONResponse(_dump(repo().list_targets()))

    async def api_findings(request: Request):
        return JSONResponse(_dump(repo().list_findings(
            request.query_params.get("scan") or None)))

    async def api_finding(request: Request):
        finding = repo().get_finding(request.path_params["finding_id"])
        if not finding:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(_dump(finding))

    async def api_evidence(request: Request):
        scan_id = request.query_params.get("scan")
        if not scan_id:
            return JSONResponse({"error": "scan query parameter is required"},
                                status_code=400)
        return JSONResponse(_dump(repo().list_evidence(scan_id)))

    async def api_graph(request: Request):
        r = repo()
        scan_id = request.path_params["scan_id"]
        # An unknown id used to return an empty graph, which is indistinguishable from
        # a scan that genuinely produced no nodes.
        if not r.get_scan(scan_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({"nodes": _dump(r.list_nodes(scan_id)),
                             "edges": _dump(r.list_edges(scan_id))})

    async def api_plugins(request: Request):
        return JSONResponse([{"id": c.id, "name": c.name, "category": c.category,
                              "safe_mode": c.safe_mode, "severity": c.severity.value,
                              "description": c.description} for c in registry.all()])

    async def api_engagements(request: Request):
        return JSONResponse(_dump(repo().list_engagements()))

    async def api_identities(request: Request):
        # Identities expose only a secret *reference*; credential values are never stored.
        return JSONResponse(_dump(repo().list_identities(
            request.query_params.get("engagement") or None)))

    async def api_differential(request: Request):
        return JSONResponse(_dump(repo().list_differentials(
            request.query_params.get("scan") or None)))

    async def api_authorization_tests(request: Request):
        return JSONResponse(_dump(repo().list_authz_tests(
            request.query_params.get("scan") or None)))

    async def api_workflows(request: Request):
        r = repo()
        out = []
        for w in r.list_workflows():
            item = _dump(w)
            item["steps"] = _dump(r.list_workflow_steps(w.id))
            out.append(item)
        return JSONResponse(out)

    async def api_assessment_plans(request: Request):
        r = repo()
        out = []
        for p in r.list_plans():
            item = _dump(p)
            item["steps"] = _dump(r.list_plan_steps(p.id))
            out.append(item)
        return JSONResponse(out)

    async def api_remediation(request: Request):
        r = repo()
        out = []
        for a in r.list_remediations():
            item = _dump(a)
            item["retests"] = _dump(r.list_retests(a.finding_id))
            out.append(item)
        return JSONResponse(out)

    async def api_regression(request: Request):
        return JSONResponse(_dump(repo().list_regressions(
            request.query_params.get("scan") or None)))

    async def api_benchmark(request: Request):
        return JSONResponse(_dump(repo().list_benchmark_runs()))

    async def api_posture(request: Request):
        return JSONResponse(_dump(repo().list_postures(
            request.query_params.get("target") or None)))

    async def api_reproduction(request: Request):
        finding_id = request.query_params.get("finding")
        if not finding_id:
            return JSONResponse({"error": "finding query parameter is required"},
                                status_code=400)
        record = repo().get_reproduction_for_finding(finding_id)
        if not record:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(_dump(record))

    async def api_security_gate(request: Request):
        return JSONResponse(_dump(repo().list_gate_results(
            request.query_params.get("scan") or None)))

    async def api_ai_analyses(request: Request):
        return JSONResponse(_dump(repo().list_ai_analyses(
            request.query_params.get("scan") or None)))

    async def api_audit(request: Request):
        return JSONResponse(_dump(repo().list_audit(limit=500)))

    async def api_sarif(request: Request):
        from ..reporting.sarif import build_sarif
        scan_id = request.path_params["scan_id"]
        r = repo()
        if not r.get_scan(scan_id):
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(build_sarif(r, scan_id))

    async def not_found(request: Request, exc: Exception):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "not found"}, status_code=404)
        return _TEMPLATES.TemplateResponse(
            request, "notfound.html",
            base_ctx(request, "", what=request.url.path), status_code=404)

    routes = [
        Route("/", page_dashboard),
        Route("/engagements", page_engagements),
        Route("/targets", page_targets),
        Route("/scans", page_scans),
        Route("/scans/{scan_id}", page_scan_detail),
        Route("/attack-surface", page_attack_surface),
        Route("/attack-graph", page_attack_graph),
        Route("/differential", page_differential),
        Route("/findings", page_findings),
        Route("/findings/{finding_id}", page_finding_detail),
        Route("/evidence", page_evidence),
        Route("/ai-analyst", page_ai_analyst),
        Route("/authorization", page_authorization),
        Route("/workflows", page_workflows),
        Route("/remediation", page_remediation),
        Route("/regression", page_regression),
        Route("/posture", page_posture),
        Route("/benchmarks", page_benchmarks),
        Route("/plans", page_plans),
        Route("/reports", page_reports),
        Route("/ci-cd", page_ci_cd),
        Route("/plugins", page_plugins),
        Route("/audit", page_audit),
        Route("/settings", page_settings),
        # ---- JSON API ----
        Route("/api/health", api_health),
        Route("/api/targets", api_targets),
        Route("/api/scans", api_scans),
        Route("/api/scans/{scan_id}/graph", api_graph),
        Route("/api/scans/{scan_id}/sarif", api_sarif),
        Route("/api/findings", api_findings),
        Route("/api/findings/{finding_id}", api_finding),
        Route("/api/evidence", api_evidence),
        Route("/api/plugins", api_plugins),
        Route("/api/engagements", api_engagements),
        Route("/api/identities", api_identities),
        Route("/api/differential", api_differential),
        Route("/api/authorization-tests", api_authorization_tests),
        Route("/api/workflows", api_workflows),
        Route("/api/assessment-plans", api_assessment_plans),
        Route("/api/remediation", api_remediation),
        Route("/api/regression", api_regression),
        Route("/api/benchmark", api_benchmark),
        Route("/api/posture", api_posture),
        Route("/api/reproduction", api_reproduction),
        Route("/api/security-gate", api_security_gate),
        Route("/api/ai-analyses", api_ai_analyses),
        Route("/api/audit", api_audit),
    ]
    middleware = [Middleware(SecurityHeadersMiddleware)]
    if settings.api.cors_allow_origins:
        # Only ever the explicitly configured origins — never "*", which would let any
        # site read this dashboard's data from a victim's browser.
        from starlette.middleware.cors import CORSMiddleware
        origins = [o for o in settings.api.cors_allow_origins if o != "*"]
        if origins:
            middleware.append(Middleware(
                CORSMiddleware, allow_origins=origins,
                allow_methods=["GET"], allow_headers=["accept", "content-type"],
                allow_credentials=False))
    app = Starlette(routes=routes, middleware=middleware,
                    exception_handlers={404: not_found})
    app.state.settings = settings
    app.state.db = db
    return app
