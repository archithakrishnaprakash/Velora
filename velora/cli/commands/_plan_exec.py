"""Execution of approved assessment-plan steps.

Each capability maps to an in-process Velora call. There is deliberately no shell-out and
no generic "run this string" path: the mapping below is the complete set of things a plan
can cause to happen, and every branch re-enters a scope-gated code path.
"""
from __future__ import annotations

from typing import Any

from ...benchmark import BenchmarkRunner, LABSHOP_SUITE
from ...core.http import SafeHTTPClient
from ...core.orchestrator import ScanOrchestrator
from ...crawler import Crawler
from ...differential import DifferentialEngine
from ...differential.service import DifferentialService, ExchangeSpec
from ...models.domain import AssessmentPlanStep, Target
from ...models.enums import ScanProfile
from ...reconnaissance import ReconEngine
from ...utils.logging import get_logger
from ..helpers import run_async, scope_manager_for

log = get_logger("planning.exec")


def execute_step(app: Any, step: AssessmentPlanStep, target: Target,
                 scope: tuple[str, ...], allow_private: bool, operator: str) -> str:
    """Run one approved step and return a one-line result summary."""
    capability = step.capability

    if capability in {"scan.safe", "scan.standard"}:
        profile = ScanProfile.SAFE if capability == "scan.safe" else ScanProfile.STANDARD
        scan = run_async(ScanOrchestrator(app.settings, app.db).run_scan(
            target, profile=profile, operator=operator, authorization_ack=True))
        return (f"scan {scan.id} {scan.status.value}: "
                f"{scan.stats.get('findings', 0)} finding(s)")

    if capability == "recon":
        async def _recon():
            sm = scope_manager_for(target.url, scope, allow_private, app.settings, 60)
            async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                      request_delay=sm.policy.request_delay) as client:
                return await ReconEngine(client).run(target.url)
        result = run_async(_recon())
        return (f"recon complete: status={result.base_status} "
                f"methods={len(result.allowed_methods)} techs={len(result.technologies)}")

    if capability == "crawl":
        async def _crawl():
            sm = scope_manager_for(target.url, scope, allow_private, app.settings, 300)
            async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                      request_delay=sm.policy.request_delay) as client:
                return await Crawler(client,
                                     max_depth=app.settings.scanner.max_crawl_depth,
                                     max_pages=app.settings.scanner.max_crawl_pages
                                     ).crawl(target.url)
        result = run_async(_crawl())
        return (f"crawl complete: {result.pages_fetched} page(s), "
                f"{len(result.endpoints)} endpoint(s), {result.blocked} blocked")

    if capability == "differential.compare":
        async def _diff():
            sm = scope_manager_for(target.url, scope, allow_private, app.settings, 20)
            service = DifferentialService(app.repo, DifferentialEngine(ignore_timing=True))
            async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                      request_delay=sm.policy.request_delay) as client:
                return await service.run(
                    client,
                    ExchangeSpec(url=target.url, label="baseline"),
                    ExchangeSpec(url=target.url, label="candidate"),
                    label="plan-step baseline stability check")
        result, observation = run_async(_diff())
        if result is None:
            return "differential blocked by scope policy"
        return (f"differential {observation.id if observation else '-'}: "
                f"{len(result.differences)} difference(s) "
                f"({', '.join(result.classifications) or 'none'})")

    if capability == "benchmark":
        scans = app.repo.list_scans(target.id)
        if not scans:
            return "benchmark skipped: no scan available to score"
        report = BenchmarkRunner(app.repo).score(LABSHOP_SUITE, scans[-1].id, target.url)
        BenchmarkRunner(app.repo).persist(report)
        m = report.metrics
        return (f"benchmark: precision={m.precision:.2f} recall={m.recall:.2f} "
                f"TP={m.true_positives} FP={m.false_positives} FN={m.false_negatives}")

    if capability == "authz.matrix":
        return ("authz.matrix requires an authorization plan file; run "
                "`velora authz run --config <plan.yaml> --i-am-authorized`")

    if capability == "workflow.assess":
        return ("workflow.assess requires an authorized workflow definition; run "
                "`velora workflow run --config <workflow.yaml> --i-am-authorized`")

    # Unreachable: the planner only emits catalog keys, and the catalog is covered above.
    log.warning("no executor mapped for capability %s", capability)
    return f"no executor is mapped for capability '{capability}'; nothing was run"
