"""`velora benchmark` — objectively measure Velora's own detection accuracy."""
from __future__ import annotations

import json
from pathlib import Path

import click

from ...benchmark import BenchmarkRunner, discover_suites
from ...core.orchestrator import ScanOrchestrator
from ...models.enums import ScanProfile
from ...utils import console
from ..helpers import (
    AUTH_HELP,
    app_ctx,
    echo_json,
    require_authorization,
    resolve_or_create_target,
    run_async,
)

DEFAULT_SUITE_DIR = "examples/labs"


@click.group()
def benchmark() -> None:
    """Measure Velora against ground-truth benchmark suites."""


@benchmark.command("list")
@click.option("--suite-dir", default=DEFAULT_SUITE_DIR, show_default=True)
@click.option("--json", "as_json", is_flag=True)
def benchmark_list(suite_dir, as_json):
    """List available benchmark suites and their ground-truth cases."""
    suites = discover_suites(suite_dir)
    if as_json:
        echo_json({name: s.to_dict() for name, s in suites.items()})
        return
    console.header(f"Benchmark suites ({len(suites)})")
    console.table(
        [[s.name, s.application[:26], str(len(s)), str(len(s.positive_cases)),
          str(len(s.negative_cases))] for s in suites.values()],
        ["SUITE", "APPLICATION", "CASES", "POSITIVE", "NEGATIVE"])
    for suite in suites.values():
        console.header(f"{suite.name} cases")
        console.table(
            [[c.name[:40], c.expected_check_id, c.endpoint_path[:22],
              "detect" if c.expected_detection else "stay silent", c.cwe_id]
             for c in suite.cases],
            ["CASE", "CHECK", "ENDPOINT", "GROUND TRUTH", "CWE"])


@benchmark.command("run")
@click.option("--suite", "suite_name", default="labshop", show_default=True)
@click.option("--suite-dir", default=DEFAULT_SUITE_DIR, show_default=True)
@click.option("--target", "target_arg", required=True, help="Benchmark target URL or id.")
@click.option("--profile", type=click.Choice([p.value for p in ScanProfile]), default="safe")
@click.option("--scan", "existing_scan", default=None,
              help="Score an existing scan instead of running a new one.")
@click.option("--allow-private", is_flag=True)
@click.option("--operator", default="")
@click.option("--output", default=None, type=click.Path(), help="Write the JSON report here.")
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def benchmark_run(click_ctx, suite_name, suite_dir, target_arg, profile, existing_scan,
                  allow_private, operator, output, authorized):
    """Run a benchmark suite and report MEASURED metrics.

    Metrics come from a real scan compared against ground truth. Nothing is assumed.
    """
    app = app_ctx(click_ctx)
    suites = discover_suites(suite_dir)
    suite = suites.get(suite_name)
    if suite is None:
        raise click.ClickException(
            f"unknown suite '{suite_name}'. Available: {', '.join(sorted(suites))}")

    if existing_scan:
        scan = app.repo.get_scan(existing_scan)
        if scan is None:
            raise click.ClickException(f"scan not found: {existing_scan}")
        target = app.repo.get_target(scan.target_id)
        target_url = target.url if target else target_arg
    else:
        require_authorization(authorized)
        target = resolve_or_create_target(app, target_arg, (), allow_private, operator,
                                          tuple(app.settings.scope.allowed_ports))
        target_url = target.url
        console.header(f"Running benchmark scan against {target_url}")
        scan = run_async(ScanOrchestrator(app.settings, app.db).run_scan(
            target, profile=ScanProfile(profile), operator=operator, authorization_ack=True))

    runner = BenchmarkRunner(app.repo)
    report = runner.score(suite, scan.id, target_url)
    runner.persist(report)

    if output:
        Path(output).write_text(json.dumps(report.to_dict(), indent=2, default=str),
                                encoding="utf-8")
        console.ok(f"wrote JSON report: {output}")

    _print_report(report)


def _print_report(report) -> None:
    m = report.metrics
    console.header(f"Benchmark: {report.suite}  (Velora {report.velora_version})")
    console.table(
        [[c.outcome.value, c.case.name[:40], c.case.expected_check_id,
          "yes" if c.detected else "no", "yes" if c.evidence_satisfied else "-"]
         for c in report.case_results],
        ["OUTCOME", "CASE", "CHECK", "DETECTED", "EVIDENCE OK"])

    console.header("Measured metrics")
    console.table([
        ["True positives", str(m.true_positives)],
        ["True negatives", str(m.true_negatives)],
        ["False positives", str(m.false_positives)],
        ["False negatives", str(m.false_negatives)],
        ["Precision", f"{m.precision:.3f}"],
        ["Recall", f"{m.recall:.3f}"],
        ["F1", f"{m.f1:.3f}"],
        ["False positive rate", f"{m.false_positive_rate:.3f}"],
        ["False negative rate", f"{m.false_negative_rate:.3f}"],
        ["Detection coverage", f"{m.detection_coverage:.3f}"],
        ["Evidence completeness", f"{report.evidence_completeness:.3f}"],
        ["AI agreement", "not measured (no AI analysis run)"
            if report.ai_agreement is None else f"{report.ai_agreement:.3f}"],
        ["Human validation rate", "n/a" if report.human_validation_rate is None
            else f"{report.human_validation_rate:.3f}"],
    ], ["METRIC", "VALUE"])

    if report.uncovered:
        console.header(f"Uncovered detections ({len(report.uncovered)})")
        click.echo("Findings no benchmark case describes. Counted as NEITHER true nor "
                   "false positives:")
        for item in report.uncovered[:12]:
            click.echo(f"  - [{item['severity']}] {item['title'][:60]} ({item['check']})")

    console.header("Scope of these numbers")
    for note in report.to_dict()["notes"]:
        click.echo(f"  * {note}")


@benchmark.command("report")
@click.option("--run", "run_id", default=None, help="Benchmark run id (default: latest).")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def benchmark_report(click_ctx, run_id, as_json):
    """Show a stored benchmark run."""
    app = app_ctx(click_ctx)
    runs = app.repo.list_benchmark_runs()
    if not runs:
        console.warn("no benchmark runs recorded — run `velora benchmark run` first")
        return
    run = app.repo.get_benchmark_run(run_id) if run_id else runs[-1]
    if run is None:
        raise click.ClickException(f"benchmark run not found: {run_id}")
    if as_json:
        echo_json(run.model_dump())
        return
    console.header(f"Benchmark run {run.id}  suite={run.suite}")
    click.echo(f"target={run.target_url}  scan={run.scan_id}  velora={run.velora_version}")
    console.table([
        ["Cases", str(run.total_cases)],
        ["TP / TN / FP / FN",
         f"{run.true_positives} / {run.true_negatives} / "
         f"{run.false_positives} / {run.false_negatives}"],
        ["Precision", f"{run.precision:.3f}"],
        ["Recall", f"{run.recall:.3f}"],
        ["F1", f"{run.f1:.3f}"],
        ["FPR / FNR", f"{run.false_positive_rate:.3f} / {run.false_negative_rate:.3f}"],
        ["Detection coverage", f"{run.detection_coverage:.3f}"],
        ["Evidence completeness", f"{run.evidence_completeness:.3f}"],
    ], ["METRIC", "VALUE"])
    console.header("Per case")
    console.table([[c.get("outcome", ""), c.get("case", "")[:44], c.get("check", "")]
                   for c in run.per_case], ["OUTCOME", "CASE", "CHECK"])
