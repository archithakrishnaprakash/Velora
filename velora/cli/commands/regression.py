"""`velora regression` — scan-to-scan security regression analysis."""
from __future__ import annotations

import click

from ...models.enums import RegressionChange, Severity
from ...regression import RegressionEngine, severity_delta
from ...utils import console
from ..helpers import app_ctx, echo_json

_CHANGE_COLOR = {
    RegressionChange.NEW_FINDING: "yellow",
    RegressionChange.FIXED_FINDING: "green",
    RegressionChange.PERSISTING_FINDING: "white",
    RegressionChange.REINTRODUCED_FINDING: "red",
    RegressionChange.NEW_ENDPOINT: "cyan",
    RegressionChange.REMOVED_ENDPOINT: "cyan",
    RegressionChange.CHANGED_TECHNOLOGY: "bright_black",
    RegressionChange.CHANGED_SECURITY_CONTROL: "magenta",
}


def _style(change: RegressionChange) -> str:
    return click.style(change.value, fg=_CHANGE_COLOR.get(change, "white"),
                       bold=change == RegressionChange.REINTRODUCED_FINDING)


@click.group()
def regression() -> None:
    """Compare two scans and classify what changed."""


@regression.command("compare")
@click.option("--previous", "previous_id", required=True)
@click.option("--current", "current_id", required=True)
@click.option("--no-persist", is_flag=True, help="Compute without storing the results.")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def regression_compare(click_ctx, previous_id, current_id, no_persist, as_json):
    """Compare a previous scan against a current scan."""
    app = app_ctx(click_ctx)
    previous = app.repo.get_scan(previous_id)
    current = app.repo.get_scan(current_id)
    if previous is None:
        raise click.ClickException(f"scan not found: {previous_id}")
    if current is None:
        raise click.ClickException(f"scan not found: {current_id}")
    if previous.target_id != current.target_id:
        console.warn("the two scans target different targets; the comparison may be meaningless")

    summary = RegressionEngine(app.repo).compare(previous, current, persist=not no_persist)
    delta = severity_delta(app.repo.list_findings(previous_id),
                           app.repo.list_findings(current_id))
    if as_json:
        echo_json({**summary.to_dict(), "severity_delta": delta})
        return

    console.header(f"Regression: {previous_id} -> {current_id}")
    console.table(
        [[s.value, str(delta["previous"][s.value]), str(delta["current"][s.value]),
          f"{delta['current'][s.value] - delta['previous'][s.value]:+d}"]
         for s in reversed(list(Severity))],
        ["SEVERITY", "PREVIOUS", "CURRENT", "DELTA"])

    counts = summary.counts()
    console.header("Changes")
    console.table([[k, str(v)] for k, v in sorted(counts.items())], ["CHANGE", "COUNT"])

    for change in (RegressionChange.REINTRODUCED_FINDING, RegressionChange.NEW_FINDING,
                   RegressionChange.FIXED_FINDING):
        items = summary.by_change(change)
        if not items:
            continue
        console.header(f"{change.value} ({len(items)})")
        for item in items[:15]:
            title = item.detail.get("title", item.subject)
            click.echo(f"  [{item.severity or '-':13}] {str(title)[:60]}")
            note = item.detail.get("note") or item.detail.get("reason")
            if note:
                click.echo(click.style(f"      {note}", fg="bright_black"))

    if summary.has_regression:
        console.fail(f"REGRESSION DETECTED: "
                     f"{len(summary.by_change(RegressionChange.REINTRODUCED_FINDING))} "
                     "previously-absent finding(s) reappeared")
    else:
        console.ok("no reintroduced findings")


@regression.command("report")
@click.option("--current", "current_id", required=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def regression_report(click_ctx, current_id, as_json):
    """Show stored regression results for a scan."""
    app = app_ctx(click_ctx)
    results = app.repo.list_regressions(current_id)
    if not results:
        console.warn(f"no stored regression results for {current_id} — "
                     "run `velora regression compare` first")
        return
    if as_json:
        echo_json([r.model_dump() for r in results])
        return
    console.header(f"Regression results for {current_id}")
    console.table(
        [[_style(r.change), r.severity or "-", str(r.detail.get("title", r.subject))[:52]]
         for r in results],
        ["CHANGE", "SEVERITY", "SUBJECT"])
    reintroduced = [r for r in results if r.change == RegressionChange.REINTRODUCED_FINDING]
    if reintroduced:
        console.fail(f"{len(reintroduced)} reintroduced finding(s)")
