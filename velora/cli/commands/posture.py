"""`velora posture` — the Velora Security Posture Score (aggregate metric, NOT CVSS)."""
from __future__ import annotations

import click

from ...posture import band_for, METHODOLOGY_VERSION, PostureEngine
from ...utils import console
from ..helpers import app_ctx, echo_json

_BAND_COLOR = {"Strong": "green", "Adequate": "cyan", "Weak": "yellow", "Poor": "red"}


def _bar(score: float | None, width: int = 24) -> str:
    if score is None:
        return click.style("not assessed", fg="bright_black")
    filled = int(round(width * score / 100))
    # Colour follows the same thresholds as the band label, so the bar and the word
    # next to it can never disagree.
    colour = {"Strong": "green", "Adequate": "cyan",
              "Weak": "yellow", "Poor": "red"}[band_for(score)]
    return click.style("█" * filled, fg=colour) + click.style("░" * (width - filled),
                                                              fg="bright_black")


@click.group()
def posture() -> None:
    """Compute and track the Velora Security Posture Score."""


@posture.command("show")
@click.option("--scan", "scan_id", required=True)
@click.option("--save", is_flag=True, help="Persist a posture snapshot.")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def posture_show(click_ctx, scan_id, save, as_json):
    """Compute the posture score for a scan."""
    app = app_ctx(click_ctx)
    scan = app.repo.get_scan(scan_id)
    if scan is None:
        raise click.ClickException(f"scan not found: {scan_id}")
    engine = PostureEngine(app.repo)
    result = engine.compute(scan_id)
    if save:
        engine.snapshot(scan_id, target_id=scan.target_id)
    if as_json:
        echo_json(result.to_dict())
        return

    console.header("Velora Security Posture Score")
    click.echo(click.style(f"  {result.overall:.1f}/100  ", bold=True)
               + click.style(f"({result.band})", fg=_BAND_COLOR.get(result.band, "white")))
    click.echo(click.style("  This is a Velora-specific aggregate metric. It is NOT a CVSS "
                           "score.", fg="bright_black"))

    console.header("Categories")
    for category, score in result.categories.items():
        label = f"{score:5.1f}" if score is not None else "    -"
        click.echo(f"  {category:22} {label}  {_bar(score)}")

    if result.contributors:
        console.header("Major contributors")
        console.table(
            [[c["severity"], f"-{c['penalty']:.1f}", c["category"], c["title"][:44]]
             for c in result.contributors],
            ["SEVERITY", "PENALTY", "CATEGORY", "FINDING"])

    if result.adjustments:
        console.header("Adjustments")
        console.table([[k.replace("_", " "), f"{v:+.2f}"]
                       for k, v in result.adjustments.items()], ["ADJUSTMENT", "VALUE"])

    console.header("Explanation")
    click.echo(result.explanation)
    click.echo(click.style(f"\nMethodology version {METHODOLOGY_VERSION} — see "
                           "docs/POSTURE.md", fg="bright_black"))


@posture.command("trend")
@click.option("--target", "target_id", required=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def posture_trend(click_ctx, target_id, as_json):
    """Show posture over time for a target."""
    app = app_ctx(click_ctx)
    # Accept an id or a name, like every other --target in the CLI. Passing a name used
    # to print "no snapshots recorded", which reads as missing data rather than as a
    # lookup that never happened.
    target = app.repo.get_target(target_id) or app.repo.get_target_by_name(target_id)
    if target is None:
        raise click.ClickException(f"target not found: {target_id}")
    entries = PostureEngine(app.repo).trend(target.id)
    if not entries:
        console.warn(f"no posture snapshots recorded for {target.name} — run "
                     "`velora posture show --scan <id> --save`")
        return
    if as_json:
        echo_json(entries)
        return
    console.header(f"Posture trend for {target.name}")
    previous = None
    rows = []
    for entry in entries:
        delta = "" if previous is None else f"{entry['overall'] - previous:+.1f}"
        rows.append([entry["at"][:19], entry["scan_id"], f"{entry['overall']:.1f}", delta,
                     _bar(entry["overall"], 18)])
        previous = entry["overall"]
    console.table(rows, ["WHEN", "SCAN", "SCORE", "DELTA", ""])


@posture.command("methodology")
def posture_methodology():
    """Explain exactly how the score is computed."""
    from ...posture.engine import (
        CATEGORY_WEIGHTS,
        MAX_REGRESSION_PENALTY,
        MAX_REMEDIATION_CREDIT,
        SEVERITY_PENALTY,
    )

    console.header(f"Velora Security Posture Score — methodology v{METHODOLOGY_VERSION}")
    click.echo("NOT CVSS. An aggregate 0-100 trend indicator across assessed categories.\n")
    click.echo("1. Each assessed category starts at 100.")
    click.echo("2. Each open finding deducts severity_penalty x confidence_weight:")
    console.table([[s.value, f"{p:.0f}"] for s, p in SEVERITY_PENALTY.items()],
                  ["SEVERITY", "PENALTY"])
    click.echo("   confidence_weight = 0.55 + 0.45 x scanner_confidence")
    click.echo("3. A category with no coverage is reported as 'not assessed', never as 100.")
    click.echo("4. overall = category-weighted mean of assessed categories:")
    console.table([[c, f"{w:.2f}"] for c, w in CATEGORY_WEIGHTS.items()],
                  ["CATEGORY", "WEIGHT"])
    click.echo(f"5. Bounded adjustments: verified remediations add up to "
               f"+{MAX_REMEDIATION_CREDIT:.0f}; reintroduced findings deduct up to "
               f"-{MAX_REGRESSION_PENALTY:.0f}.")
    click.echo("6. Rejected and remediated findings stop counting against the score.")
    click.echo("\nA high score means 'nothing significant was found in what was assessed'. "
               "It is not a statement that the target is secure.")
