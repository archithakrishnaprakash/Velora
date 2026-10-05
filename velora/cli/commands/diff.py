"""`velora diff` — differential request analysis."""
from __future__ import annotations

import click

from ...core.http import SafeHTTPClient
from ...differential import DifferentialEngine
from ...differential.service import DifferentialService, ExchangeSpec
from ...utils import console
from ..helpers import (
    AUTH_HELP,
    app_ctx,
    echo_json,
    parse_headers,
    require_authorization,
    run_async,
    scope_manager_for,
)


@click.group()
def diff() -> None:
    """Compare two controlled exchanges and classify the differences."""


def _compare_options(fn):
    """Apply the shared comparison options.

    ``click.command()`` consumes the ``__click_params__`` list a stacked decorator
    builds up, so registering the same function twice gave the second command no
    options at all. Re-applying them per registration keeps both commands usable.
    """
    for decorator in reversed([
        click.option("--baseline", "baseline_url", required=True, help="Baseline URL."),
        click.option("--candidate", "candidate_url", required=True, help="Candidate URL."),
        click.option("--method", default="GET", help="HTTP method for both exchanges."),
        click.option("--baseline-header", "baseline_headers", multiple=True,
                     help="Header for the baseline request ('Name: value'), repeatable."),
        click.option("--candidate-header", "candidate_headers", multiple=True,
                     help="Header for the candidate request ('Name: value'), repeatable."),
        click.option("--label", default="", help="Label stored with the observation."),
        click.option("--scan", "scan_id", default=None, help="Attach to an existing scan id."),
        click.option("--scope", multiple=True, help="Additional in-scope domain (repeatable)."),
        click.option("--allow-private", is_flag=True,
                     help="Permit private/loopback targets (lab)."),
        click.option("--ignore-timing", is_flag=True,
                     help="Ignore response-timing differences."),
        click.option("--json", "as_json", is_flag=True, help="Emit the full result as JSON."),
        click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP),
        click.pass_context,
    ]):
        fn = decorator(fn)
    return fn


def _compare_impl(click_ctx, baseline_url, candidate_url, method, baseline_headers,
                  candidate_headers, label, scan_id, scope, allow_private, ignore_timing,
                  as_json, authorized):
    """Fetch a baseline and a candidate exchange, then classify the differences.

    Both requests pass through the scope engine; an out-of-scope URL is refused.
    A difference is an observation, not a vulnerability: every result is stored with
    validation_required=True.
    """
    require_authorization(authorized)
    app = app_ctx(click_ctx)
    service = DifferentialService(app.repo, DifferentialEngine(ignore_timing=ignore_timing))

    base_spec = ExchangeSpec(url=baseline_url, method=method.upper(),
                             headers=parse_headers(baseline_headers), label="baseline")
    cand_spec = ExchangeSpec(url=candidate_url, method=method.upper(),
                             headers=parse_headers(candidate_headers), label="candidate")

    async def _run():
        sm = scope_manager_for(baseline_url, scope, allow_private, app.settings, max_requests=20)
        async with SafeHTTPClient(sm, user_agent=app.settings.scanner.user_agent,
                                  request_delay=sm.policy.request_delay) as client:
            return await service.run(client, base_spec, cand_spec,
                                     scan_id=scan_id, label=label)

    result, observation = run_async(_run())
    if result is None:
        raise click.ClickException(
            "one or both exchanges were blocked by the scope policy (see SECURITY log)"
        )
    if as_json:
        echo_json(result.to_dict())
        return

    console.header(f"Differential: {base_spec.url}  ->  {cand_spec.url}")
    click.echo(f"observation: {observation.id if observation else '(not persisted)'}")
    click.echo(f"baseline  : {result.baseline.status_code} {result.baseline.content_type} "
               f"({result.baseline.response_size}B)")
    click.echo(f"candidate : {result.candidate.status_code} {result.candidate.content_type} "
               f"({result.candidate.response_size}B)")
    click.echo(f"confidence: {result.confidence:.2f}   validation_required: "
               f"{result.validation_required}")
    console.header("Differences")
    if not result.differences:
        click.echo(click.style("no structural difference observed", fg="bright_black"))
    else:
        console.table(
            [[d.classification.value, d.field_name, str(d.note)[:60]] for d in result.differences],
            ["CLASSIFICATION", "FIELD", "NOTE"],
        )
    console.header("Interpretation")
    click.echo(result.interpretation)


# Registered under both names: running a comparison is what *creates* the stored
# DifferentialObservation, so `create` and `compare` are the same operation.
# ``create`` is an alias for ``compare``; each gets its own decorated copy.
diff.add_command(click.command("compare")(_compare_options(_compare_impl)))
diff.add_command(click.command("create")(_compare_options(_compare_impl)))


@diff.command("list")
@click.option("--scan", "scan_id", default=None)
@click.pass_context
def diff_list(click_ctx, scan_id):
    """List stored differential observations."""
    app = app_ctx(click_ctx)
    rows = [
        [d.id, d.label[:34], f"{d.confidence:.2f}",
         ",".join(d.classifications)[:40] or "none", "yes" if d.validation_required else "no"]
        for d in app.repo.list_differentials(scan_id)
    ]
    console.table(rows, ["ID", "LABEL", "CONF", "CLASSIFICATIONS", "NEEDS REVIEW"])


@diff.command("show")
@click.argument("differential_id")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def diff_show(click_ctx, differential_id, as_json):
    """Show a stored differential observation."""
    app = app_ctx(click_ctx)
    d = app.repo.get_differential(differential_id)
    if d is None:
        raise click.ClickException(f"differential not found: {differential_id}")
    if as_json:
        echo_json(d.model_dump())
        return
    console.header(f"{d.id}  {d.label}")
    click.echo(f"baseline : {d.baseline_method} {d.baseline_url} -> "
               f"{d.baseline_fingerprint.get('status_code')}")
    click.echo(f"candidate: {d.candidate_method} {d.candidate_url} -> "
               f"{d.candidate_fingerprint.get('status_code')}")
    click.echo(f"confidence: {d.confidence:.2f}  validation_required: {d.validation_required}")
    console.header("Differences")
    console.table(
        [[x.get("classification", ""), x.get("field", ""), str(x.get("note", ""))[:60]]
         for x in d.differences],
        ["CLASSIFICATION", "FIELD", "NOTE"],
    )
    console.header("Interpretation")
    click.echo(d.interpretation)
