"""`velora integrations` — run a safe external-tool adapter against an in-scope target.

These adapters exist so Velora can use an operator's existing toolchain without
inheriting its risks. Every run:

* resolves the executable and refuses to guess at one that is not installed;
* validates the target against the scan's ScopePolicy *before* the process starts;
* executes an argument array, never a shell string, so nothing in a URL or a hostname
  can become part of a command;
* runs under a timeout, killing the process group on expiry;
* captures bounded output.

Results are shown, not silently converted into Velora findings: a third-party tool's
output is that tool's claim, and folding it into Velora's evidence model without a
human reading it would undercut the point of an evidence-first framework.
"""
from __future__ import annotations

import click

from ...integrations import NmapAdapter, NucleiAdapter, ZapAdapter
from ...utils import console
from ...utils.errors import ScopeViolation
from ..helpers import app_ctx, echo_json, scope_manager_for

AUTH_HELP = "Confirm you are authorized to test this target (required)."

_ADAPTERS = {
    "nmap": (NmapAdapter, "scan_host", "Port/service discovery on the target host."),
    "zap": (ZapAdapter, "baseline_scan", "OWASP ZAP passive baseline scan."),
    "nuclei": (NucleiAdapter, "scan_url", "Nuclei template scan."),
}


@click.group()
def integrations() -> None:
    """Run safe adapters for external tools (nmap, OWASP ZAP, nuclei)."""


@integrations.command("list")
@click.option("--json", "as_json", is_flag=True)
def integrations_list(as_json):
    """Show which external tools are installed and reachable."""
    rows = []
    payload = []
    for name, (cls, _, description) in sorted(_ADAPTERS.items()):
        adapter = cls()
        path = adapter.resolve_executable()
        rows.append([name, adapter.executable, path or "not found",
                     "available" if path else "missing"])
        payload.append({"tool": name, "executable": adapter.executable,
                        "path": path, "available": bool(path),
                        "description": description})
    if as_json:
        echo_json(payload)
        return
    console.table(rows, ["TOOL", "EXECUTABLE", "PATH", "STATUS"])
    console.warn("External tools are optional. Velora's own checks do not depend on "
                 "them, and their output is never auto-converted into Velora findings.")


@integrations.command("run")
@click.option("--tool", required=True, type=click.Choice(sorted(_ADAPTERS)))
@click.option("--target", "target_arg", required=True,
              help="Stored target id/name, or a full http(s) URL.")
@click.option("--scope", multiple=True, help="Additional in-scope domain (repeatable).")
@click.option("--allow-private", is_flag=True, help="Permit private/loopback targets (lab).")
@click.option("--timeout", type=float, default=None, help="Override the adapter timeout.")
@click.option("--json", "as_json", is_flag=True)
@click.option("--i-am-authorized", "authorized", is_flag=True, help=AUTH_HELP)
@click.pass_context
def integrations_run(click_ctx, tool, target_arg, scope, allow_private, timeout, as_json,
                     authorized):
    """Run one external tool against a target, gated by the same scope policy as a scan."""
    if not authorized:
        raise click.ClickException("pass --i-am-authorized to confirm authorization")
    app = app_ctx(click_ctx)

    stored = app.repo.get_target(target_arg) or app.repo.get_target_by_name(target_arg)
    url = stored.url if stored else target_arg
    if not url.lower().startswith(("http://", "https://")):
        raise click.BadParameter("target must be a stored id/name or a full http(s) URL")

    cls, method_name, _ = _ADAPTERS[tool]
    sm = scope_manager_for(url, scope, allow_private, app.settings)
    adapter = cls(scope=sm)
    if not adapter.available():
        raise click.ClickException(
            f"{tool} is not installed (looked for '{adapter.executable}'). "
            f"Install it, or run `velora integrations list` to see what is available.")

    method = getattr(adapter, method_name)
    kwargs = {"timeout": timeout} if timeout else {}
    console.header(f"Running {tool} against {url}")
    try:
        result = method(url, **kwargs)
    except ScopeViolation as exc:
        raise click.ClickException(
            f"refused: {url} is out of scope ({exc.reason})") from exc

    if as_json:
        echo_json({"tool": result.tool, "available": result.available,
                   "returncode": result.returncode, "timed_out": result.timed_out,
                   "command": result.command, "error": result.error,
                   "stdout": result.stdout[:100_000], "stderr": result.stderr[:20_000]})
        return

    click.echo(f"command   : {' '.join(result.command)}")
    click.echo(f"exit code : {result.returncode}")
    if result.timed_out:
        console.warn("the tool timed out and was terminated")
    if result.error:
        console.warn(result.error)
    if result.stdout:
        console.header(f"{tool} output")
        click.echo(result.stdout[:20_000])
    if result.stderr.strip():
        console.header("stderr")
        click.echo(result.stderr[:4_000])
    console.warn("This is the external tool's own output. It has not been converted "
                 "into Velora findings; review it yourself and record anything real "
                 "through the normal finding workflow.")
