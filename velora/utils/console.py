"""Small console helpers (tables, severity colors) built on click — no rich dependency."""
from __future__ import annotations

import click

_SEV_COLOR = {
    "Critical": "red", "High": "bright_red", "Medium": "yellow",
    "Low": "cyan", "Informational": "white",
}


def sev(severity: str) -> str:
    return click.style(severity, fg=_SEV_COLOR.get(severity, "white"), bold=severity in {"Critical", "High"})


def ok(msg: str) -> None:
    click.echo(click.style("PASS ", fg="green", bold=True) + msg)


def warn(msg: str) -> None:
    click.echo(click.style("WARN ", fg="yellow", bold=True) + msg)


def fail(msg: str) -> None:
    click.echo(click.style("FAIL ", fg="red", bold=True) + msg)


def header(msg: str) -> None:
    click.echo()
    click.echo(click.style(msg, fg="bright_blue", bold=True))
    click.echo(click.style("─" * len(msg), fg="blue"))


def table(rows: list[list[str]], headers: list[str]) -> None:
    """Render a simple aligned table."""
    if not rows:
        click.echo(click.style("(none)", fg="bright_black"))
        return
    cols = len(headers)
    widths = [len(h) for h in headers]
    str_rows = [[str(c) for c in row] for row in rows]
    for row in str_rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(row[i]) if i < len(row) else 0)
    line = "  ".join(click.style(headers[i].ljust(widths[i]), fg="bright_black", bold=True)
                      for i in range(cols))
    click.echo(line)
    for row in str_rows:
        click.echo("  ".join((row[i] if i < len(row) else "").ljust(widths[i]) for i in range(cols)))
