"""Report generator: renders the assembled context to JSON, HTML, and (optionally) PDF."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config.settings import Settings
from ..database.repository import Repository
from ..models.domain import ReportRecord
from ..utils.logging import get_logger
from .assembler import assemble_report

log = get_logger("reporting")

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    def __init__(self, repo: Repository, settings: Settings) -> None:
        self.repo = repo
        self.settings = settings
        self.env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters["sevclass"] = _sev_class

    def generate(
        self, scan_id: str, formats: list[str], output_dir: str | Path | None = None
    ) -> ReportRecord:
        context = assemble_report(self.repo, scan_id, self.settings)
        out_dir = Path(output_dir or self.settings.reports.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        paths: dict[str, str] = {}
        #: Formats that were requested but could not be produced. Surfaced to the
        #: caller rather than swallowed, so a missing format is never read as success.
        unavailable: list[str] = []

        for fmt in formats:
            fmt = fmt.lower()
            if fmt == "json":
                p = out_dir / f"{scan_id}.json"
                p.write_text(json.dumps(context, indent=2, default=str), encoding="utf-8")
                paths["json"] = str(p)
            elif fmt == "html":
                p = out_dir / f"{scan_id}.html"
                p.write_text(self.render_html(context), encoding="utf-8")
                paths["html"] = str(p)
            elif fmt == "sarif":
                p = out_dir / f"{scan_id}.sarif"
                from .sarif import build_sarif

                p.write_text(json.dumps(build_sarif(self.repo, scan_id), indent=2,
                                        default=str), encoding="utf-8")
                paths["sarif"] = str(p)
            elif fmt == "pdf":
                pdf_path = self._render_pdf(context, out_dir / f"{scan_id}.pdf")
                if pdf_path:
                    paths["pdf"] = str(pdf_path)
                else:
                    # Falling back to HTML is reasonable; reporting success is not. A
                    # pipeline asking for a PDF needs to know it did not get one.
                    log.warning("PDF requested but WeasyPrint is unavailable; wrote HTML "
                                "instead")
                    p = out_dir / f"{scan_id}.html"
                    p.write_text(self.render_html(context), encoding="utf-8")
                    paths.setdefault("html", str(p))
                    unavailable.append(
                        "pdf: WeasyPrint is not installed, so no PDF was produced. HTML "
                        f"was written instead ({p}). Install the 'pdf' extra to enable "
                        "PDF output.")
            else:
                log.warning("unknown report format: %s", fmt)

        record = ReportRecord(scan_id=scan_id, formats=list(paths.keys()), paths=paths,
                              operator=context["meta"]["operator"])
        record.unavailable = unavailable
        self.repo.add_report(record)
        from ..models.domain import AuditLog
        self.repo.audit(AuditLog(action="report_generated", target_ref=scan_id,
                                 detail={"formats": list(paths.keys())}))
        return record

    def render_html(self, context: dict[str, Any]) -> str:
        return self.env.get_template("report.html").render(**context)

    def _render_pdf(self, context: dict[str, Any], out_path: Path) -> Path | None:
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError:
            return None
        try:
            HTML(string=self.render_html(context)).write_pdf(str(out_path))
            return out_path
        except Exception as exc:  # noqa: BLE001
            log.error("PDF rendering failed: %s", exc)
            return None


def _sev_class(severity: str) -> str:
    return {
        "Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium",
        "Low": "sev-low", "Informational": "sev-info",
    }.get(severity, "sev-info")
