"""Benchmark case definitions and suites.

A benchmark case is a **ground-truth statement** about a target: either "check X should
fire here" or "check X should NOT fire here". Both directions matter — a scanner that
reports everything has perfect recall and useless precision.

The built-in ``labshop`` suite describes the bundled local lab application. Its ground
truth is authoritative because the lab app's behaviour is defined in this repository
(``tests/fixtures/labapp.py``), not guessed.

Suites for third-party applications (Juice Shop, DVWA, WebGoat) ship as YAML under
``examples/labs/`` and are loaded the same way. No suite requires internet access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models.domain import BenchmarkCase
from ..utils.errors import ConfigError


@dataclass
class Suite:
    name: str
    application: str = ""
    description: str = ""
    cases: list[BenchmarkCase] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.cases)

    @property
    def positive_cases(self) -> list[BenchmarkCase]:
        return [c for c in self.cases if c.expected_detection]

    @property
    def negative_cases(self) -> list[BenchmarkCase]:
        return [c for c in self.cases if not c.expected_detection]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "application": self.application,
            "description": self.description,
            "total_cases": len(self.cases),
            "positive_cases": len(self.positive_cases),
            "negative_cases": len(self.negative_cases),
        }


def _case(**kw) -> BenchmarkCase:
    return BenchmarkCase(suite="labshop", application="Velora Lab App", **kw)


# --- Built-in suite for the bundled lab app ------------------------------
# Ground truth is derived from tests/fixtures/labapp.py, which defines exactly which
# weaknesses the app exhibits. Negative cases assert the absence of a weakness.
LABSHOP_SUITE = Suite(
    name="labshop",
    application="Velora Lab App",
    description=("Ground truth for the bundled local lab application. Positive cases are "
                 "weaknesses deliberately present in the fixture; negative cases assert "
                 "weaknesses that are deliberately absent."),
    cases=[
        # --- positives: the app really does exhibit these ---
        _case(name="Missing Content-Security-Policy", vulnerability_type="security-header",
              endpoint_path="/", expected_detection=True,
              expected_check_id="headers.security_headers", expected_severity="Medium",
              evidence_requirements=["response headers captured"],
              cwe_id="CWE-693", owasp_category="A05:2021",
              description="The fixture sends no CSP header."),
        _case(name="Server version disclosure", vulnerability_type="information-disclosure",
              endpoint_path="/", expected_detection=True,
              expected_check_id="headers.server_version", expected_severity="Low",
              evidence_requirements=["response headers captured"],
              cwe_id="CWE-200", owasp_category="A05:2021",
              description="The fixture advertises 'LabShop/1.4.2'."),
        _case(name="Insecure session cookie", vulnerability_type="session",
              endpoint_path="/login", expected_detection=True,
              expected_check_id="cookies.attributes", expected_severity="Medium",
              evidence_requirements=["Set-Cookie observed"],
              cwe_id="CWE-1004", owasp_category="A05:2021",
              description="SESSIONID is set without HttpOnly or SameSite."),
        _case(name="Secret disclosed in response body",
              vulnerability_type="information-disclosure",
              endpoint_path="/", expected_detection=True,
              expected_check_id="infodisc.indicators", expected_severity="High",
              evidence_requirements=["response body inspected"],
              cwe_id="CWE-200", owasp_category="A05:2021",
              description="The index page embeds an api_key-shaped token."),
        _case(name="Risky HTTP methods enabled", vulnerability_type="misconfiguration",
              endpoint_path="/", expected_detection=True,
              expected_check_id="config.http_methods", expected_severity="Medium",
              evidence_requirements=["response headers captured"],
              cwe_id="CWE-650", owasp_category="A05:2021",
              description="OPTIONS advertises TRACE, PUT and DELETE."),
        _case(name="Credentials submitted over plaintext HTTP",
              vulnerability_type="transport", endpoint_path="/login",
              expected_detection=True, expected_check_id="auth.indicators",
              expected_severity="High",
              evidence_requirements=["authentication surface identified"],
              cwe_id="CWE-319", owasp_category="A02:2021",
              description="The login form posts over HTTP."),
        _case(name="No security.txt published", vulnerability_type="best-practice",
              endpoint_path="/.well-known/security.txt", expected_detection=True,
              expected_check_id="config.security_txt", expected_severity="Informational",
              evidence_requirements=[], cwe_id="UNKNOWN", owasp_category="UNKNOWN",
              description="The fixture publishes no disclosure policy."),

        # --- negatives: these must NOT be reported ---
        _case(name="No directory listing exposed", vulnerability_type="misconfiguration",
              endpoint_path="/", expected_detection=False,
              expected_check_id="config.directory_exposure",
              description="The fixture never emits an auto-index page. Reporting one "
                          "would be a false positive."),
        _case(name="No TLS weakness on a plaintext target", vulnerability_type="transport",
              endpoint_path="/", expected_detection=False,
              expected_check_id="tls.configuration",
              description="The fixture serves HTTP only, so the TLS check must stay silent "
                          "rather than inventing a transport finding."),
    ],
)

BUILTIN_SUITES: dict[str, Suite] = {LABSHOP_SUITE.name: LABSHOP_SUITE}


def load_suite_file(path: str | Path) -> Suite:
    """Load a benchmark suite from YAML."""
    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"benchmark suite not found: {file_path}")
    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    if not isinstance(data, dict) or "name" not in data:
        raise ConfigError(f"{file_path} must be a mapping containing at least 'name'")

    suite = Suite(name=str(data["name"]),
                  application=str(data.get("application", "")),
                  description=str(data.get("description", "")))
    for raw in data.get("cases", []) or []:
        if not isinstance(raw, dict):
            raise ConfigError("each benchmark case must be a mapping")
        for required in ("name", "expected_check_id"):
            if required not in raw:
                raise ConfigError(f"benchmark case missing '{required}'")
        suite.cases.append(BenchmarkCase(
            suite=suite.name,
            application=suite.application,
            name=str(raw["name"]),
            vulnerability_type=str(raw.get("vulnerability_type", "")),
            endpoint_path=str(raw.get("endpoint_path", "/")),
            description=str(raw.get("description", "")),
            expected_detection=bool(raw.get("expected_detection", True)),
            expected_check_id=str(raw["expected_check_id"]),
            expected_severity=str(raw.get("expected_severity", "")),
            evidence_requirements=[str(e) for e in raw.get("evidence_requirements", []) or []],
            cwe_id=str(raw.get("cwe_id", "UNKNOWN")),
            owasp_category=str(raw.get("owasp_category", "UNKNOWN")),
        ))
    if not suite.cases:
        raise ConfigError(f"{file_path} defines no cases")
    return suite


def discover_suites(directory: str | Path | None = None) -> dict[str, Suite]:
    """Built-in suites plus any YAML suites found in ``directory``."""
    suites = dict(BUILTIN_SUITES)
    if directory:
        path = Path(directory)
        if path.is_dir():
            for file in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
                try:
                    suite = load_suite_file(file)
                    suites[suite.name] = suite
                except ConfigError:
                    continue
    return suites
