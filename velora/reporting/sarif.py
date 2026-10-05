"""SARIF 2.1.0 export.

Maps Velora findings into the Static Analysis Results Interchange Format so results can
be consumed by GitHub code scanning, GitLab, and other SARIF-aware tooling.

Two deliberate modelling choices:

1. **No invented source locations.** Velora assesses running web applications, not source
   files. Inventing ``file.py:42`` would be a lie that tools would render as fact. Each
   result's physical location is the **endpoint URI** with no region, and a logical
   location names the endpoint path. Consumers that require a file path will show the URI
   instead, which is the truthful answer.
2. **Validation state is carried, not hidden.** A ``Potential`` finding is exported with
   its status in the message and in ``properties``, so a reviewer in GitHub sees that it
   is an unvalidated indicator rather than a confirmed vulnerability.
"""
from __future__ import annotations

from typing import Any

from .. import __version__
from ..database.repository import Repository
from ..models.domain import Finding
from ..models.enums import Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
                "sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/architha/velora"

# SARIF levels: error | warning | note | none
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# SARIF security-severity is a 0.0-10.0 string that GitHub reads as a CVSS-like score.
# Velora emits it ONLY where a real CVSS base score exists, at result level. Rules carry
# Velora's own ordering under a namespaced property instead, so nothing Velora publishes
# can be mistaken for a CVSS score it did not derive.
_RANK: dict[Severity, float] = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 30.0,
    Severity.INFO: 10.0,
}


def _rule_id(finding: Finding) -> str:
    return finding.scanner or "velora.unknown"


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """One rule per detecting check, deduplicated."""
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        properties: dict[str, Any] = {
            "category": finding.category,
            "precision": {"Certain": "very-high", "Firm": "high",
                          "Tentative": "medium"}.get(finding.confidence.value, "medium"),
            "problem.severity": _LEVEL[finding.severity],
            # Velora's own severity ordering, namespaced. NOT "security-severity":
            # that field reads as a CVSS score, and this rank is not one.
            "velora/severityRank": str(_RANK[finding.severity]),
        }
        tags = ["security", "velora"]
        if finding.cwe_id and finding.cwe_id != "UNKNOWN":
            tags.append(f"external/cwe/{finding.cwe_id.lower()}")
        if finding.owasp_category and finding.owasp_category != "UNKNOWN":
            tags.append(finding.owasp_category.split("-")[0])
        properties["tags"] = tags

        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id.replace(".", "_"),
            "shortDescription": {"text": finding.title[:120]},
            "fullDescription": {
                "text": (finding.description or finding.title)[:900]},
            "help": {
                "text": finding.remediation or "See the Velora report for remediation.",
                "markdown": (f"**Remediation.** {finding.remediation}\n\n"
                             f"**Impact.** {finding.impact}" if finding.remediation
                             else "See the Velora report."),
            },
            "defaultConfiguration": {"level": _LEVEL[finding.severity]},
            "properties": properties,
        }
        if finding.references:
            rules[rule_id]["helpUri"] = finding.references[0]
    return list(rules.values())


def _location(finding: Finding) -> dict[str, Any]:
    """Endpoint URI as the location. No file path, no line number, ever."""
    uri = finding.endpoint or ""
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": uri,
                "description": {"text": "HTTP endpoint assessed by Velora "
                                        "(not a source-code location)"},
            }
        },
        "logicalLocations": [{
            "name": finding.method + " " + uri,
            "kind": "resource",
            "fullyQualifiedName": uri,
        }],
    }
    return location


def _result(finding: Finding, evidence_text: list[str]) -> dict[str, Any]:
    status_note = (f"[{finding.status.value}] " if finding.status.value != "Confirmed"
                   else "")
    validation_note = ("" if finding.status.value in {"Confirmed", "Rejected"}
                       else " This is an evidence-backed indicator and requires human "
                            "validation before it is treated as confirmed.")
    message = (f"{status_note}{finding.title}. {finding.description}"
               f"{validation_note}").strip()

    properties: dict[str, Any] = {
        "velora/findingId": finding.id,
        "velora/scanId": finding.scan_id,
        "velora/category": finding.category,
        "velora/severity": finding.severity.value,
        "velora/confidence": finding.confidence.value,
        "velora/status": finding.status.value,
        "velora/validationState": finding.validation_state.value,
        "velora/remediationStatus": finding.remediation_status.value,
        "velora/priorityScore": finding.priority_score,
        "velora/priorityScoreNote": "Velora Priority Score — a triage metric, not CVSS.",
        "velora/cwe": finding.cwe_id,
        "velora/owasp": finding.owasp_category,
        "velora/evidence": evidence_text[:5],
    }
    if finding.cvss_base_score is not None:
        properties["velora/cvssBaseScore"] = finding.cvss_base_score
        properties["velora/cvssVector"] = finding.cvss_vector
        properties["security-severity"] = str(finding.cvss_base_score)
    else:
        properties["velora/cvss"] = "Not Assessed"

    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _LEVEL[finding.severity],
        "message": {"text": message[:1800]},
        "locations": [_location(finding)],
        "properties": properties,
    }
    # Stable cross-run identity so SARIF consumers can track an issue over time.
    if finding.fingerprint:
        result["partialFingerprints"] = {"veloraFingerprint/v1": finding.fingerprint}
    if finding.status.value == "Rejected":
        result["suppressions"] = [{
            "kind": "external",
            "justification": finding.validation_note or "rejected by a human reviewer",
        }]
    return result


def build_sarif(repo: Repository, scan_id: str, *, include_rejected: bool = False
                ) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for one scan."""
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")
    target = repo.get_target(scan.target_id)
    findings = repo.list_findings(scan_id)
    if not include_rejected:
        findings = [f for f in findings if f.status.value != "Rejected"]

    evidence_by_finding: dict[str, list[str]] = {}
    for row in repo.list_evidence(scan_id):
        if row.finding_id and row.sanitized_excerpt:
            evidence_by_finding.setdefault(row.finding_id, []).append(row.sanitized_excerpt)

    results = [_result(f, evidence_by_finding.get(f.id, [])) for f in findings]

    invocation: dict[str, Any] = {
        "executionSuccessful": scan.status.value == "completed",
        "commandLine": f"velora scan --target {target.url if target else ''}",
        "properties": {
            "profile": scan.profile.value,
            "operator": scan.operator,
            "requests": scan.stats.get("requests"),
            "blockedRequests": scan.stats.get("blocked_requests"),
        },
    }
    if scan.started_at:
        invocation["startTimeUtc"] = scan.started_at.isoformat()
    if scan.finished_at:
        invocation["endTimeUtc"] = scan.finished_at.isoformat()

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Velora",
                    "fullName": "Velora — AI-Assisted Web Application Security Assessment "
                                "& Validation Platform",
                    "version": __version__,
                    "semanticVersion": __version__,
                    "informationUri": INFORMATION_URI,
                    "rules": _build_rules(findings),
                }
            },
            "invocations": [invocation],
            "automationDetails": {"id": f"velora/{scan_id}"},
            "results": results,
            "properties": {
                "velora/scanId": scan_id,
                "velora/target": target.url if target else "",
                "velora/authorizationStatus":
                    target.authorization_status.value if target else "UNKNOWN",
                "velora/note": (
                    "Locations are HTTP endpoint URIs, not source-code paths. Velora "
                    "assesses running applications and does not map findings to source "
                    "files. Findings marked Potential are unvalidated indicators."),
            },
        }],
    }
