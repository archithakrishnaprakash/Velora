"""The fixed catalog of assessment capabilities a plan may reference.

This is the central safety control of the planner. An assessment plan is not free-form
text that gets executed: every step must name a capability from this catalog. A planner —
heuristic or LLM — can only *select and order* these entries. It cannot invent an action,
craft a command, or widen what Velora is able to do.

Each capability declares the permission it needs, the evidence it produces, and its risk
level, so a reviewer can approve or reject a step on the facts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Capability:
    key: str
    title: str
    description: str
    required_permission: str
    expected_evidence: str
    risk: str                      # low | medium | lab-only
    safe_mode: bool                # runs under the default safe profile
    cli: str                       # the command a reviewer can run to reproduce it

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "title": self.title, "description": self.description,
            "required_permission": self.required_permission,
            "expected_evidence": self.expected_evidence, "risk": self.risk,
            "safe_mode": self.safe_mode, "cli": self.cli,
        }


CAPABILITIES: dict[str, Capability] = {
    "recon": Capability(
        key="recon",
        title="Passive reconnaissance",
        description="Collect headers, cookies, TLS metadata, DNS, HTTP methods, "
                    "robots.txt, sitemap and security.txt.",
        required_permission="in-scope read access",
        expected_evidence="response headers, TLS handshake metadata, method list",
        risk="low", safe_mode=True,
        cli="velora recon --target <url> --i-am-authorized"),
    "crawl": Capability(
        key="crawl",
        title="Same-origin crawl and attack-surface mapping",
        description="Enumerate reachable endpoints, forms, parameters and API routes "
                    "within the authorized origin.",
        required_permission="in-scope read access",
        expected_evidence="endpoint inventory with status codes and parameters",
        risk="low", safe_mode=True,
        cli="velora crawl --target <url> --i-am-authorized"),
    "scan.safe": Capability(
        key="scan.safe",
        title="Passive security checks",
        description="Run the safe-profile deterministic checks (headers, cookies, TLS, "
                    "information disclosure, methods, directory exposure).",
        required_permission="in-scope read access",
        expected_evidence="evidence-backed findings with request/response metadata",
        risk="low", safe_mode=True,
        cli="velora scan --target <url> --profile safe --i-am-authorized"),
    "scan.standard": Capability(
        key="scan.standard",
        title="Safe checks plus light active probes",
        description="Adds the benign-marker reflection check. Sends no payloads.",
        required_permission="explicit authorization to send non-passive requests",
        expected_evidence="reflection observations using a benign alphanumeric marker",
        risk="medium", safe_mode=False,
        cli="velora scan --target <url> --profile standard --i-am-authorized"),
    "authz.matrix": Capability(
        key="authz.matrix",
        title="Multi-identity authorization matrix",
        description="Compare declared expected access against observed access for every "
                    "identity/resource pair in an authorization plan.",
        required_permission="test credentials supplied via environment secret references",
        expected_evidence="expected vs observed access per identity, with owner-baseline "
                          "differentials",
        risk="medium", safe_mode=False,
        cli="velora authz run --config <plan.yaml> --i-am-authorized"),
    "differential.compare": Capability(
        key="differential.compare",
        title="Differential request analysis",
        description="Compare a baseline and a candidate exchange under a controlled "
                    "variation and classify the differences.",
        required_permission="in-scope read access",
        expected_evidence="normalized response fingerprints and classified differences",
        risk="low", safe_mode=True,
        cli="velora diff compare --baseline <url> --candidate <url> --i-am-authorized"),
    "workflow.assess": Capability(
        key="workflow.assess",
        title="Business-logic workflow assessment",
        description="Execute an operator-defined workflow state machine and probe whether "
                    "required steps can be skipped.",
        required_permission="an authorized workflow definition (authorized: true)",
        expected_evidence="per-step outcomes and step-skip probe results",
        risk="lab-only", safe_mode=False,
        cli="velora workflow run --config <workflow.yaml> --i-am-authorized"),
    "benchmark": Capability(
        key="benchmark",
        title="Ground-truth benchmark",
        description="Measure Velora's detection accuracy against a ground-truth suite.",
        required_permission="a benchmark target with known ground truth",
        expected_evidence="precision, recall, F1 and per-case outcomes",
        risk="low", safe_mode=True,
        cli="velora benchmark run --suite <name> --target <url> --i-am-authorized"),
}

# Capabilities that may never be auto-approved, even in a lab.
REQUIRES_EXPLICIT_REVIEW = frozenset({"workflow.assess", "authz.matrix", "scan.standard"})


def get(key: str) -> Capability | None:
    return CAPABILITIES.get(key)


def keys() -> list[str]:
    return sorted(CAPABILITIES)


def allowed_for_profile(profile: str) -> list[Capability]:
    if profile == "safe":
        return [c for c in CAPABILITIES.values() if c.safe_mode]
    return list(CAPABILITIES.values())
