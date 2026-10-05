"""Rule-based finding correlation.

Correlations connect individually-observed findings into a plausible attack path. Every
correlation is explicitly a HYPOTHESIS: it is not proof of exploitability and requires
manual validation. The engine is deterministic (no AI); the AI layer may later *explain*
these hypotheses, but does not create or confirm them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models.domain import Finding


@dataclass
class Correlation:
    title: str
    description: str
    finding_ids: list[str] = field(default_factory=list)
    path: list[str] = field(default_factory=list)  # ordered step labels
    hypothesis: bool = True  # always True until a human validates


# Each rule: (name, required_categories, path_steps, description_template)
_RULES = [
    {
        "name": "Unauthorized access to sensitive data",
        "requires": ["authorization", "information_disclosure"],
        "path": ["Weak or missing access control", "Reachable privileged endpoint",
                 "Sensitive data exposure"],
        "description": (
            "A privileged-looking endpoint is reachable without authentication AND sensitive "
            "information was observed being disclosed. Chained, these could allow an "
            "unauthenticated actor to read data they should not. HYPOTHESIS — validate manually."
        ),
    },
    {
        "name": "Credential / session interception",
        "requires": ["authentication", "session"],
        "path": ["Credentials over plaintext / weak transport", "Insecure session cookie",
                 "Session hijack"],
        "description": (
            "Authentication material is exposed to transport-layer attack AND session cookies "
            "lack protective attributes. Together these raise the risk of credential/session "
            "theft. HYPOTHESIS — validate manually."
        ),
    },
    {
        "name": "Elevated cross-site scripting impact",
        "requires": ["input_validation", "configuration"],
        "path": ["Reflected input surface", "Weak/missing CSP", "Higher XSS impact"],
        "description": (
            "A reflected-input surface exists AND Content-Security-Policy is weak or missing, "
            "which would amplify the impact of any successful XSS. HYPOTHESIS — validate manually."
        ),
    },
    {
        "name": "Unauthorized resource manipulation",
        "requires": ["configuration", "authorization"],
        "path": ["Risky HTTP methods enabled", "Privileged endpoint reachable",
                 "Unauthorized write/delete"],
        "description": (
            "Write-capable HTTP methods are enabled AND privileged endpoints are reachable "
            "without authentication, which could permit unauthorized changes. HYPOTHESIS — "
            "validate manually."
        ),
    },
]


class CorrelationEngine:
    def correlate(self, findings: list[Finding]) -> list[Correlation]:
        by_category: dict[str, list[Finding]] = {}
        for f in findings:
            by_category.setdefault(f.category, []).append(f)

        correlations: list[Correlation] = []
        for rule in _RULES:
            required = rule["requires"]
            if not all(cat in by_category for cat in required):
                continue
            involved: list[str] = []
            for cat in required:
                involved.extend(f.id for f in by_category[cat])
            # Require the CSP-specific finding for the XSS rule to reduce noise.
            if rule["name"] == "Elevated cross-site scripting impact":
                if not any("content-security-policy" in f.title.lower()
                           for f in by_category.get("configuration", [])):
                    continue
            if rule["name"] == "Unauthorized resource manipulation":
                if not any("method" in f.title.lower()
                           for f in by_category.get("configuration", [])):
                    continue
            correlations.append(
                Correlation(
                    title=rule["name"],
                    description=rule["description"].replace("■", ""),
                    finding_ids=sorted(set(involved)),
                    path=rule["path"],
                )
            )
        return correlations
