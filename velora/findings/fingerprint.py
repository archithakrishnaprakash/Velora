"""Stable finding identity across scans.

Regression analysis and remediation retesting both need to answer: *is this the same
issue we saw last time?* Finding ids are per-scan and useless for that. A fingerprint is
a deterministic hash of the properties that define the issue rather than the run:

    detecting check + category + normalized endpoint + normalized title

Deliberately excluded: scan id, timestamps, priority score, severity (a severity change
on the same issue should read as *persisting*, not as fixed-plus-new), evidence ids, and
any volatile path segment such as a numeric object id.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from ..models.domain import Finding
from ..models.enums import FindingStatus

# Path segments that identify a specific object rather than an endpoint shape.
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")

# Volatile fragments inside a title (ids, ports, counts).
_TITLE_VOLATILE = re.compile(r"\b\d+\b")
_WHITESPACE = re.compile(r"\s+")


def normalize_endpoint(url: str) -> str:
    """Collapse object identifiers so /api/orders/1 and /api/orders/2 are one endpoint."""
    if not url:
        return ""
    parts = urlsplit(url)
    segments = []
    for segment in (parts.path or "/").split("/"):
        if not segment:
            continue
        if _NUMERIC_SEGMENT.match(segment) or _UUID_SEGMENT.match(segment) \
                or _HEX_SEGMENT.match(segment):
            segments.append("{id}")
        else:
            segments.append(segment.lower())
    path = "/" + "/".join(segments)
    # Host is included but the port is not: moving a lab app to another port should not
    # invent a "new" finding.
    host = (parts.hostname or "").lower()
    return f"{host}{path}"


def normalize_title(title: str) -> str:
    """Strip volatile numbers and casing from a title."""
    if not title:
        return ""
    cleaned = _TITLE_VOLATILE.sub("#", title.lower())
    return _WHITESPACE.sub(" ", cleaned).strip()


def compute(finding: Finding) -> str:
    """Return the stable fingerprint for a finding.

    Five parts: the detecting check, the category, the HTTP method, the normalised
    endpoint and the normalised title. Severity is deliberately NOT included, so a
    finding that is later re-rated still matches its earlier self and reads as
    *persisting* rather than as one issue fixed and a new one introduced.
    """
    parts = [
        (finding.scanner or "unknown").strip().lower(),
        (finding.category or "").strip().lower(),
        (finding.method or "GET").strip().upper(),
        normalize_endpoint(finding.endpoint),
        normalize_title(finding.title),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"VF-{digest[:24]}"


def ensure(finding: Finding) -> str:
    """Compute and attach the fingerprint if it is not already set."""
    if not finding.fingerprint:
        finding.fingerprint = compute(finding)
    return finding.fingerprint


#: Statuses that take a finding out of the active set. A finding a reviewer has
#: rejected is not a live issue, so it must not be compared as one: reporting it as
#: PERSISTING scan after scan would keep a false positive alive in every report.
EXCLUDED_FROM_COMPARISON = frozenset({FindingStatus.REJECTED})


def index_by_fingerprint(findings: list[Finding], *,
                         include_rejected: bool = False) -> dict[str, Finding]:
    """Map fingerprint -> finding, keeping the highest-severity duplicate.

    Rejected findings are excluded by default so regression and retest comparisons
    operate on the set a human still considers live.
    """
    out: dict[str, Finding] = {}
    for finding in findings:
        if not include_rejected and finding.status in EXCLUDED_FROM_COMPARISON:
            continue
        fp = ensure(finding)
        current = out.get(fp)
        if current is None or finding.severity.rank > current.severity.rank:
            out[fp] = finding
    return out
