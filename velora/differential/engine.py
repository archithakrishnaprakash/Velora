"""Differential comparison engine.

Takes a baseline and a candidate exchange and produces a classified, confidence-scored
``DifferentialResult``. The engine is deliberately conservative:

* A difference is reported, never asserted to be a vulnerability.
* Confidence reflects how *reliable the observation* is, not how bad it is.
* ``validation_required`` is True whenever the interpretation touches authorization.
* Volatile fields are normalized away by the fingerprinter before comparison.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.http import HttpResponse
from ..models.enums import DiffClassification
from ..utils.logging import get_logger
from ..utils.redaction import redact_text
from .fingerprint import ResponseFingerprint, fingerprint_response

log = get_logger("differential")

# The only classification that, on its own, indicates a change in access behaviour.
#
# ``_status`` already does the careful work: it emits AUTHORIZATION_BEHAVIOR_CHANGE
# only when an allow/deny boundary was actually crossed, and plain STATUS_CHANGE
# otherwise. Treating STATUS_CHANGE or REDIRECT_CHANGE as an access signal here would
# throw that restraint away and make a 200 -> 500 read as an authorization boundary
# crossing in the human-readable interpretation.
_AUTHZ_SIGNALS = {
    DiffClassification.AUTHORIZATION_BEHAVIOR_CHANGE,
}

# Changes that are *relevant* to an access question without establishing one. They
# earn a mention in the interpretation, not an access-boundary claim.
_AUTHZ_ADJACENT = {
    DiffClassification.STATUS_CHANGE,
    DiffClassification.REDIRECT_CHANGE,
    DiffClassification.COOKIE_CHANGE,
}

# Status classes used to reason about access behaviour.
_DENY_STATUSES = {401, 403}
_NOT_FOUND = {404, 410}


@dataclass
class Difference:
    classification: DiffClassification
    field_name: str
    baseline: Any
    candidate: Any
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "field": self.field_name,
            "baseline": _safe(self.baseline),
            "candidate": _safe(self.candidate),
            "note": self.note,
        }


@dataclass
class DifferentialResult:
    baseline: ResponseFingerprint
    candidate: ResponseFingerprint
    differences: list[Difference] = field(default_factory=list)
    confidence: float = 0.0
    interpretation: str = ""
    validation_required: bool = True

    @property
    def classifications(self) -> list[str]:
        seen: list[str] = []
        for d in self.differences:
            if d.classification.value not in seen:
                seen.append(d.classification.value)
        return seen

    @property
    def changed(self) -> bool:
        return bool(self.differences)

    @property
    def indicates_access_change(self) -> bool:
        """True only when an allow/deny boundary was actually crossed."""
        return any(d.classification in _AUTHZ_SIGNALS for d in self.differences)

    @property
    def has_access_adjacent_change(self) -> bool:
        """True for changes worth a reviewer's attention that prove nothing on their own."""
        return any(d.classification in _AUTHZ_ADJACENT for d in self.differences)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict(),
            "differences": [d.to_dict() for d in self.differences],
            "classifications": self.classifications,
            "confidence": round(self.confidence, 3),
            "interpretation": self.interpretation,
            "validation_required": self.validation_required,
        }


def _safe(value: Any) -> Any:
    """Redact and bound any value before it enters stored evidence."""
    if isinstance(value, str):
        return redact_text(value)[:400]
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in list(value)[:25]]
    if isinstance(value, dict):
        return {k: _safe(v) for k, v in list(value.items())[:25]}
    return value


class DifferentialEngine:
    """Compares two exchanges (or two fingerprints) and classifies the differences."""

    def __init__(self, *, ignore_timing: bool = False) -> None:
        # Timing is noisy on shared infrastructure; callers may disable it.
        self.ignore_timing = ignore_timing

    # ---- public API -----------------------------------------------------
    def compare_responses(self, baseline: HttpResponse, candidate: HttpResponse) -> DifferentialResult:
        return self.compare(fingerprint_response(baseline), fingerprint_response(candidate))

    def compare(self, baseline: ResponseFingerprint, candidate: ResponseFingerprint) -> DifferentialResult:
        diffs: list[Difference] = []
        diffs += self._status(baseline, candidate)
        diffs += self._headers(baseline, candidate)
        diffs += self._cookies(baseline, candidate)
        diffs += self._redirect(baseline, candidate)
        diffs += self._content_type(baseline, candidate)
        diffs += self._body(baseline, candidate)
        if not self.ignore_timing:
            diffs += self._timing(baseline, candidate)

        result = DifferentialResult(baseline=baseline, candidate=candidate, differences=diffs)
        result.confidence = self._confidence(result)
        result.interpretation = self._interpret(result)
        result.validation_required = True  # every differential observation needs a human
        return result

    # ---- comparators ----------------------------------------------------
    def _status(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        if b.status_code == c.status_code:
            return []
        # An access-relevant transition gets a more specific classification.
        crossed_access_boundary = (
            (b.status_code in _DENY_STATUSES and 200 <= c.status_code < 300)
            or (200 <= b.status_code < 300 and c.status_code in _DENY_STATUSES)
        )
        classification = (
            DiffClassification.AUTHORIZATION_BEHAVIOR_CHANGE
            if crossed_access_boundary
            else DiffClassification.STATUS_CHANGE
        )
        note = (
            "response crossed an allow/deny boundary"
            if crossed_access_boundary
            else "status code differs"
        )
        return [Difference(classification, "status_code", b.status_code, c.status_code, note)]

    def _headers(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        out: list[Difference] = []
        bset, cset = set(b.header_names), set(c.header_names)
        added, removed = sorted(cset - bset), sorted(bset - cset)
        if added or removed:
            out.append(Difference(
                DiffClassification.HEADER_CHANGE, "header_names",
                removed or [], added or [],
                f"headers added={added} removed={removed}",
            ))
        for name in sorted(set(b.security_headers) | set(c.security_headers)):
            bv, cv = b.security_headers.get(name), c.security_headers.get(name)
            if name in ("location", "content-type"):
                continue  # handled by dedicated comparators
            if bv != cv:
                out.append(Difference(
                    DiffClassification.HEADER_CHANGE, f"header:{name}", bv, cv,
                    "security-relevant header value differs",
                ))
        return out

    def _cookies(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        out: list[Difference] = []
        if b.cookie_names != c.cookie_names:
            out.append(Difference(
                DiffClassification.COOKIE_CHANGE, "cookie_names",
                b.cookie_names, c.cookie_names, "set-cookie names differ",
            ))
        for name in sorted(set(b.cookie_flags) & set(c.cookie_flags)):
            if b.cookie_flags[name] != c.cookie_flags[name]:
                out.append(Difference(
                    DiffClassification.COOKIE_CHANGE, f"cookie_flags:{name}",
                    b.cookie_flags[name], c.cookie_flags[name], "cookie attributes differ",
                ))
        return out

    def _redirect(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        if b.redirect_target == c.redirect_target:
            return []
        return [Difference(
            DiffClassification.REDIRECT_CHANGE, "redirect_target",
            b.redirect_target, c.redirect_target, "Location target differs",
        )]

    def _content_type(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        if b.content_type == c.content_type:
            return []
        return [Difference(
            DiffClassification.CONTENT_TYPE_CHANGE, "content_type",
            b.content_type, c.content_type, "content type differs",
        )]

    def _body(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        out: list[Difference] = []
        if b.body_kind != c.body_kind:
            out.append(Difference(
                DiffClassification.BODY_STRUCTURE_CHANGE, "body_kind",
                b.body_kind, c.body_kind, "response body type differs",
            ))
            return out

        if b.body_kind == "json":
            bshape, cshape = set(b.body_shape), set(c.body_shape)
            added, removed = sorted(cshape - bshape), sorted(bshape - cshape)
            if added or removed:
                out.append(Difference(
                    DiffClassification.JSON_FIELD_CHANGE, "json_shape",
                    removed, added,
                    f"{len(removed)} field(s) absent / {len(added)} field(s) added in candidate",
                ))
        elif b.body_kind == "html":
            bshape, cshape = set(b.body_shape), set(c.body_shape)
            if bshape != cshape:
                added, removed = sorted(cshape - bshape), sorted(bshape - cshape)
                out.append(Difference(
                    DiffClassification.BODY_STRUCTURE_CHANGE, "html_skeleton",
                    removed[:20], added[:20], "HTML structure differs",
                ))
        if b.body_hash != c.body_hash and not out:
            # Same structure, different normalized content.
            note = "normalized body content differs (structure unchanged)"
            if b.size_bucket != c.size_bucket:
                note += f"; size bucket {b.size_bucket} -> {c.size_bucket}"
            out.append(Difference(
                DiffClassification.CONTENT_CHANGE, "body_hash", b.body_hash, c.body_hash, note,
            ))
        return out

    def _timing(self, b: ResponseFingerprint, c: ResponseFingerprint) -> list[Difference]:
        if abs(b.timing_bucket - c.timing_bucket) < 2:
            return []  # require a clear, multi-bucket shift before reporting
        return [Difference(
            DiffClassification.TIMING_CHANGE, "timing_bucket",
            b.timing_bucket, c.timing_bucket,
            "response timing differs by more than one bucket (weak signal)",
        )]

    # ---- scoring and interpretation -------------------------------------
    def _confidence(self, result: DifferentialResult) -> float:
        """Confidence that the observed difference is REAL (not noise), in [0,1]."""
        if not result.differences:
            return 0.0
        if result.baseline.error or result.candidate.error:
            return 0.2   # a transport error makes any comparison unreliable
        weights = {
            DiffClassification.AUTHORIZATION_BEHAVIOR_CHANGE: 0.95,
            DiffClassification.STATUS_CHANGE: 0.9,
            DiffClassification.REDIRECT_CHANGE: 0.85,
            DiffClassification.JSON_FIELD_CHANGE: 0.8,
            DiffClassification.COOKIE_CHANGE: 0.75,
            DiffClassification.BODY_STRUCTURE_CHANGE: 0.7,
            DiffClassification.CONTENT_TYPE_CHANGE: 0.7,
            DiffClassification.HEADER_CHANGE: 0.6,
            DiffClassification.CONTENT_CHANGE: 0.45,
            DiffClassification.TIMING_CHANGE: 0.25,
        }
        return max(weights.get(d.classification, 0.4) for d in result.differences)

    def _interpret(self, result: DifferentialResult) -> str:
        """A factual, non-speculative sentence. Never asserts a vulnerability."""
        if not result.differences:
            return ("No structural difference observed between baseline and candidate. "
                    "This does not prove equivalent behaviour.")
        if result.baseline.error or result.candidate.error:
            return ("One or both exchanges failed at the transport layer; the comparison is "
                    "unreliable and should be repeated.")
        kinds = result.classifications
        lead = f"{len(result.differences)} difference(s) observed: {', '.join(kinds)}."
        if result.indicates_access_change:
            lead += (" The candidate response crossed an allow/deny boundary relative to the "
                     "baseline. This is an INDICATOR only — it requires manual validation and "
                     "does not by itself establish an authorization flaw.")
        elif result.has_access_adjacent_change:
            lead += (" The responses differ in status, redirect or cookie behaviour without "
                     "crossing an allow/deny boundary. That is worth a reviewer's attention "
                     "but does not indicate an authorization difference.")
        else:
            lead += (" These are structural differences; they do not by themselves indicate a "
                     "security weakness.")
        return lead
