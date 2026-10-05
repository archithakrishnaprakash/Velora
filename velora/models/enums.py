"""Enumerations with well-defined ordering for severity and confidence."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_any(cls, value: str) -> "Severity":
        v = (value or "").strip().lower()
        for member in cls:
            if member.value.lower() == v or member.name.lower() == v:
                return member
        return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """Qualitative confidence buckets. Deterministic scanners set these from evidence."""

    TENTATIVE = "Tentative"   # weak/indirect signal
    FIRM = "Firm"             # clear signal, low false-positive rate
    CERTAIN = "Certain"       # directly observable fact (e.g. header literally present)

    @property
    def score(self) -> float:
        return {"Tentative": 0.4, "Firm": 0.7, "Certain": 0.95}[self.value]

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        if score >= 0.85:
            return cls.CERTAIN
        if score >= 0.6:
            return cls.FIRM
        return cls.TENTATIVE


class FindingStatus(str, Enum):
    POTENTIAL = "Potential"
    NEEDS_REVIEW = "Needs Review"
    CONFIRMED = "Confirmed"
    REJECTED = "Rejected"
    REMEDIATED = "Remediated"


class ScanStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, Enum):
    SAFE = "safe"          # passive + low-touch checks only (default)
    STANDARD = "standard"  # safe + light active checks, authorized targets
    LAB = "lab"            # more intensive, only for explicitly-authorized lab targets

    @property
    def description(self) -> str:
        return {
            "safe": "Passive and low-touch checks only. Safe default.",
            "standard": "Safe checks plus light active probes. Authorized targets only.",
            "lab": "More intensive assessment. Explicitly-authorized lab targets only.",
        }[self.value]


class AuthorizationStatus(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"   # cannot be scanned
    LAB_ONLY = "LAB_ONLY"           # isolated lab / intentionally vulnerable app
    AUTHORIZED = "AUTHORIZED"       # explicit written authorization on file

    @property
    def scannable(self) -> bool:
        return self in {AuthorizationStatus.LAB_ONLY, AuthorizationStatus.AUTHORIZED}


# ---------------------------------------------------------------------------
# Velora 2.0 enumerations
# ---------------------------------------------------------------------------


class ValidationState(str, Enum):
    """Epistemic status of an assertion (graph edge, AI claim, knowledge link).

    This is the backbone of Velora's evidence discipline: a statement must declare
    how it is known, and only a human can move something to VALIDATED.
    """

    OBSERVED = "OBSERVED"          # directly measured from a response
    INFERRED = "INFERRED"          # derived deterministically from observations
    HYPOTHESIZED = "HYPOTHESIZED"  # plausible but untested (AI/correlation)
    VALIDATED = "VALIDATED"        # a human confirmed it
    UNKNOWN = "UNKNOWN"            # insufficient information

    @property
    def is_fact(self) -> bool:
        return self in {ValidationState.OBSERVED, ValidationState.VALIDATED}


class DiffClassification(str, Enum):
    """Classification of a single difference between a baseline and a candidate."""

    NO_CHANGE = "NO_CHANGE"
    STATUS_CHANGE = "STATUS_CHANGE"
    HEADER_CHANGE = "HEADER_CHANGE"
    COOKIE_CHANGE = "COOKIE_CHANGE"
    REDIRECT_CHANGE = "REDIRECT_CHANGE"
    CONTENT_TYPE_CHANGE = "CONTENT_TYPE_CHANGE"
    CONTENT_CHANGE = "CONTENT_CHANGE"
    BODY_STRUCTURE_CHANGE = "BODY_STRUCTURE_CHANGE"
    JSON_FIELD_CHANGE = "JSON_FIELD_CHANGE"
    TIMING_CHANGE = "TIMING_CHANGE"
    AUTHORIZATION_BEHAVIOR_CHANGE = "AUTHORIZATION_BEHAVIOR_CHANGE"


class IdentityRole(str, Enum):
    """Roles used by the multi-identity authorization matrix."""

    ANONYMOUS = "anonymous"
    USER_A = "user_a"
    USER_B = "user_b"
    PRIVILEGED_USER = "privileged_user"
    ADMIN = "admin"

    @property
    def privilege_rank(self) -> int:
        return {"anonymous": 0, "user_a": 1, "user_b": 1,
                "privileged_user": 2, "admin": 3}[self.value]


class AccessExpectation(str, Enum):
    """What the operator declares *should* happen for an identity/resource pair."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class AccessObservation(str, Enum):
    """What actually happened."""

    GRANTED = "GRANTED"
    DENIED = "DENIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class AuthzOutcome(str, Enum):
    """Result of comparing expectation against observation."""

    AS_EXPECTED = "AS_EXPECTED"
    HORIZONTAL_AUTHORIZATION_WEAKNESS = "HORIZONTAL_AUTHORIZATION_WEAKNESS"
    VERTICAL_AUTHORIZATION_WEAKNESS = "VERTICAL_AUTHORIZATION_WEAKNESS"
    UNAUTHENTICATED_ACCESS = "UNAUTHENTICATED_ACCESS"
    PRIVILEGE_BOUNDARY_WEAKNESS = "PRIVILEGE_BOUNDARY_WEAKNESS"
    INCONCLUSIVE = "INCONCLUSIVE"

    @property
    def is_weakness(self) -> bool:
        return self not in {AuthzOutcome.AS_EXPECTED, AuthzOutcome.INCONCLUSIVE}


class RemediationStatus(str, Enum):
    """Lifecycle of a fix, tracked separately from the finding's validation status."""

    OPEN = "OPEN"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    READY_FOR_RETEST = "READY_FOR_RETEST"
    FIX_VERIFIED = "FIX_VERIFIED"
    FIX_FAILED = "FIX_FAILED"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"


class RegressionChange(str, Enum):
    """Scan-to-scan delta classifications."""

    NEW_FINDING = "NEW_FINDING"
    FIXED_FINDING = "FIXED_FINDING"
    PERSISTING_FINDING = "PERSISTING_FINDING"
    REINTRODUCED_FINDING = "REINTRODUCED_FINDING"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    REMOVED_ENDPOINT = "REMOVED_ENDPOINT"
    CHANGED_TECHNOLOGY = "CHANGED_TECHNOLOGY"
    CHANGED_SECURITY_CONTROL = "CHANGED_SECURITY_CONTROL"


class EngagementStatus(str, Enum):
    PLANNED = "PLANNED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CLOSED = "CLOSED"

    @property
    def accepts_scans(self) -> bool:
        return self in {EngagementStatus.PLANNED, EngagementStatus.ACTIVE}


class PlanStepStatus(str, Enum):
    """AI planner steps require explicit human approval before execution."""

    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"


class GateDecision(str, Enum):
    """CI/CD security gate outcome. Maps directly to process exit codes."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"

    @property
    def exit_code(self) -> int:
        return {"PASS": 0, "FAIL": 1, "ERROR": 2}[self.value]


class WorkflowStepOutcome(str, Enum):
    """Result of executing one business-logic workflow step."""

    PENDING = "PENDING"
    PASSED = "PASSED"
    ASSERTION_FAILED = "ASSERTION_FAILED"
    UNEXPECTED_STATE = "UNEXPECTED_STATE"
    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
    ERROR = "ERROR"


class BenchmarkOutcome(str, Enum):
    """Per-case benchmark scoring against ground truth."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
