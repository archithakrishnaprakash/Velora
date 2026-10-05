"""Pydantic domain models mirrored by the database schema.

These are the in-memory representation of framework entities. The database layer
serializes them to/from SQLite rows. Timestamps are timezone-aware UTC.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from ..utils.ids import new_id
from .enums import (
    AccessExpectation,
    AccessObservation,
    AuthorizationStatus,
    AuthzOutcome,
    BenchmarkOutcome,
    Confidence,
    DiffClassification,
    EngagementStatus,
    FindingStatus,
    GateDecision,
    IdentityRole,
    PlanStepStatus,
    RegressionChange,
    RemediationStatus,
    ScanProfile,
    ScanStatus,
    Severity,
    ValidationState,
    WorkflowStepOutcome,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(BaseModel):
    model_config = {"use_enum_values": False, "validate_assignment": True}


class ScopePolicyRecord(Base):
    id: str = Field(default_factory=lambda: new_id("SCOPE"))
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    allowed_schemes: list[str] = Field(default_factory=lambda: ["http", "https"])
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    max_requests: int = 500
    max_concurrency: int = 5
    request_delay: float = 0.2
    timeout: float = 15.0
    redirect_policy: str = "same-scope"
    allow_private_targets: bool = False


class Target(Base):
    id: str = Field(default_factory=lambda: new_id("TGT"))
    engagement_id: str | None = None
    name: str
    url: str
    description: str = ""
    owner: str = ""
    authorization_status: AuthorizationStatus = AuthorizationStatus.UNAUTHORIZED
    authorization_note: str = ""
    scope_policy_id: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Scan(Base):
    id: str = Field(default_factory=lambda: new_id("SCAN"))
    engagement_id: str | None = None
    baseline_scan_id: str | None = None
    is_retest: bool = False
    target_id: str
    profile: ScanProfile = ScanProfile.SAFE
    status: ScanStatus = ScanStatus.CREATED
    operator: str = ""
    authorization_ack: bool = False
    scope_policy_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class ScanEvent(Base):
    id: str = Field(default_factory=lambda: new_id("EVT"))
    scan_id: str
    level: str = "INFO"
    event: str = ""
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class Host(Base):
    id: str = Field(default_factory=lambda: new_id("HOST"))
    scan_id: str
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class Endpoint(Base):
    id: str = Field(default_factory=lambda: new_id("EP"))
    scan_id: str
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    response_size: int = 0
    parent_url: str | None = None
    parameters: list[str] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    is_api: bool = False
    created_at: datetime = Field(default_factory=_utcnow)


class Technology(Base):
    id: str = Field(default_factory=lambda: new_id("TECH"))
    scan_id: str
    name: str
    version: str | None = None
    categories: list[str] = Field(default_factory=list)
    evidence: str = ""
    confidence: float = 0.5
    created_at: datetime = Field(default_factory=_utcnow)


class Evidence(Base):
    id: str = Field(default_factory=lambda: new_id("EV"))
    finding_id: str | None = None
    scan_id: str
    test_name: str = ""
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None
    content_type: str = ""
    response_size: int = 0
    sanitized_excerpt: str = ""
    confidence: float = 0.5
    created_at: datetime = Field(default_factory=_utcnow)


class Finding(Base):
    id: str = Field(default_factory=lambda: new_id("WEB"))
    scan_id: str
    title: str
    description: str = ""
    category: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE
    status: FindingStatus = FindingStatus.POTENTIAL
    endpoint: str = ""
    method: str = "GET"
    evidence_ids: list[str] = Field(default_factory=list)
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    references: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    scanner: str = ""
    priority_score: float | None = None
    ai_analysis_id: str | None = None
    validated_by: str | None = None
    validation_note: str = ""
    # --- Velora 2.0 additions (all optional, safe defaults) ---
    engagement_id: str | None = None
    identity_id: str | None = None
    cwe_id: str = "UNKNOWN"
    owasp_category: str = "UNKNOWN"
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    fingerprint: str = ""            # stable identity across scans, for regression matching
    first_seen_scan_id: str | None = None
    validation_state: ValidationState = ValidationState.OBSERVED
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class AttackNode(Base):
    id: str = Field(default_factory=lambda: new_id("NODE"))
    scan_id: str
    #: Free-form by design so plugins can add their own. The built-in builder emits:
    #: Application, Host, Port, Technology, Endpoint, Parameter, Identity, Finding,
    #: Impact, Remediation, Path. See velora/attack_graph/builder.py.
    kind: str
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    ref_id: str | None = None  # id of the underlying entity (endpoint/finding/...)
    confidence: float = 0.5
    validation_status: ValidationState = ValidationState.OBSERVED
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class AttackEdge(Base):
    id: str = Field(default_factory=lambda: new_id("EDGE"))
    scan_id: str
    source_id: str
    target_id: str
    #: Free-form by design. The built-in builder emits: HOSTS, CONTAINS, USES, AFFECTS,
    #: EXPOSES, CAN_ACCESS, LEADS_TO, MITIGATED_BY.
    relation: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    hypothesis: bool = False  # kept for backward compatibility; derived from validation_status
    confidence: float = 0.5
    validation_status: ValidationState = ValidationState.INFERRED
    evidence_ids: list[str] = Field(default_factory=list)
    source: str = ""          # which component asserted this edge
    created_at: datetime = Field(default_factory=_utcnow)


class AIAnalysis(Base):
    id: str = Field(default_factory=lambda: new_id("AI"))
    finding_id: str | None = None
    scan_id: str
    provider: str = ""
    model: str = ""
    classification: str = ""
    confidence: float = 0.0
    reasoning_summary: str = ""
    impact: str = ""
    remediation: str = ""
    related_findings: list[str] = Field(default_factory=list)
    human_validation_required: bool = True
    ai_generated: bool = True
    raw: dict[str, Any] = Field(default_factory=dict)
    # --- Velora 2.0 evidence-reasoning additions ---
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_validation: str = ""
    evidence_matrix: dict[str, Any] = Field(default_factory=dict)
    validation_status: ValidationState = ValidationState.HYPOTHESIZED
    prompt_sanitized: bool = True
    created_at: datetime = Field(default_factory=_utcnow)


class ReportRecord(Base):
    id: str = Field(default_factory=lambda: new_id("RPT"))
    scan_id: str
    formats: list[str] = Field(default_factory=list)
    paths: dict[str, str] = Field(default_factory=dict)
    #: Requested formats that could not be produced, with the reason. A format that
    #: silently degraded to another must be visible, not inferred from a missing path.
    unavailable: list[str] = Field(default_factory=list)
    operator: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class AuditLog(Base):
    id: str = Field(default_factory=lambda: new_id("AUD"))
    action: str
    actor: str = ""
    target_ref: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class Plugin(Base):
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Velora 2.0 domain models
#
# All new models are additive. Existing models are extended only with optional
# fields carrying safe defaults, so rows written by 0.1.0 deserialize unchanged.
# ---------------------------------------------------------------------------

class Engagement(Base):
    """A scoped body of assessment work: authorization, targets, scans, findings, reports."""

    id: str = Field(default_factory=lambda: new_id("ENG"))
    name: str
    client: str = ""
    description: str = ""
    status: EngagementStatus = EngagementStatus.PLANNED
    operator: str = ""
    authorization_reference: str = ""   # ticket / contract reference, never a secret
    authorization_granted_by: str = ""
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Identity(Base):
    """A test identity used for authorization testing.

    Credentials are NEVER stored. ``secret_ref`` names an environment variable that
    holds the credential/token at run time; only the reference is persisted.
    """

    id: str = Field(default_factory=lambda: new_id("IDENT"))
    engagement_id: str | None = None
    name: str
    role: IdentityRole = IdentityRole.ANONYMOUS
    description: str = ""
    # Env var name, e.g. "VELORA_IDENTITY_USER_A_TOKEN". Never the value itself.
    secret_ref: str = ""
    auth_scheme: str = "bearer"        # bearer | header | cookie | none
    auth_header_name: str = "Authorization"
    owned_resource_hints: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)

    @property
    def is_anonymous(self) -> bool:
        return self.role == IdentityRole.ANONYMOUS or not self.secret_ref


class DifferentialObservation(Base):
    """A structured comparison between a baseline and a candidate exchange."""

    id: str = Field(default_factory=lambda: new_id("DIFF"))
    scan_id: str | None = None
    engagement_id: str | None = None
    label: str = ""
    baseline_url: str = ""
    candidate_url: str = ""
    baseline_method: str = "GET"
    candidate_method: str = "GET"
    baseline_fingerprint: dict[str, Any] = Field(default_factory=dict)
    candidate_fingerprint: dict[str, Any] = Field(default_factory=dict)
    differences: list[dict[str, Any]] = Field(default_factory=list)
    classifications: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    interpretation: str = ""
    validation_required: bool = True
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)

    @property
    def changed(self) -> bool:
        return bool(self.differences)


class AuthorizationTest(Base):
    """One cell of the authorization matrix: identity × resource × expectation."""

    id: str = Field(default_factory=lambda: new_id("AUTHZ"))
    scan_id: str | None = None
    engagement_id: str | None = None
    plan_id: str | None = None
    identity_id: str = ""
    identity_role: IdentityRole = IdentityRole.ANONYMOUS
    resource_owner_identity_id: str | None = None
    url: str = ""
    method: str = "GET"
    expected: AccessExpectation = AccessExpectation.UNKNOWN
    observed: AccessObservation = AccessObservation.INCONCLUSIVE
    outcome: AuthzOutcome = AuthzOutcome.INCONCLUSIVE
    status_code: int | None = None
    response_size: int = 0
    differential_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    notes: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class Workflow(Base):
    """A business-logic workflow modelled as a state machine."""

    id: str = Field(default_factory=lambda: new_id("WF"))
    engagement_id: str | None = None
    target_id: str | None = None
    name: str
    description: str = ""
    identity_id: str | None = None
    initial_state: str = "start"
    authorized: bool = False   # must be explicitly authorized before execution
    created_at: datetime = Field(default_factory=_utcnow)


class WorkflowStep(Base):
    """One transition in a workflow, with a security assertion attached."""

    id: str = Field(default_factory=lambda: new_id("WFS"))
    workflow_id: str
    order_index: int = 0
    name: str = ""
    method: str = "GET"
    url: str = ""
    from_state: str = ""
    to_state: str = ""
    expected_status: list[int] = Field(default_factory=list)
    assertion: str = ""          # human-readable security assertion
    assert_status_in: list[int] = Field(default_factory=list)
    assert_body_contains: str = ""
    assert_body_absent: str = ""
    outcome: WorkflowStepOutcome = WorkflowStepOutcome.PENDING
    observed_status: int | None = None
    observed_state: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class RemediationAction(Base):
    """Tracks a fix from OPEN through verification."""

    id: str = Field(default_factory=lambda: new_id("REM"))
    finding_id: str
    engagement_id: str | None = None
    status: RemediationStatus = RemediationStatus.OPEN
    owner: str = ""
    note: str = ""
    opened_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    verified_at: datetime | None = None
    last_retest_id: str | None = None


class RetestRun(Base):
    """A retest of a specific finding, comparing original vs retest evidence."""

    id: str = Field(default_factory=lambda: new_id("RETEST"))
    finding_id: str
    remediation_id: str | None = None
    original_scan_id: str = ""
    retest_scan_id: str | None = None
    still_present: bool | None = None
    verdict: RemediationStatus = RemediationStatus.READY_FOR_RETEST
    detail: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class RegressionResult(Base):
    """One delta between a previous scan and a current scan."""

    id: str = Field(default_factory=lambda: new_id("REG"))
    engagement_id: str | None = None
    previous_scan_id: str = ""
    current_scan_id: str = ""
    change: RegressionChange = RegressionChange.PERSISTING_FINDING
    subject: str = ""            # finding fingerprint, endpoint url, technology name
    severity: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class BenchmarkCase(Base):
    """A ground-truth case used to measure Velora's own accuracy."""

    id: str = Field(default_factory=lambda: new_id("BC"))
    suite: str = "default"
    application: str = ""
    name: str = ""
    vulnerability_type: str = ""
    endpoint_path: str = "/"
    description: str = ""
    # Ground truth: should a check with this id fire on this case?
    expected_detection: bool = True
    expected_check_id: str = ""
    expected_severity: str = ""
    evidence_requirements: list[str] = Field(default_factory=list)
    cwe_id: str = "UNKNOWN"
    owasp_category: str = "UNKNOWN"
    created_at: datetime = Field(default_factory=_utcnow)


class BenchmarkRun(Base):
    """The measured result of executing a benchmark suite. Never fabricated."""

    id: str = Field(default_factory=lambda: new_id("BR"))
    suite: str = "default"
    scan_id: str | None = None
    target_url: str = ""
    total_cases: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_coverage: float = 0.0
    evidence_completeness: float = 0.0
    #: Detections the suite has no ground-truth case for. Counted as neither a true nor
    #: a false positive — and persisted, because this is precisely the number that says
    #: how much of what Velora found the benchmark is silent about.
    uncovered_detections: int = 0
    uncovered: list[dict[str, Any]] = Field(default_factory=list)
    #: None when not measured, never 0.0 — an unmeasured rate is not a zero rate.
    ai_agreement: float | None = None
    human_validation_rate: float | None = None
    per_case: list[dict[str, Any]] = Field(default_factory=list)
    velora_version: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class SecurityPostureSnapshot(Base):
    """A point-in-time Velora Security Posture Score. NOT a CVSS score."""

    id: str = Field(default_factory=lambda: new_id("POST"))
    engagement_id: str | None = None
    target_id: str | None = None
    scan_id: str = ""
    overall: float = 0.0
    #: Per-category score. A value of ``None`` means the category was NOT assessed by
    #: this scan — it is deliberately not collapsed to 0.0 or dropped, because an
    #: unassessed area must never read as either a failure or a clean bill of health.
    categories: dict[str, float | None] = Field(default_factory=dict)
    contributors: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""
    methodology_version: str = "1.0"
    created_at: datetime = Field(default_factory=_utcnow)


class AssessmentPlan(Base):
    """An AI-assisted (or manual) assessment plan. Steps require human approval."""

    id: str = Field(default_factory=lambda: new_id("PLAN"))
    engagement_id: str | None = None
    target_id: str = ""
    scan_id: str | None = None
    title: str = ""
    rationale: str = ""
    generated_by: str = "heuristic"
    approved_by: str = ""
    approved_at: datetime | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class AssessmentPlanStep(Base):
    """One proposed assessment action. Cannot execute until APPROVED and in scope."""

    id: str = Field(default_factory=lambda: new_id("STEP"))
    plan_id: str
    order_index: int = 0
    title: str = ""
    reason: str = ""
    capability: str = ""          # the Velora capability that would run it
    target_scope: str = ""
    required_permission: str = ""
    expected_evidence: str = ""
    risk: str = "low"
    validation_requirement: str = "human validation required"
    status: PlanStepStatus = PlanStepStatus.PROPOSED
    scope_ok: bool | None = None
    scope_reason: str = ""
    executed_at: datetime | None = None
    result_summary: str = ""


class KnowledgeEntity(Base):
    """A node in the security knowledge graph (CWE, OWASP, CVE, CPE, technology...)."""

    id: str = Field(default_factory=lambda: new_id("KE"))
    kind: str = "CWE"             # CWE | OWASP | CVE | CPE | TECHNOLOGY | CONTROL | REMEDIATION
    identifier: str = "UNKNOWN"   # e.g. CWE-639, A01:2021, CVE-2024-1234
    title: str = ""
    description: str = ""
    references: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class KnowledgeRelationship(Base):
    """A typed edge in the knowledge graph, always carrying its epistemic status."""

    id: str = Field(default_factory=lambda: new_id("KR"))
    source_kind: str = "FINDING"
    source_id: str = ""
    target_kind: str = "CWE"
    target_id: str = ""
    relation: str = "MAPS_TO"
    validation_status: ValidationState = ValidationState.INFERRED
    confidence: float = 0.5
    created_at: datetime = Field(default_factory=_utcnow)


class ReproductionRecord(Base):
    """Everything needed to reproduce a finding — without any secret material."""

    id: str = Field(default_factory=lambda: new_id("REPRO"))
    finding_id: str
    velora_version: str = ""
    scanner_id: str = ""
    scan_id: str = ""
    scan_profile: str = ""
    scope_policy_hash: str = ""
    scope_summary: str = ""
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    validation_state: str = "Potential"
    steps: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)


class SecurityGateResult(Base):
    """Outcome of a CI/CD security gate evaluation."""

    id: str = Field(default_factory=lambda: new_id("GATE"))
    scan_id: str = ""
    engagement_id: str | None = None
    decision: GateDecision = GateDecision.PASS
    policy: dict[str, Any] = Field(default_factory=dict)
    violations: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class BenchmarkCaseResult(Base):
    """Per-case benchmark outcome (kept inline in BenchmarkRun.per_case too)."""

    case_id: str
    outcome: BenchmarkOutcome
    detected: bool = False
    matched_finding_id: str | None = None
    detail: str = ""


class DiffDetail(Base):
    """One typed difference inside a DifferentialObservation."""

    classification: DiffClassification
    field: str = ""
    baseline: Any = None
    candidate: Any = None
    note: str = ""
