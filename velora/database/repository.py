"""Repository: typed CRUD over the SQLite tables.

A single generic mapper converts Pydantic domain models to/from rows by inspecting
field annotations, so adding a field to a model requires no repository changes as long
as the column exists. Reserved-word columns are remapped (e.g. Finding.references ->
findings.references_json).
"""
from __future__ import annotations

import json
import sqlite3
import typing
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from pydantic import BaseModel

from ..utils.logging import get_logger
from ..models.domain import (
    AIAnalysis,
    AssessmentPlan,
    AssessmentPlanStep,
    AuthorizationTest,
    BenchmarkCase,
    BenchmarkRun,
    DifferentialObservation,
    Engagement,
    Identity,
    KnowledgeEntity,
    KnowledgeRelationship,
    RegressionResult,
    RemediationAction,
    ReproductionRecord,
    RetestRun,
    SecurityGateResult,
    SecurityPostureSnapshot,
    Workflow,
    WorkflowStep,
    AttackEdge,
    AttackNode,
    AuditLog,
    Endpoint,
    Evidence,
    Finding,
    Host,
    ReportRecord,
    Scan,
    ScanEvent,
    ScopePolicyRecord,
    Target,
    Technology,
)

T = TypeVar("T", bound=BaseModel)

# model field name -> table column name overrides (SQL reserved words, etc.)
_COLUMN_OVERRIDES: dict[str, str] = {"references": "references_json"}

# domain model -> table name
_TABLE_FOR: dict[type, str] = {
    ScopePolicyRecord: "scope_policies",
    Target: "targets",
    Scan: "scans",
    ScanEvent: "scan_events",
    Host: "hosts",
    Endpoint: "endpoints",
    Technology: "technologies",
    Evidence: "evidence",
    Finding: "findings",
    AttackNode: "attack_graph_nodes",
    AttackEdge: "attack_graph_edges",
    AIAnalysis: "ai_analyses",
    ReportRecord: "reports",
    AuditLog: "audit_logs",
    # --- Velora 2.0 ---
    Engagement: "engagements",
    Identity: "identities",
    DifferentialObservation: "differential_observations",
    AuthorizationTest: "authorization_tests",
    Workflow: "workflows",
    WorkflowStep: "workflow_steps",
    RemediationAction: "remediation_actions",
    RetestRun: "retest_runs",
    RegressionResult: "regression_results",
    BenchmarkCase: "benchmark_cases",
    BenchmarkRun: "benchmark_runs",
    SecurityPostureSnapshot: "security_posture_snapshots",
    AssessmentPlan: "assessment_plans",
    AssessmentPlanStep: "assessment_plan_steps",
    KnowledgeEntity: "knowledge_entities",
    KnowledgeRelationship: "knowledge_relationships",
    ReproductionRecord: "reproduction_records",
    SecurityGateResult: "security_gate_results",
}


def _is_json_field(annotation: Any) -> bool:
    origin = typing.get_origin(annotation)
    if origin in (list, dict):
        return True
    # Optional[...] / Union handling
    if origin is typing.Union:
        return any(_is_json_field(a) for a in typing.get_args(annotation))
    return annotation in (list, dict)


def _allows_none(annotation: Any) -> bool:
    """True when a field's annotation permits None (Optional[...] / X | None)."""
    if annotation is None or annotation is type(None):
        return True
    if typing.get_origin(annotation) is typing.Union:
        return any(a is type(None) for a in typing.get_args(annotation))
    # PEP 604 unions (X | None) surface as types.UnionType
    import types as _types

    if isinstance(annotation, getattr(_types, "UnionType", ())):
        return any(a is type(None) for a in typing.get_args(annotation))
    return False


def _json_fields(model_cls: type[BaseModel]) -> set[str]:
    return {
        name
        for name, field in model_cls.model_fields.items()
        if _is_json_field(field.annotation)
    }


log = get_logger("database.repository")


def _column(name: str) -> str:
    return _COLUMN_OVERRIDES.get(name, name)


def _encode_value(value: Any, is_json: bool) -> Any:
    if is_json:
        return json.dumps(value, default=str)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return int(value)
    return value


def to_row(model: BaseModel) -> dict[str, Any]:
    json_fields = _json_fields(type(model))
    row: dict[str, Any] = {}
    for name in type(model).model_fields:
        value = getattr(model, name)
        row[_column(name)] = _encode_value(value, name in json_fields)
    return row


def from_row(model_cls: type[T], row: sqlite3.Row | dict[str, Any]) -> T:
    data = dict(row)
    json_fields = _json_fields(model_cls)
    kwargs: dict[str, Any] = {}
    for name, field in model_cls.model_fields.items():
        col = _column(name)
        if col not in data:
            continue
        value = data[col]
        # A column added by a later migration is NULL for pre-existing rows. If the
        # model field does not accept None, omit it so its default applies. Without
        # this, every additive column would break reads of legacy rows.
        if value is None and not _allows_none(field.annotation):
            continue
        if name in json_fields and isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                # A corrupted JSON column must not make the whole row unreadable: the
                # rest of the record is still the best information available, and an
                # operator investigating a damaged database needs to be able to read
                # it. The field falls back to its default and the damage is logged.
                log.error("CORRUPT_JSON_COLUMN model=%s field=%s — falling back to the "
                          "field default", model_cls.__name__, name)
                continue
        kwargs[name] = value
    return model_cls(**kwargs)


class Repository:
    """Thin data-access object bound to a SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ---- generic operations --------------------------------------------
    def insert(self, model: BaseModel) -> BaseModel:
        table = _TABLE_FOR[type(model)]
        row = to_row(model)
        cols = ", ".join(row.keys())
        placeholders = ", ".join("?" for _ in row)
        self.conn.execute(
            f"INSERT INTO {table} ({cols}) VALUES ({placeholders});",  # noqa: S608 (table from static map)
            tuple(row.values()),
        )
        return model

    def update(self, model: BaseModel) -> BaseModel:
        table = _TABLE_FOR[type(model)]
        row = to_row(model)
        row_id = row.pop("id")
        assignments = ", ".join(f"{k} = ?" for k in row)
        self.conn.execute(
            f"UPDATE {table} SET {assignments} WHERE id = ?;",  # noqa: S608
            (*row.values(), row_id),
        )
        return model

    def _get(self, model_cls: type[T], id_: str) -> T | None:
        table = _TABLE_FOR[model_cls]
        cur = self.conn.execute(f"SELECT * FROM {table} WHERE id = ?;", (id_,))  # noqa: S608
        row = cur.fetchone()
        return from_row(model_cls, row) if row else None

    def _list(self, model_cls: type[T], where: str = "", params: tuple = ()) -> list[T]:
        table = _TABLE_FOR[model_cls]
        sql = f"SELECT * FROM {table}"  # noqa: S608
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY rowid ASC;"
        cur = self.conn.execute(sql, params)
        return [from_row(model_cls, r) for r in cur.fetchall()]

    # ---- targets --------------------------------------------------------
    def add_target(self, t: Target) -> Target:
        return self.insert(t)  # type: ignore[return-value]

    def get_target(self, id_: str) -> Target | None:
        return self._get(Target, id_)

    def list_targets(self) -> list[Target]:
        return self._list(Target)

    def get_target_by_name(self, name: str) -> Target | None:
        rows = self._list(Target, "name = ?", (name,))
        return rows[0] if rows else None

    # ---- scope ----------------------------------------------------------
    def add_scope(self, s: ScopePolicyRecord) -> ScopePolicyRecord:
        return self.insert(s)  # type: ignore[return-value]

    def get_scope(self, id_: str) -> ScopePolicyRecord | None:
        return self._get(ScopePolicyRecord, id_)

    # ---- scans ----------------------------------------------------------
    def add_scan(self, s: Scan) -> Scan:
        return self.insert(s)  # type: ignore[return-value]

    def update_scan(self, s: Scan) -> Scan:
        return self.update(s)  # type: ignore[return-value]

    def get_scan(self, id_: str) -> Scan | None:
        return self._get(Scan, id_)

    def list_scans(self, target_id: str | None = None) -> list[Scan]:
        if target_id:
            return self._list(Scan, "target_id = ?", (target_id,))
        return self._list(Scan)

    # ---- scan events ----------------------------------------------------
    def add_event(self, e: ScanEvent) -> ScanEvent:
        return self.insert(e)  # type: ignore[return-value]

    def list_events(self, scan_id: str) -> list[ScanEvent]:
        return self._list(ScanEvent, "scan_id = ?", (scan_id,))

    # ---- hosts / endpoints / technologies -------------------------------
    def add_host(self, h: Host) -> Host:
        return self.insert(h)  # type: ignore[return-value]

    def list_hosts(self, scan_id: str) -> list[Host]:
        return self._list(Host, "scan_id = ?", (scan_id,))

    def add_endpoint(self, e: Endpoint) -> Endpoint:
        return self.insert(e)  # type: ignore[return-value]

    def list_endpoints(self, scan_id: str) -> list[Endpoint]:
        return self._list(Endpoint, "scan_id = ?", (scan_id,))

    def add_technology(self, t: Technology) -> Technology:
        return self.insert(t)  # type: ignore[return-value]

    def list_technologies(self, scan_id: str) -> list[Technology]:
        return self._list(Technology, "scan_id = ?", (scan_id,))

    # ---- evidence -------------------------------------------------------
    def add_evidence(self, e: Evidence) -> Evidence:
        return self.insert(e)  # type: ignore[return-value]

    def get_evidence(self, id_: str) -> Evidence | None:
        return self._get(Evidence, id_)

    def list_evidence(self, scan_id: str) -> list[Evidence]:
        return self._list(Evidence, "scan_id = ?", (scan_id,))

    def list_evidence_for_finding(self, finding_id: str) -> list[Evidence]:
        return self._list(Evidence, "finding_id = ?", (finding_id,))

    # ---- findings -------------------------------------------------------
    def add_finding(self, f: Finding) -> Finding:
        return self.insert(f)  # type: ignore[return-value]

    def update_finding(self, f: Finding) -> Finding:
        return self.update(f)  # type: ignore[return-value]

    def get_finding(self, id_: str) -> Finding | None:
        return self._get(Finding, id_)

    def list_findings(self, scan_id: str | None = None) -> list[Finding]:
        if scan_id:
            return self._list(Finding, "scan_id = ?", (scan_id,))
        return self._list(Finding)

    # ---- attack graph ---------------------------------------------------
    def add_node(self, n: AttackNode) -> AttackNode:
        return self.insert(n)  # type: ignore[return-value]

    def add_edge(self, e: AttackEdge) -> AttackEdge:
        return self.insert(e)  # type: ignore[return-value]

    def list_nodes(self, scan_id: str) -> list[AttackNode]:
        return self._list(AttackNode, "scan_id = ?", (scan_id,))

    def list_edges(self, scan_id: str) -> list[AttackEdge]:
        return self._list(AttackEdge, "scan_id = ?", (scan_id,))

    # ---- AI analyses ----------------------------------------------------
    def add_ai_analysis(self, a: AIAnalysis) -> AIAnalysis:
        return self.insert(a)  # type: ignore[return-value]

    def get_ai_analysis(self, id_: str) -> AIAnalysis | None:
        return self._get(AIAnalysis, id_)

    def list_ai_analyses(self, scan_id: str | None = None) -> list[AIAnalysis]:
        if scan_id:
            return self._list(AIAnalysis, "scan_id = ?", (scan_id,))
        return self._list(AIAnalysis)

    def list_ai_analyses_for_finding(self, finding_id: str) -> list[AIAnalysis]:
        return self._list(AIAnalysis, "finding_id = ?", (finding_id,))

    # ---- reports --------------------------------------------------------
    def add_report(self, r: ReportRecord) -> ReportRecord:
        return self.insert(r)  # type: ignore[return-value]

    def list_reports(self, scan_id: str) -> list[ReportRecord]:
        return self._list(ReportRecord, "scan_id = ?", (scan_id,))

    # ---- audit log (append-only) ---------------------------------------
    def audit(self, log_entry: AuditLog) -> AuditLog:
        return self.insert(log_entry)  # type: ignore[return-value]

    def list_audit(self, limit: int = 200) -> list[AuditLog]:
        cur = self.conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?;", (limit,)
        )
        return [from_row(AuditLog, r) for r in cur.fetchall()]


    # =====================================================================
    # Velora 2.0 accessors
    # =====================================================================

    # ---- engagements ----------------------------------------------------
    def add_engagement(self, e: Engagement) -> Engagement:
        return self.insert(e)  # type: ignore[return-value]

    def update_engagement(self, e: Engagement) -> Engagement:
        return self.update(e)  # type: ignore[return-value]

    def get_engagement(self, id_: str) -> Engagement | None:
        return self._get(Engagement, id_)

    def get_engagement_by_name(self, name: str) -> Engagement | None:
        rows = self._list(Engagement, "name = ?", (name,))
        return rows[0] if rows else None

    def list_engagements(self) -> list[Engagement]:
        return self._list(Engagement)

    # ---- identities -----------------------------------------------------
    def add_identity(self, i: Identity) -> Identity:
        return self.insert(i)  # type: ignore[return-value]

    def get_identity(self, id_: str) -> Identity | None:
        return self._get(Identity, id_)

    def get_identity_by_name(self, name: str) -> Identity | None:
        rows = self._list(Identity, "name = ?", (name,))
        return rows[0] if rows else None

    def list_identities(self, engagement_id: str | None = None) -> list[Identity]:
        if engagement_id:
            return self._list(Identity, "engagement_id = ?", (engagement_id,))
        return self._list(Identity)

    # ---- differential ---------------------------------------------------
    def add_differential(self, d: DifferentialObservation) -> DifferentialObservation:
        return self.insert(d)  # type: ignore[return-value]

    def get_differential(self, id_: str) -> DifferentialObservation | None:
        return self._get(DifferentialObservation, id_)

    def list_differentials(self, scan_id: str | None = None) -> list[DifferentialObservation]:
        if scan_id:
            return self._list(DifferentialObservation, "scan_id = ?", (scan_id,))
        return self._list(DifferentialObservation)

    # ---- authorization tests -------------------------------------------
    def add_authz_test(self, t: AuthorizationTest) -> AuthorizationTest:
        return self.insert(t)  # type: ignore[return-value]

    def list_authz_tests(self, scan_id: str | None = None) -> list[AuthorizationTest]:
        if scan_id:
            return self._list(AuthorizationTest, "scan_id = ?", (scan_id,))
        return self._list(AuthorizationTest)

    # ---- workflows ------------------------------------------------------
    def add_workflow(self, w: Workflow) -> Workflow:
        return self.insert(w)  # type: ignore[return-value]

    def update_workflow(self, w: Workflow) -> Workflow:
        return self.update(w)  # type: ignore[return-value]

    def get_workflow(self, id_: str) -> Workflow | None:
        return self._get(Workflow, id_)

    def get_workflow_by_name(self, name: str) -> Workflow | None:
        rows = self._list(Workflow, "name = ?", (name,))
        return rows[0] if rows else None

    def list_workflows(self) -> list[Workflow]:
        return self._list(Workflow)

    def add_workflow_step(self, s: WorkflowStep) -> WorkflowStep:
        return self.insert(s)  # type: ignore[return-value]

    def update_workflow_step(self, s: WorkflowStep) -> WorkflowStep:
        return self.update(s)  # type: ignore[return-value]

    def list_workflow_steps(self, workflow_id: str) -> list[WorkflowStep]:
        steps = self._list(WorkflowStep, "workflow_id = ?", (workflow_id,))
        return sorted(steps, key=lambda s: s.order_index)

    # ---- remediation / retest -------------------------------------------
    def add_remediation(self, r: RemediationAction) -> RemediationAction:
        return self.insert(r)  # type: ignore[return-value]

    def update_remediation(self, r: RemediationAction) -> RemediationAction:
        return self.update(r)  # type: ignore[return-value]

    def get_remediation(self, id_: str) -> RemediationAction | None:
        return self._get(RemediationAction, id_)

    def get_remediation_for_finding(self, finding_id: str) -> RemediationAction | None:
        rows = self._list(RemediationAction, "finding_id = ?", (finding_id,))
        return rows[-1] if rows else None

    def list_remediations(self) -> list[RemediationAction]:
        return self._list(RemediationAction)

    def add_retest(self, r: RetestRun) -> RetestRun:
        return self.insert(r)  # type: ignore[return-value]

    def list_retests(self, finding_id: str | None = None) -> list[RetestRun]:
        if finding_id:
            return self._list(RetestRun, "finding_id = ?", (finding_id,))
        return self._list(RetestRun)

    # ---- regression -----------------------------------------------------
    def add_regression(self, r: RegressionResult) -> RegressionResult:
        return self.insert(r)  # type: ignore[return-value]

    def list_regressions(self, current_scan_id: str | None = None) -> list[RegressionResult]:
        if current_scan_id:
            return self._list(RegressionResult, "current_scan_id = ?", (current_scan_id,))
        return self._list(RegressionResult)

    # ---- benchmark ------------------------------------------------------
    def add_benchmark_case(self, c: BenchmarkCase) -> BenchmarkCase:
        return self.insert(c)  # type: ignore[return-value]

    def list_benchmark_cases(self, suite: str | None = None) -> list[BenchmarkCase]:
        if suite:
            return self._list(BenchmarkCase, "suite = ?", (suite,))
        return self._list(BenchmarkCase)

    def add_benchmark_run(self, r: BenchmarkRun) -> BenchmarkRun:
        return self.insert(r)  # type: ignore[return-value]

    def get_benchmark_run(self, id_: str) -> BenchmarkRun | None:
        return self._get(BenchmarkRun, id_)

    def list_benchmark_runs(self) -> list[BenchmarkRun]:
        return self._list(BenchmarkRun)

    # ---- posture --------------------------------------------------------
    def add_posture(self, p: SecurityPostureSnapshot) -> SecurityPostureSnapshot:
        return self.insert(p)  # type: ignore[return-value]

    def list_postures(self, target_id: str | None = None) -> list[SecurityPostureSnapshot]:
        if target_id:
            return self._list(SecurityPostureSnapshot, "target_id = ?", (target_id,))
        return self._list(SecurityPostureSnapshot)

    # ---- assessment plans -----------------------------------------------
    def add_plan(self, p: AssessmentPlan) -> AssessmentPlan:
        return self.insert(p)  # type: ignore[return-value]

    def update_plan(self, p: AssessmentPlan) -> AssessmentPlan:
        return self.update(p)  # type: ignore[return-value]

    def get_plan(self, id_: str) -> AssessmentPlan | None:
        return self._get(AssessmentPlan, id_)

    def list_plans(self) -> list[AssessmentPlan]:
        return self._list(AssessmentPlan)

    def add_plan_step(self, s: AssessmentPlanStep) -> AssessmentPlanStep:
        return self.insert(s)  # type: ignore[return-value]

    def update_plan_step(self, s: AssessmentPlanStep) -> AssessmentPlanStep:
        return self.update(s)  # type: ignore[return-value]

    def get_plan_step(self, id_: str) -> AssessmentPlanStep | None:
        return self._get(AssessmentPlanStep, id_)

    def list_plan_steps(self, plan_id: str) -> list[AssessmentPlanStep]:
        steps = self._list(AssessmentPlanStep, "plan_id = ?", (plan_id,))
        return sorted(steps, key=lambda s: s.order_index)

    # ---- knowledge graph -------------------------------------------------
    def add_knowledge_entity(self, e: KnowledgeEntity) -> KnowledgeEntity:
        return self.insert(e)  # type: ignore[return-value]

    def get_knowledge_entity_by_identifier(self, identifier: str) -> KnowledgeEntity | None:
        rows = self._list(KnowledgeEntity, "identifier = ?", (identifier,))
        return rows[0] if rows else None

    def list_knowledge_entities(self, kind: str | None = None) -> list[KnowledgeEntity]:
        if kind:
            return self._list(KnowledgeEntity, "kind = ?", (kind,))
        return self._list(KnowledgeEntity)

    def add_knowledge_relationship(self, r: KnowledgeRelationship) -> KnowledgeRelationship:
        return self.insert(r)  # type: ignore[return-value]

    def list_knowledge_relationships(self, source_id: str | None = None) -> list[KnowledgeRelationship]:
        if source_id:
            return self._list(KnowledgeRelationship, "source_id = ?", (source_id,))
        return self._list(KnowledgeRelationship)

    # ---- reproduction ----------------------------------------------------
    def add_reproduction(self, r: ReproductionRecord) -> ReproductionRecord:
        return self.insert(r)  # type: ignore[return-value]

    def get_reproduction_for_finding(self, finding_id: str) -> ReproductionRecord | None:
        rows = self._list(ReproductionRecord, "finding_id = ?", (finding_id,))
        return rows[-1] if rows else None

    # ---- security gate ---------------------------------------------------
    def add_gate_result(self, g: SecurityGateResult) -> SecurityGateResult:
        return self.insert(g)  # type: ignore[return-value]

    def list_gate_results(self, scan_id: str | None = None) -> list[SecurityGateResult]:
        if scan_id:
            return self._list(SecurityGateResult, "scan_id = ?", (scan_id,))
        return self._list(SecurityGateResult)
