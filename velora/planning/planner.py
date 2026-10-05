"""Assessment planner.

Produces an ordered plan of assessment steps for a target. Two planners exist and both
obey the same contract:

* Every step names a capability from :mod:`velora.planning.capabilities`. Anything else
  is dropped before the plan is stored.
* Every step is scope-validated against the target's ScopePolicy at generation time, and
  again immediately before execution.
* Every step starts as ``PROPOSED``. Execution requires an explicit human ``approve``.
* The planner cannot execute anything itself.

``HeuristicPlanner`` is deterministic and offline: it reasons from what has and has not
been assessed. ``AIPlanner`` asks a provider to *order and justify* a selection from the
same fixed catalog, then re-validates every element. If the provider returns anything
outside the catalog it is discarded, so a compromised or confused model cannot widen
Velora's behaviour.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..ai.base import AIProvider, AnalysisInput
from ..database.repository import Repository
from ..models.domain import AssessmentPlan, AssessmentPlanStep, AuditLog, Target
from ..models.enums import PlanStepStatus
from ..scope.manager import ScopeManager
from ..utils.errors import AIProviderError
from ..utils.logging import get_logger
from . import capabilities as caps

log = get_logger("planning")


@dataclass
class PlannedStep:
    capability: str
    title: str
    reason: str
    order_index: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"capability": self.capability, "title": self.title,
                "reason": self.reason, "order_index": self.order_index}


@dataclass
class PlanDraft:
    title: str
    rationale: str
    steps: list[PlannedStep] = field(default_factory=list)
    generated_by: str = "heuristic"
    discarded: list[dict[str, str]] = field(default_factory=list)


class HeuristicPlanner:
    """Deterministic planner driven by assessment coverage, not prose."""

    name = "heuristic"

    def plan(self, target: Target, context: dict[str, Any]) -> PlanDraft:
        endpoints = context.get("endpoints", 0)
        technologies = context.get("technologies", 0)
        findings_by_category: dict[str, int] = context.get("findings_by_category", {})
        has_identities = context.get("identities", 0) >= 2
        has_authz_tests = context.get("authz_tests", 0) > 0
        profile = context.get("profile", "safe")

        draft = PlanDraft(
            title=f"Assessment plan for {target.name or target.url}",
            rationale=("Derived from current assessment coverage: which capabilities have "
                       "already produced evidence and which have not."),
            generated_by=self.name)

        order = 0

        def add(key: str, reason: str) -> None:
            nonlocal order
            capability = caps.get(key)
            if capability is None:
                return
            draft.steps.append(PlannedStep(key, capability.title, reason, order))
            order += 1

        if endpoints == 0:
            add("recon", "No reconnaissance evidence exists for this target yet; headers, "
                         "TLS posture and HTTP methods are unknown.")
            add("crawl", "The attack surface is unmapped, so no endpoint inventory exists "
                         "to assess against.")
        else:
            add("recon", f"Refresh reconnaissance: {technologies} technology detection(s) "
                         "on record; server posture may have changed since the last run.")

        add("scan.safe", "Passive checks establish the configuration baseline (headers, "
                         "cookies, TLS, information disclosure) with no active probing.")

        if not findings_by_category.get("input_validation") and profile != "safe":
            add("scan.standard", "Input-reflection surface has not been assessed. This uses "
                                 "a benign marker only and sends no payloads.")

        if has_identities and not has_authz_tests:
            add("authz.matrix", "Multiple test identities are configured but no "
                                "identity/resource matrix has been executed, so horizontal "
                                "and vertical access control are unverified.")
        elif not has_identities:
            add("differential.compare",
                "No second identity is configured, so authorization cannot be tested "
                "directly. A controlled differential comparison is the safe alternative "
                "for observing behavioural differences.")

        if findings_by_category.get("authorization"):
            add("differential.compare",
                "An authorization indicator exists; an owner-baseline differential would "
                "strengthen or refute it before it is escalated.")

        add("benchmark", "Measure detection accuracy against ground truth so the results "
                         "of this engagement can be interpreted with known precision and "
                         "recall.")
        return draft


class AIPlanner:
    """LLM-assisted planner constrained to the fixed capability catalog."""

    name = "ai"

    def __init__(self, provider: AIProvider) -> None:
        self.provider = provider

    def plan(self, target: Target, context: dict[str, Any]) -> PlanDraft:
        catalog = {k: c.to_dict() for k, c in caps.CAPABILITIES.items()}
        data = AnalysisInput(
            target=target.url,
            endpoint=target.url,
            method="GET",
            finding_title="Assessment planning",
            category="planning",
            severity="Informational",
            scanner_confidence="Firm",
            description=("Select and order assessment capabilities for this target. You may "
                         "ONLY choose keys from the provided catalog."),
            evidence_excerpts=[json.dumps(context)],
        )
        data.evidence_matrix = {"capability_catalog": catalog, "coverage": context}

        try:
            result = self.provider.analyze(data)
            selected = self._extract(result.raw, result.reasoning_summary)
            rationale = result.reasoning_summary
            generated_by = f"ai:{result.provider}"
        except AIProviderError as exc:
            log.warning("AI planner failed (%s); falling back to the heuristic planner", exc)
            return HeuristicPlanner().plan(target, context)

        draft = PlanDraft(title=f"AI-assisted assessment plan for {target.name or target.url}",
                          rationale=rationale, generated_by=generated_by)
        order = 0
        for key in selected:
            capability = caps.get(key)
            if capability is None:
                draft.discarded.append(
                    {"capability": str(key),
                     "reason": "not in the fixed capability catalog; discarded"})
                continue
            draft.steps.append(PlannedStep(
                key, capability.title,
                f"Selected by the AI planner from the fixed catalog. {capability.description}",
                order))
            order += 1

        if not draft.steps:
            log.warning("AI planner returned no valid capabilities; using the heuristic plan")
            fallback = HeuristicPlanner().plan(target, context)
            fallback.discarded = draft.discarded
            return fallback
        return draft

    @staticmethod
    def _extract(raw: dict[str, Any], summary: str) -> list[str]:
        """Pull capability keys out of a provider response, tolerating shape drift."""
        for key in ("capabilities", "plan", "steps"):
            value = raw.get(key)
            if isinstance(value, list):
                return [str(v) for v in value]
        # Fall back to scanning the summary for known keys, in order of appearance.
        found: list[str] = []
        lowered = summary.lower()
        for candidate in caps.keys():
            index = lowered.find(candidate)
            if index >= 0:
                found.append((index, candidate))  # type: ignore[arg-type]
        return [c for _, c in sorted(found)]  # type: ignore[misc]


class PlanService:
    """Creates, validates, approves and records assessment plans."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def context_for(self, target: Target, scan_id: str | None = None) -> dict[str, Any]:
        scans = self.repo.list_scans(target.id)
        latest = self.repo.get_scan(scan_id) if scan_id else (scans[-1] if scans else None)
        findings_by_category: dict[str, int] = {}
        endpoints = technologies = authz_tests = 0
        if latest is not None:
            for finding in self.repo.list_findings(latest.id):
                findings_by_category[finding.category] = \
                    findings_by_category.get(finding.category, 0) + 1
            endpoints = len(self.repo.list_endpoints(latest.id))
            technologies = len(self.repo.list_technologies(latest.id))
            authz_tests = len(self.repo.list_authz_tests(latest.id))
        return {
            "target": target.url,
            "authorization_status": target.authorization_status.value,
            "scans": len(scans),
            "endpoints": endpoints,
            "technologies": technologies,
            "identities": len(self.repo.list_identities(target.engagement_id)),
            "authz_tests": authz_tests,
            "findings_by_category": findings_by_category,
            "profile": latest.profile.value if latest else "safe",
        }

    def generate(self, target: Target, *, planner: HeuristicPlanner | AIPlanner,
                 scope: ScopeManager, scan_id: str | None = None,
                 engagement_id: str | None = None) -> tuple[AssessmentPlan,
                                                            list[AssessmentPlanStep]]:
        context = self.context_for(target, scan_id)
        draft = planner.plan(target, context)

        plan = AssessmentPlan(
            engagement_id=engagement_id, target_id=target.id, scan_id=scan_id,
            title=draft.title, rationale=draft.rationale, generated_by=draft.generated_by)
        self.repo.add_plan(plan)

        steps: list[AssessmentPlanStep] = []
        # Scope-validate every step at generation time. A step targeting an out-of-scope
        # URL is stored as PROPOSED but permanently marked scope_ok=False.
        decision = scope.check(target.url)
        for planned in draft.steps:
            capability = caps.get(planned.capability)
            assert capability is not None  # guaranteed by the planners
            step = AssessmentPlanStep(
                plan_id=plan.id, order_index=planned.order_index,
                title=planned.title, reason=planned.reason,
                capability=planned.capability, target_scope=target.url,
                required_permission=capability.required_permission,
                expected_evidence=capability.expected_evidence,
                risk=capability.risk,
                validation_requirement=(
                    "human approval required before execution"
                    + ("; this capability always requires explicit review"
                       if planned.capability in caps.REQUIRES_EXPLICIT_REVIEW else "")),
                status=PlanStepStatus.PROPOSED,
                scope_ok=decision.allowed,
                scope_reason=decision.reason)
            self.repo.add_plan_step(step)
            steps.append(step)

        self.repo.audit(AuditLog(
            action="plan_created", target_ref=plan.id,
            detail={"target": target.url, "steps": len(steps),
                    "generated_by": draft.generated_by,
                    "discarded": draft.discarded}))
        log.info("PLAN_CREATED plan=%s steps=%d by=%s", plan.id, len(steps), draft.generated_by)
        return plan, steps

    def approve(self, plan_id: str, operator: str, *, step_ids: list[str] | None = None
                ) -> list[AssessmentPlanStep]:
        """Approve a plan (or specific steps). Out-of-scope steps can never be approved."""
        plan = self.repo.get_plan(plan_id)
        if plan is None:
            raise ValueError(f"plan not found: {plan_id}")
        approved: list[AssessmentPlanStep] = []
        for step in self.repo.list_plan_steps(plan_id):
            if step_ids and step.id not in step_ids:
                continue
            if step.scope_ok is False:
                step.status = PlanStepStatus.REJECTED
                step.result_summary = f"refused: out of scope ({step.scope_reason})"
            else:
                step.status = PlanStepStatus.APPROVED
            self.repo.update_plan_step(step)
            if step.status == PlanStepStatus.APPROVED:
                approved.append(step)
        plan.approved_by = operator
        plan.approved_at = datetime.now(timezone.utc)
        self.repo.update_plan(plan)
        self.repo.audit(AuditLog(action="plan_approved", actor=operator, target_ref=plan_id,
                                 detail={"approved_steps": len(approved)}))
        log.info("PLAN_APPROVED plan=%s by=%s steps=%d", plan_id, operator, len(approved))
        return approved

    def reject(self, plan_id: str, operator: str, step_id: str) -> AssessmentPlanStep | None:
        step = self.repo.get_plan_step(step_id)
        if step is None or step.plan_id != plan_id:
            return None
        step.status = PlanStepStatus.REJECTED
        self.repo.update_plan_step(step)
        self.repo.audit(AuditLog(action="plan_step_rejected", actor=operator,
                                 target_ref=step_id, detail={"plan": plan_id}))
        return step

    def executable_steps(self, plan_id: str, scope: ScopeManager
                         ) -> tuple[list[AssessmentPlanStep], list[str]]:
        """Steps that may run now, plus the reasons other steps may not.

        Scope is re-checked here, immediately before execution — approval alone is never
        sufficient, because scope may have changed since the plan was approved.
        """
        runnable: list[AssessmentPlanStep] = []
        blocked: list[str] = []
        for step in self.repo.list_plan_steps(plan_id):
            if step.status != PlanStepStatus.APPROVED:
                blocked.append(f"{step.title}: status is {step.status.value}, not APPROVED")
                continue
            decision = scope.check(step.target_scope)
            if not decision.allowed:
                step.scope_ok = False
                step.scope_reason = decision.reason
                step.status = PlanStepStatus.REJECTED
                step.result_summary = f"refused at execution time: {decision.reason}"
                self.repo.update_plan_step(step)
                blocked.append(f"{step.title}: out of scope ({decision.reason})")
                continue
            runnable.append(step)
        return runnable, blocked

    def mark_executed(self, step: AssessmentPlanStep, summary: str) -> AssessmentPlanStep:
        step.status = PlanStepStatus.EXECUTED
        step.executed_at = datetime.now(timezone.utc)
        step.result_summary = summary
        self.repo.update_plan_step(step)
        return step
