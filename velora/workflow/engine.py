"""Business-logic workflow execution.

Two things happen here:

1. **Baseline run** — execute the declared steps in order, evaluate each step's security
   assertion, and record the observed state machine.
2. **Step-skip probe** — for each step marked ``required``, re-run the sequence with that
   step omitted. If the terminal step still succeeds, a required control was bypassable.
   That is the classic business-logic flaw (checkout without payment, publish without
   review) and it cannot be found by any single-request check.

Safety rules, enforced here and not by convention:

* A workflow runs only when its definition sets ``authorized: true`` **and** the caller
  passes an explicit acknowledgement.
* Destructive verbs are refused at parse time (see ``spec.REFUSED_METHODS``).
* Every request goes through the scope-gated client.
* Findings are ``Potential`` and require human validation — a skip that appears to work
  may be a legitimate flow the operator did not model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.http import HttpResponse, SafeHTTPClient
from ..database.repository import Repository
from ..evidence.store import EvidenceStore
from ..models.domain import AuditLog, Finding, Scan, Workflow, WorkflowStep
from ..models.enums import (
    Confidence,
    FindingStatus,
    Severity,
    ValidationState,
    WorkflowStepOutcome,
)
from ..risk.scoring import PriorityInputs, compute_priority
from ..scanners.base import EvidenceItem
from ..utils.errors import AuthorizationError, RateLimitExceeded, ScopeViolation
from ..utils.logging import get_logger
from .spec import StepSpec, WorkflowSpec

log = get_logger("workflow")


@dataclass
class StepResult:
    step: StepSpec
    outcome: WorkflowStepOutcome
    observed_status: int | None = None
    observed_state: str = ""
    detail: str = ""
    evidence_ids: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.outcome == WorkflowStepOutcome.PASSED


@dataclass
class WorkflowRunResult:
    spec: WorkflowSpec
    steps: list[StepResult] = field(default_factory=list)
    final_state: str = ""
    skip_probes: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def completed(self) -> bool:
        return all(s.succeeded for s in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow": self.spec.name,
            "final_state": self.final_state,
            "completed": self.completed,
            "steps": [{"name": s.step.name, "outcome": s.outcome.value,
                       "status": s.observed_status, "state": s.observed_state,
                       "detail": s.detail} for s in self.steps],
            "skip_probes": self.skip_probes,
            "findings": [f.id for f in self.findings],
        }


class WorkflowEngine:
    def __init__(self, client: SafeHTTPClient, repo: Repository) -> None:
        self.client = client
        self.repo = repo
        self.evidence = EvidenceStore(repo)

    # ---- execution -------------------------------------------------------
    async def _execute(self, step: StepSpec) -> HttpResponse | None:
        try:
            return await self.client.request(
                step.method, step.url,
                headers=step.headers or None,
                # A declared body is actually sent. It used to be parsed, stored and
                # silently dropped, so a POST step in a workflow file sent nothing.
                body=step.body or None)
        except ScopeViolation as exc:
            log.security("WORKFLOW_STEP_BLOCKED step=%s url=%s reason=%s",
                         step.name, step.url, exc.reason)
            return None
        except RateLimitExceeded:
            log.warning("workflow stopped: request budget exhausted")
            return None

    def _evaluate(self, step: StepSpec, resp: HttpResponse | None,
                  current_state: str) -> StepResult:
        if resp is None:
            return StepResult(step, WorkflowStepOutcome.BLOCKED_BY_SCOPE,
                              detail="request blocked by scope policy or request budget",
                              observed_state=current_state)
        if resp.error:
            return StepResult(step, WorkflowStepOutcome.ERROR, resp.status_code,
                              current_state, f"transport error: {resp.error}")

        if step.from_state and step.from_state != current_state:
            return StepResult(
                step, WorkflowStepOutcome.UNEXPECTED_STATE, resp.status_code, current_state,
                f"step expects state '{step.from_state}' but the machine is in "
                f"'{current_state}'")

        failures: list[str] = []
        if step.assert_status_in and resp.status_code not in step.assert_status_in:
            failures.append(f"status {resp.status_code} not in {step.assert_status_in}")
        if step.assert_body_contains and step.assert_body_contains not in resp.body:
            failures.append(f"body does not contain {step.assert_body_contains!r}")
        if step.assert_body_absent and step.assert_body_absent in resp.body:
            failures.append(f"body unexpectedly contains {step.assert_body_absent!r}")

        if failures:
            return StepResult(step, WorkflowStepOutcome.ASSERTION_FAILED, resp.status_code,
                              current_state, "; ".join(failures))
        return StepResult(step, WorkflowStepOutcome.PASSED, resp.status_code,
                          step.to_state or current_state, "assertion satisfied")

    async def run_sequence(self, spec: WorkflowSpec,
                           steps: list[StepSpec]) -> tuple[list[StepResult], str]:
        """Run an ordered list of steps, returning the results and the final state."""
        results: list[StepResult] = []
        state = spec.initial_state
        for step in steps:
            resp = await self._execute(step)
            result = self._evaluate(step, resp, state)
            results.append(result)
            if result.succeeded:
                state = result.observed_state
            else:
                break  # a failed step stops the machine; later steps are meaningless
        return results, state

    # ---- full assessment -------------------------------------------------
    async def assess(
        self,
        spec: WorkflowSpec,
        *,
        scan: Scan | None = None,
        authorization_ack: bool = False,
        probe_skips: bool = True,
    ) -> WorkflowRunResult:
        if not spec.authorized:
            raise AuthorizationError(
                f"workflow '{spec.name}' is not marked authorized; set 'authorized: true' "
                "in its definition before running it")
        if not authorization_ack:
            raise AuthorizationError(
                "authorization acknowledgement required to execute a workflow")

        problems = spec.validate()
        if problems:
            raise AuthorizationError(
                "workflow definition is invalid; refusing to execute:\n  - "
                + "\n  - ".join(problems))

        result = WorkflowRunResult(spec=spec)
        baseline, final_state = await self.run_sequence(spec, spec.steps)
        result.steps = baseline
        result.final_state = final_state

        if scan is not None:
            for step_result in baseline:
                item = EvidenceItem(
                    test_name="workflow.step",
                    request={"method": step_result.step.method, "url": step_result.step.url},
                    response={"status_code": step_result.observed_status},
                    status_code=step_result.observed_status,
                    excerpt=(f"step '{step_result.step.name}' -> "
                             f"{step_result.outcome.value}: {step_result.detail}"),
                    confidence=Confidence.FIRM.score)
                record = self.evidence.persist(scan.id, item)
                step_result.evidence_ids.append(record.id)

        if probe_skips and result.completed:
            await self._probe_skips(spec, result, scan)

        if scan is not None:
            result.findings = self._create_findings(spec, result, scan)

        self.repo.audit(AuditLog(
            action="workflow_executed", target_ref=spec.name,
            detail={"completed": result.completed, "final_state": result.final_state,
                    "skip_probes": len(result.skip_probes)}))
        log.info("workflow %s completed=%s final_state=%s probes=%d",
                 spec.name, result.completed, result.final_state, len(result.skip_probes))
        return result

    async def _probe_skips(self, spec: WorkflowSpec, result: WorkflowRunResult,
                           scan: Scan | None) -> None:
        """Re-run the sequence omitting each required step in turn."""
        terminal = spec.steps[-1]
        for required in spec.required_steps:
            if required.name == terminal.name:
                continue
            reduced = [s for s in spec.steps if s.name != required.name]
            # Relax from_state chaining for the probe: we are deliberately breaking it.
            probe_steps = [
                StepSpec(**{**s.__dict__, "from_state": ""}) for s in reduced
            ]
            steps, _ = await self.run_sequence(spec, probe_steps)
            terminal_result = next((s for s in steps if s.step.name == terminal.name), None)
            bypassable = terminal_result is not None and terminal_result.succeeded
            result.skip_probes.append({
                "omitted_step": required.name,
                "terminal_step": terminal.name,
                "terminal_reached": bypassable,
                "terminal_status": terminal_result.observed_status if terminal_result else None,
                "detail": ("the terminal step still succeeded without the required step"
                           if bypassable else
                           "the terminal step did not succeed, as expected"),
            })

    # ---- findings --------------------------------------------------------
    def _create_findings(self, spec: WorkflowSpec, result: WorkflowRunResult,
                         scan: Scan) -> list[Finding]:
        findings: list[Finding] = []

        for probe in result.skip_probes:
            if not probe["terminal_reached"]:
                continue
            findings.append(self._finding(
                scan, spec,
                title=(f"Required workflow step '{probe['omitted_step']}' can be skipped "
                       f"before '{probe['terminal_step']}'"),
                description=(
                    f"The workflow '{spec.name}' declares '{probe['omitted_step']}' as a "
                    f"required step. When the sequence was replayed without it, the terminal "
                    f"step '{probe['terminal_step']}' still returned "
                    f"{probe['terminal_status']}. This indicates the business process does "
                    "not enforce its own ordering server-side. It is an INDICATOR: the "
                    "operator's model of the workflow may be incomplete, so a human must "
                    "validate it."),
                severity=Severity.HIGH,
                endpoint=next((s.url for s in spec.steps
                               if s.name == probe["terminal_step"]), ""),
                method=next((s.method for s in spec.steps
                             if s.name == probe["terminal_step"]), "GET"),
                cwe="CWE-841",
                remediation=("Enforce workflow ordering server-side: verify every required "
                             "precondition on the terminal operation rather than relying on "
                             "client-driven sequencing."),
                evidence_ids=[e for s in result.steps for e in s.evidence_ids][:3],
            ))

        for step_result in result.steps:
            if step_result.outcome == WorkflowStepOutcome.UNEXPECTED_STATE:
                findings.append(self._finding(
                    scan, spec,
                    title=f"Unexpected workflow state at step '{step_result.step.name}'",
                    description=(f"{step_result.detail}. The application's state machine "
                                 "diverged from the declared model."),
                    severity=Severity.MEDIUM,
                    endpoint=step_result.step.url,
                    method=step_result.step.method,
                    cwe="CWE-841",
                    remediation="Reconcile the declared workflow with the application's "
                                "actual state transitions, then re-assess.",
                    evidence_ids=step_result.evidence_ids))
        return findings

    def _finding(self, scan: Scan, spec: WorkflowSpec, *, title: str, description: str,
                 severity: Severity, endpoint: str, cwe: str, remediation: str,
                 evidence_ids: list[str], method: str = "GET") -> Finding:
        from ..findings import fingerprint as fp

        finding = Finding(
            scan_id=scan.id,
            engagement_id=scan.engagement_id,
            title=title,
            description=description,
            category="business_logic",
            severity=severity,
            confidence=Confidence.FIRM,
            status=FindingStatus.POTENTIAL,
            endpoint=endpoint,
            # The step's own verb. Hardcoding POST put the wrong method in the report
            # and, because the method is part of the fingerprint, made the finding fail
            # to match itself across scans.
            method=method.upper(),
            evidence_ids=evidence_ids,
            impact="A required control in the business process may not be enforced.",
            remediation=remediation,
            references=["https://cwe.mitre.org/data/definitions/841.html"],
            scanner="workflow.engine",
            cwe_id=cwe,
            owasp_category="A04:2021-Insecure Design",
            validation_state=ValidationState.OBSERVED,
            first_seen_scan_id=scan.id,
        )
        finding.priority_score = compute_priority(PriorityInputs(
            severity=severity, confidence=Confidence.FIRM, exposure=0.7,
            asset_importance=0.7, evidence_quality=0.7, unauthenticated=False)).score
        fp.ensure(finding)
        self.repo.add_finding(finding)
        self.repo.audit(AuditLog(action="finding_created", actor=scan.operator,
                                 target_ref=finding.id,
                                 detail={"source": "workflow.engine",
                                         "workflow": spec.name}))
        return finding

    # ---- persistence -----------------------------------------------------
    def persist(self, spec: WorkflowSpec, result: WorkflowRunResult,
                *, engagement_id: str | None = None,
                target_id: str | None = None) -> Workflow:
        workflow = Workflow(
            engagement_id=engagement_id, target_id=target_id, name=spec.name,
            description=spec.description, initial_state=spec.initial_state,
            authorized=spec.authorized)
        self.repo.add_workflow(workflow)
        for index, step_result in enumerate(result.steps):
            self.repo.add_workflow_step(WorkflowStep(
                workflow_id=workflow.id, order_index=index,
                name=step_result.step.name, method=step_result.step.method,
                url=step_result.step.url, from_state=step_result.step.from_state,
                to_state=step_result.step.to_state,
                expected_status=step_result.step.assert_status_in,
                assertion=step_result.step.assertion,
                assert_status_in=step_result.step.assert_status_in,
                assert_body_contains=step_result.step.assert_body_contains,
                assert_body_absent=step_result.step.assert_body_absent,
                outcome=step_result.outcome,
                observed_status=step_result.observed_status,
                observed_state=step_result.observed_state,
                evidence_ids=step_result.evidence_ids))
        return workflow
