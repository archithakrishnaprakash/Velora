import os
import tempfile
import unittest

from velora.config import load_settings
from velora.database import Database
from velora.database.repository import Repository
from velora.models.domain import Target
from velora.models.enums import AuthorizationStatus, PlanStepStatus
from velora.planning import AIPlanner, HeuristicPlanner, PlanService
from velora.planning import capabilities as caps
from velora.scope import ScopeManager, ScopePolicy
from velora.workflow.spec import StepSpec, WorkflowSpec


def step(name, url="http://lab.local/x", method="POST", frm="", to="s2", required=False,
         assertion="must hold"):
    return StepSpec(name=name, url=url, method=method, from_state=frm, to_state=to,
                    required=required, assertion=assertion)


class TestWorkflowSpec(unittest.TestCase):
    def test_valid_spec_has_no_problems(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", frm="s1", to="s2"),
                                   step("b", frm="s2", to="s3")])
        self.assertEqual(spec.validate(), [])

    def test_destructive_verbs_are_refused(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", method="DELETE", frm="s1")])
        problems = spec.validate()
        self.assertTrue(any("refuses to execute" in p for p in problems))

    def test_broken_state_chain_is_detected(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", frm="s1", to="s2"),
                                   step("b", frm="WRONG", to="s3")])
        self.assertTrue(any("expects from_state" in p for p in spec.validate()))

    def test_missing_assertion_is_a_problem(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", frm="s1", assertion="")])
        self.assertTrue(any("no security assertion" in p for p in spec.validate()))

    def test_duplicate_step_names_detected(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", frm="s1", to="s2"),
                                   step("a", frm="s2", to="s3")])
        self.assertTrue(any("duplicate step name" in p for p in spec.validate()))

    def test_non_http_url_rejected(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", url="file:///etc/passwd", frm="s1")])
        self.assertTrue(any("non-http(s) url" in p for p in spec.validate()))

    def test_required_steps_and_terminal_state(self):
        spec = WorkflowSpec(name="w", initial_state="s1",
                            steps=[step("a", frm="s1", to="s2", required=True),
                                   step("b", frm="s2", to="done")])
        self.assertEqual([s.name for s in spec.required_steps], ["a"])
        self.assertEqual(spec.terminal_state, "done")


class TestCapabilityCatalog(unittest.TestCase):
    def test_catalog_entries_are_complete(self):
        for key, capability in caps.CAPABILITIES.items():
            self.assertEqual(capability.key, key)
            self.assertTrue(capability.required_permission)
            self.assertTrue(capability.expected_evidence)
            self.assertIn(capability.risk, {"low", "medium", "lab-only"})
            self.assertTrue(capability.cli.startswith("velora "))

    def test_unknown_key_returns_none(self):
        self.assertIsNone(caps.get("rm -rf /"))

    def test_safe_profile_excludes_active_capabilities(self):
        safe = {c.key for c in caps.allowed_for_profile("safe")}
        self.assertNotIn("scan.standard", safe)
        self.assertIn("scan.safe", safe)


class _RogueProvider:
    """A provider that tries to smuggle actions outside the catalog."""

    name = "rogue"

    def analyze(self, data):
        from velora.ai.base import AnalysisResult
        return AnalysisResult(
            classification="plan", confidence=0.9,
            reasoning_summary="use recon then do bad things",
            impact="", remediation="",
            raw={"capabilities": ["recon", "exec:rm -rf /", "scan.safe",
                                  "http://evil.com/exfil"]},
            provider=self.name, model="rogue-1")

    def summarize(self, s):
        return ""


class TestPlanner(unittest.TestCase):
    def setUp(self):
        os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
        self.settings = load_settings("/nonexistent.yaml")
        self.db = Database(self.settings)
        self.db.init()
        self.repo = Repository(self.db.conn)
        self.target = Target(name="t", url="http://lab.local/",
                             authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(self.target)
        self.scope = ScopeManager(
            ScopePolicy(allowed_domains=["lab.local"], allow_private_targets=True),
            resolver=lambda h: ["93.184.216.34"] if h == "lab.local" else [])
        self.service = PlanService(self.repo)

    def tearDown(self):
        self.db.close()

    def test_heuristic_plan_only_uses_catalog_keys(self):
        draft = HeuristicPlanner().plan(self.target, self.service.context_for(self.target))
        self.assertTrue(draft.steps)
        for planned in draft.steps:
            self.assertIn(planned.capability, caps.CAPABILITIES)

    def test_rogue_provider_output_is_filtered_to_the_catalog(self):
        draft = AIPlanner(_RogueProvider()).plan(
            self.target, self.service.context_for(self.target))
        keys = [s.capability for s in draft.steps]
        self.assertEqual(keys, ["recon", "scan.safe"])
        discarded = {d["capability"] for d in draft.discarded}
        self.assertIn("exec:rm -rf /", discarded)
        self.assertIn("http://evil.com/exfil", discarded)

    def test_steps_start_as_proposed(self):
        _, steps = self.service.generate(self.target, planner=HeuristicPlanner(),
                                         scope=self.scope)
        self.assertTrue(all(s.status == PlanStepStatus.PROPOSED for s in steps))

    def test_every_step_records_permission_evidence_and_risk(self):
        _, steps = self.service.generate(self.target, planner=HeuristicPlanner(),
                                         scope=self.scope)
        for step_row in steps:
            self.assertTrue(step_row.required_permission)
            self.assertTrue(step_row.expected_evidence)
            self.assertTrue(step_row.risk)
            self.assertIn("human approval required", step_row.validation_requirement)

    def test_approval_marks_steps_approved(self):
        plan, _ = self.service.generate(self.target, planner=HeuristicPlanner(),
                                        scope=self.scope)
        approved = self.service.approve(plan.id, "operator")
        self.assertTrue(approved)
        self.assertTrue(all(s.status == PlanStepStatus.APPROVED for s in approved))

    def test_out_of_scope_step_can_never_be_approved(self):
        hostile = Target(name="evil", url="http://evil.com/",
                         authorization_status=AuthorizationStatus.LAB_ONLY)
        self.repo.add_target(hostile)
        plan, _ = self.service.generate(hostile, planner=HeuristicPlanner(),
                                        scope=self.scope)
        approved = self.service.approve(plan.id, "operator")
        self.assertEqual(approved, [])
        statuses = {s.status for s in self.repo.list_plan_steps(plan.id)}
        self.assertEqual(statuses, {PlanStepStatus.REJECTED})

    def test_scope_is_rechecked_at_execution_time(self):
        plan, _ = self.service.generate(self.target, planner=HeuristicPlanner(),
                                        scope=self.scope)
        self.service.approve(plan.id, "operator")
        # Scope narrows after approval: nothing may run.
        narrowed = ScopeManager(ScopePolicy(allowed_domains=["other.local"]),
                                resolver=lambda h: [])
        runnable, blocked = self.service.executable_steps(plan.id, narrowed)
        self.assertEqual(runnable, [])
        self.assertTrue(blocked)

    def test_unapproved_steps_are_not_runnable(self):
        plan, _ = self.service.generate(self.target, planner=HeuristicPlanner(),
                                        scope=self.scope)
        runnable, blocked = self.service.executable_steps(plan.id, self.scope)
        self.assertEqual(runnable, [])
        self.assertTrue(all("not APPROVED" in b for b in blocked))


if __name__ == "__main__":
    unittest.main()
