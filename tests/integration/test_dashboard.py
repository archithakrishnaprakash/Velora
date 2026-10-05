"""Dashboard and JSON API integration tests.

Every page is rendered twice: once against an empty database (to prove the empty
states are real and nothing is fabricated) and once against a database populated with
one row of every kind (to prove the widgets read stored data).
"""
import json
import os
import tempfile
import unittest

from starlette.testclient import TestClient

from velora.api.app import NAV, create_asgi_app
from velora.config import load_settings
from velora.database.repository import Repository
from velora.models.domain import (
    AIAnalysis,
    AssessmentPlan,
    AssessmentPlanStep,
    AttackEdge,
    AttackNode,
    AuditLog,
    AuthorizationTest,
    BenchmarkCase,
    BenchmarkRun,
    DifferentialObservation,
    Endpoint,
    Engagement,
    Evidence,
    Finding,
    Host,
    Identity,
    KnowledgeRelationship,
    RegressionResult,
    RemediationAction,
    ReportRecord,
    ReproductionRecord,
    RetestRun,
    Scan,
    ScopePolicyRecord,
    SecurityGateResult,
    SecurityPostureSnapshot,
    Target,
    Technology,
    Workflow,
    WorkflowStep,
)
from velora.models.enums import (
    AccessExpectation,
    AccessObservation,
    AuthorizationStatus,
    AuthzOutcome,
    EngagementStatus,
    FindingStatus,
    GateDecision,
    IdentityRole,
    PlanStepStatus,
    RegressionChange,
    RemediationStatus,
    ScanStatus,
    Severity,
    ValidationState,
    WorkflowStepOutcome,
)

PAGES = [href for _, links in NAV for href, _ in links]

API_ENDPOINTS = [
    "/api/health", "/api/targets", "/api/scans", "/api/findings", "/api/plugins",
    "/api/engagements", "/api/identities", "/api/differential",
    "/api/authorization-tests", "/api/workflows", "/api/assessment-plans",
    "/api/remediation", "/api/regression", "/api/benchmark", "/api/posture",
    "/api/security-gate", "/api/ai-analyses", "/api/audit",
]


def _client() -> tuple[TestClient, Repository]:
    os.environ["VELORA_DATA_DIR"] = tempfile.mkdtemp()
    settings = load_settings("/nonexistent.yaml")
    app = create_asgi_app(settings)
    return TestClient(app), Repository(app.state.db.conn)


class TestEmptyDashboard(unittest.TestCase):
    """An empty install must render honestly, not with placeholder data."""

    def setUp(self):
        self.client, self.repo = _client()

    def test_every_page_renders(self):
        for href in PAGES:
            with self.subTest(page=href):
                r = self.client.get(href)
                self.assertEqual(r.status_code, 200, href)
                self.assertIn("Velora", r.text)

    def test_every_api_endpoint_responds(self):
        for href in API_ENDPOINTS:
            with self.subTest(endpoint=href):
                r = self.client.get(href)
                self.assertEqual(r.status_code, 200, href)
                json.loads(r.text)

    def test_empty_state_is_explicit_not_fabricated(self):
        text = self.client.get("/").text
        self.assertIn("no posture snapshot", text)
        self.assertIn("no findings recorded", text)
        self.assertIn("at least two scans are needed for a trend", text)
        self.assertNotIn("Benchmark F1</div>\n  <div class=\"kpi\" >", text)

    def test_benchmark_metrics_absent_rather_than_zeroed(self):
        self.assertIn("not assessed", self.client.get("/").text)

    def test_unknown_page_is_404(self):
        self.assertEqual(self.client.get("/does-not-exist").status_code, 404)

    def test_unknown_api_path_is_json_404(self):
        r = self.client.get("/api/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["error"], "not found")

    def test_security_headers_present(self):
        r = self.client.get("/")
        self.assertEqual(r.headers.get("x-frame-options"), "DENY")
        self.assertEqual(r.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(r.headers.get("referrer-policy"), "no-referrer")
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])
        self.assertIn("default-src 'none'", r.headers["content-security-policy"])

    def test_api_health(self):
        body = self.client.get("/api/health").json()
        self.assertEqual(body["status"], "ok")
        self.assertGreater(body["checks"], 0)

    def test_api_plugins(self):
        r = self.client.get("/api/plugins")
        self.assertTrue(any(p["id"] == "tls.configuration" for p in r.json()))

    def test_evidence_endpoint_requires_a_scan(self):
        self.assertEqual(self.client.get("/api/evidence").status_code, 400)

    def test_reproduction_endpoint_requires_a_finding(self):
        self.assertEqual(self.client.get("/api/reproduction").status_code, 400)


class TestPopulatedDashboard(unittest.TestCase):
    """With one row of every kind, each page must render the stored values."""

    @classmethod
    def setUpClass(cls):
        cls.client, r = _client()
        cls.repo = r

        engagement = Engagement(name="Q3 Assessment", client="LabShop",
                                status=EngagementStatus.ACTIVE, operator="alice",
                                authorization_reference="TICKET-42",
                                authorization_granted_by="CISO")
        r.add_engagement(engagement)
        scope = ScopePolicyRecord(allowed_domains=["lab.local"])
        r.add_scope(scope)
        target = Target(name="labshop", url="http://lab.local/", owner="platform",
                        engagement_id=engagement.id, scope_policy_id=scope.id,
                        authorization_status=AuthorizationStatus.LAB_ONLY)
        r.add_target(target)
        baseline = Scan(target_id=target.id, status=ScanStatus.COMPLETED,
                        operator="alice", authorization_ack=True)
        r.add_scan(baseline)
        scan = Scan(target_id=target.id, engagement_id=engagement.id,
                    status=ScanStatus.COMPLETED, operator="alice",
                    authorization_ack=True, baseline_scan_id=baseline.id,
                    stats={"findings": 1})
        r.add_scan(scan)
        cls.scan_id = scan.id
        cls.target_id = target.id

        r.add_host(Host(scan_id=scan.id, hostname="lab.local",
                        ip_addresses=["127.0.0.1"], ports=[80]))
        r.add_endpoint(Endpoint(scan_id=scan.id, url="http://lab.local/products",
                                method="GET", status_code=200, parameters=["id"],
                                is_api=False))
        r.add_technology(Technology(scan_id=scan.id, name="LabShop",
                                    version="1.4.2", categories=["web-server"],
                                    evidence="Server header"))

        finding = Finding(scan_id=scan.id, title="Missing security headers",
                          category="configuration", severity=Severity.MEDIUM,
                          status=FindingStatus.POTENTIAL,
                          endpoint="http://lab.local/", scanner="headers.security_headers",
                          priority_score=52.0, cwe_id="CWE-693",
                          owasp_category="A05:2021", fingerprint="VF-TEST-1",
                          first_seen_scan_id=baseline.id,
                          validation_state=ValidationState.OBSERVED)
        r.add_finding(finding)
        cls.finding_id = finding.id

        evidence = Evidence(scan_id=scan.id, finding_id=finding.id,
                            test_name="security_headers", status_code=200,
                            sanitized_excerpt="x-frame-options: absent")
        r.add_evidence(evidence)

        node_a = AttackNode(scan_id=scan.id, kind="Endpoint", label="/products",
                            validation_status=ValidationState.OBSERVED)
        node_b = AttackNode(scan_id=scan.id, kind="Finding", label=finding.title,
                            ref_id=finding.id, validation_status=ValidationState.OBSERVED)
        r.add_node(node_a)
        r.add_node(node_b)
        r.add_edge(AttackEdge(scan_id=scan.id, source_id=node_a.id, target_id=node_b.id,
                              relation="EXPOSES", hypothesis=True,
                              validation_status=ValidationState.INFERRED,
                              source="attack_graph.builder"))

        r.add_ai_analysis(AIAnalysis(
            scan_id=scan.id, finding_id=finding.id, provider="heuristic",
            model="rules-1", classification="missing control", confidence=0.42,
            reasoning_summary="Headers absent on the observed response.",
            supporting_evidence=[evidence.id], missing_evidence=["browser-context"],
            recommended_validation="Re-request with a browser and inspect headers.",
            validation_status=ValidationState.HYPOTHESIZED))

        identity = Identity(name="user-a", role=IdentityRole.USER_A,
                            engagement_id=engagement.id,
                            secret_ref="VELORA_IDENTITY_USER_A_TOKEN",
                            owned_resource_hints=["/api/orders/1"])
        r.add_identity(identity)
        r.add_authz_test(AuthorizationTest(
            scan_id=scan.id, identity_id=identity.id, identity_role=IdentityRole.USER_A,
            url="http://lab.local/api/orders/2", method="GET",
            expected=AccessExpectation.DENY, observed=AccessObservation.GRANTED,
            outcome=AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS, status_code=200,
            notes="Another user's order was returned."))

        r.add_differential(DifferentialObservation(
            scan_id=scan.id, label="owner vs other user",
            baseline_url="http://lab.local/api/orders/1",
            candidate_url="http://lab.local/api/orders/2",
            differences=[{"classification": "BODY_STRUCTURE_CHANGE", "field": "body"}],
            classifications=["BODY_STRUCTURE_CHANGE"], confidence=0.6,
            interpretation="Response structure differs between identities."))

        workflow = Workflow(name="checkout", target_id=target.id, authorized=True,
                            initial_state="start", description="cart then checkout")
        r.add_workflow(workflow)
        r.add_workflow_step(WorkflowStep(
            workflow_id=workflow.id, order_index=0, name="add-to-cart", method="POST",
            url="http://lab.local/cart/add", from_state="start", to_state="cart",
            assertion="cart must exist before checkout",
            outcome=WorkflowStepOutcome.PASSED, observed_status=200))

        remediation = RemediationAction(finding_id=finding.id, owner="platform",
                                        status=RemediationStatus.READY_FOR_RETEST,
                                        note="Header config change queued.")
        r.add_remediation(remediation)
        r.add_retest(RetestRun(finding_id=finding.id, remediation_id=remediation.id,
                               original_scan_id=baseline.id, retest_scan_id=scan.id,
                               still_present=True, verdict=RemediationStatus.FIX_FAILED,
                               detail="Detection still fires on the same endpoint."))

        r.add_regression(RegressionResult(
            previous_scan_id=baseline.id, current_scan_id=scan.id,
            change=RegressionChange.NEW_FINDING, subject="VF-TEST-1",
            severity="Medium", detail={"title": finding.title}))

        r.add_posture(SecurityPostureSnapshot(
            scan_id=scan.id, target_id=target.id, overall=72.5,
            categories={"transport": 90.0, "headers": 55.0},
            contributors=[{"category": "headers", "impact": -12.0}],
            explanation="Velora Security Posture Score 72.5/100 (Adequate)."))

        case = BenchmarkCase(suite="labshop", name="missing-headers",
                             vulnerability_type="configuration",
                             endpoint_path="/", expected_detection=True,
                             expected_check_id="headers.security_headers")
        r.add_benchmark_case(case)
        r.add_benchmark_run(BenchmarkRun(
            suite="labshop", scan_id=scan.id, target_url="http://lab.local/",
            total_cases=1, true_positives=1, precision=1.0, recall=1.0, f1=1.0,
            detection_coverage=1.0, evidence_completeness=1.0,
            per_case=[{"case_id": case.id, "outcome": "TRUE_POSITIVE", "detected": True,
                       "detail": "matched"}],
            velora_version="2.0.0"))

        plan = AssessmentPlan(target_id=target.id, title="Baseline safe assessment",
                              rationale="Start from passive checks.",
                              generated_by="heuristic")
        r.add_plan(plan)
        r.add_plan_step(AssessmentPlanStep(
            plan_id=plan.id, order_index=0, title="Reconnaissance",
            capability="recon", required_permission="authorized target",
            expected_evidence="DNS and header metadata", risk="low",
            status=PlanStepStatus.PROPOSED, scope_ok=True))

        r.add_knowledge_relationship(KnowledgeRelationship(
            source_kind="FINDING", source_id=finding.id, target_kind="CWE",
            target_id="CWE-693", relation="MAPS_TO",
            validation_status=ValidationState.INFERRED, confidence=0.7))

        r.add_reproduction(ReproductionRecord(
            finding_id=finding.id, velora_version="2.0.0",
            scanner_id="headers.security_headers", scan_id=scan.id,
            scan_profile="safe", scope_policy_hash="abc123",
            scope_summary="domains=lab.local",
            steps=["velora scan --target labshop --profile safe"]))

        r.add_gate_result(SecurityGateResult(
            scan_id=scan.id, decision=GateDecision.FAIL,
            policy={"fail_on": ["medium"]},
            violations=[{"rule": "fail_on", "finding": finding.id}],
            summary="1 finding at or above Medium."))

        r.add_report(ReportRecord(scan_id=scan.id, formats=["html", "json"],
                                  paths={"html": "/tmp/report.html"}, operator="alice"))
        r.audit(AuditLog(action="OUT_OF_SCOPE_REQUEST_BLOCKED", actor="scanner",
                         target_ref="http://evil.example/", detail={"reason": "domain"}))

    def test_every_page_renders_with_data(self):
        for href in PAGES:
            with self.subTest(page=href):
                r = self.client.get(href)
                self.assertEqual(r.status_code, 200, href)

    def test_dashboard_shows_stored_posture(self):
        text = self.client.get("/").text
        self.assertIn("72.5", text)
        self.assertIn("not CVSS", text)

    def test_dashboard_severity_chart_reflects_findings(self):
        self.assertIn("Findings by severity", self.client.get("/").text)

    def test_scan_detail_lists_the_finding(self):
        text = self.client.get(f"/scans/{self.scan_id}").text
        self.assertIn("Missing security headers", text)
        self.assertIn("CI/CD gate", text)

    def test_missing_scan_renders_404(self):
        self.assertEqual(self.client.get("/scans/SCAN-NOPE").status_code, 404)

    def test_finding_detail_shows_evidence_and_ai_caveats(self):
        text = self.client.get(f"/findings/{self.finding_id}").text
        self.assertIn("x-frame-options: absent", text)
        self.assertIn("has not been confirmed by a human reviewer", text)
        self.assertIn("can never", text)
        self.assertIn("CWE-693", text)

    def test_finding_detail_reports_unscored_cvss_honestly(self):
        self.assertIn("Not Assessed", self.client.get(f"/findings/{self.finding_id}").text)

    def test_missing_finding_renders_404(self):
        self.assertEqual(self.client.get("/findings/WEB-NOPE").status_code, 404)

    def test_authorization_page_shows_the_weakness(self):
        text = self.client.get(f"/authorization?scan={self.scan_id}").text
        self.assertIn("HORIZONTAL_AUTHORIZATION_WEAKNESS", text)
        self.assertIn("VELORA_IDENTITY_USER_A_TOKEN", text)

    def test_authorization_page_never_renders_a_credential_value(self):
        text = self.client.get(f"/authorization?scan={self.scan_id}").text
        self.assertNotIn("secret_value", text)
        self.assertIn("never stores or prints it", text)

    def test_attack_graph_flags_unvalidated_edges(self):
        text = self.client.get(f"/attack-graph?scan={self.scan_id}").text
        self.assertIn("INFERRED", text)
        self.assertIn("require manual validation", text)

    def test_benchmark_page_states_suite_scope(self):
        text = self.client.get("/benchmarks").text
        self.assertIn("on this suite only", text)
        self.assertIn("labshop", text)

    def test_regression_page_lists_deltas(self):
        text = self.client.get(f"/regression?scan={self.scan_id}").text
        self.assertIn("NEW_FINDING", text)

    def test_remediation_page_refuses_to_imply_a_fix(self):
        text = self.client.get("/remediation").text
        self.assertIn("never treated as a verified fix", text)
        self.assertIn("READY_FOR_RETEST", text)

    def test_ci_cd_page_documents_the_exit_code_contract(self):
        text = self.client.get("/ci-cd").text
        self.assertIn("FAIL", text)
        self.assertIn("never silently passes", text)

    def test_settings_page_shows_only_the_api_key_variable_name(self):
        text = self.client.get("/settings").text
        self.assertIn("VELORA_AI_API_KEY", text)
        self.assertIn("environment variable name only", text)

    def test_audit_page_shows_blocked_requests(self):
        self.assertIn("OUT_OF_SCOPE_REQUEST_BLOCKED", self.client.get("/audit").text)

    def test_unknown_scan_filter_does_not_silently_show_another_scan(self):
        text = self.client.get("/findings?scan=SCAN-NOPE").text
        self.assertIn("No scan selected", text)
        self.assertNotIn("Missing security headers", text)

    # ---- JSON API ----
    def test_api_endpoints_return_stored_rows(self):
        for href in API_ENDPOINTS:
            with self.subTest(endpoint=href):
                r = self.client.get(href)
                self.assertEqual(r.status_code, 200, href)

    def test_api_findings_filter_by_scan(self):
        rows = self.client.get(f"/api/findings?scan={self.scan_id}").json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["fingerprint"], "VF-TEST-1")

    def test_api_workflows_include_steps(self):
        rows = self.client.get("/api/workflows").json()
        self.assertEqual(rows[0]["steps"][0]["name"], "add-to-cart")

    def test_api_assessment_plans_include_steps(self):
        rows = self.client.get("/api/assessment-plans").json()
        self.assertEqual(rows[0]["steps"][0]["capability"], "recon")

    def test_api_identities_expose_only_a_secret_reference(self):
        rows = self.client.get("/api/identities").json()
        self.assertEqual(rows[0]["secret_ref"], "VELORA_IDENTITY_USER_A_TOKEN")
        self.assertNotIn("secret", json.dumps(rows).replace("secret_ref", ""))

    def test_api_reproduction_by_finding(self):
        body = self.client.get(f"/api/reproduction?finding={self.finding_id}").json()
        self.assertEqual(body["scope_policy_hash"], "abc123")

    def test_api_reproduction_unknown_finding_is_404(self):
        self.assertEqual(
            self.client.get("/api/reproduction?finding=WEB-NOPE").status_code, 404)

    def test_api_sarif_for_scan(self):
        doc = self.client.get(f"/api/scans/{self.scan_id}/sarif").json()
        self.assertEqual(doc["version"], "2.1.0")

    def test_api_sarif_unknown_scan_is_404(self):
        self.assertEqual(
            self.client.get("/api/scans/SCAN-NOPE/sarif").status_code, 404)

    def test_api_graph_returns_nodes_and_edges(self):
        body = self.client.get(f"/api/scans/{self.scan_id}/graph").json()
        self.assertEqual(len(body["nodes"]), 2)
        self.assertEqual(body["edges"][0]["relation"], "EXPOSES")

    def test_api_finding_by_id(self):
        body = self.client.get(f"/api/findings/{self.finding_id}").json()
        self.assertEqual(body["cwe_id"], "CWE-693")

    def test_api_finding_unknown_is_404(self):
        self.assertEqual(self.client.get("/api/findings/WEB-NOPE").status_code, 404)


if __name__ == "__main__":
    unittest.main()
