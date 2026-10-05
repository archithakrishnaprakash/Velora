"""Assembles a complete, redacted report context from persisted scan data.

Velora 2.0 makes each finding *explainable*: alongside the raw fields, every finding
carries an ``explanation`` block with a fixed set of sections —

    WHAT WAS OBSERVED / WHY IT MATTERS / EVIDENCE / CONFIDENCE /
    WHAT IS UNKNOWN / VALIDATION REQUIRED / RECOMMENDED REMEDIATION / RETEST STATUS

The "what is unknown" section is the point of the format. A report that only states
what was found invites the reader to treat silence as safety; stating the limits of
each observation next to the observation itself does not.

All 1.x keys are preserved, so existing JSON consumers and the HTML template keep
working; the new material is additive.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..attack_graph.paths import AttackPathAnalyzer
from ..config.settings import Settings
from ..correlation.engine import CorrelationEngine
from ..database.repository import Repository
from ..models.domain import AIAnalysis, Finding, RemediationAction, RetestRun
from ..models.enums import FindingStatus, Severity


def _cvss_block(f: Finding) -> Any:
    """CVSS as recorded, or the explicit string "Not Assessed".

    Velora never substitutes a guessed vector for a missing one, and never lets an
    unscored finding read as a zero.
    """
    if f.cvss_base_score is None:
        return "Not Assessed"
    return {"version": f.cvss_version, "vector": f.cvss_vector,
            "base_score": f.cvss_base_score, "severity": f.cvss_severity}


def _what_is_unknown(f: Finding, evidence: list[dict[str, Any]],
                     analysis: AIAnalysis | None,
                     retests: list[RetestRun]) -> list[str]:
    """State the limits of this observation, in the report, beside the observation."""
    unknown: list[str] = []
    if f.status is not FindingStatus.CONFIRMED:
        unknown.append(
            "Exploitability was not demonstrated. This is an observation produced by a "
            "detector, not a proven attack.")
    if not evidence:
        unknown.append(
            "No evidence records are attached to this finding, so it cannot be "
            "independently reviewed from this report alone.")
    if f.cvss_base_score is None:
        unknown.append(
            "No CVSS vector was derived, so no standardised score is available. The "
            "Velora priority score is a Velora-specific ranking, not CVSS.")
    if f.cwe_id == "UNKNOWN":
        unknown.append("No CWE mapping was claimed for this detector.")
    if f.owasp_category == "UNKNOWN":
        unknown.append("No OWASP Top 10 category was claimed for this detector.")
    if analysis is not None:
        for missing in analysis.missing_evidence:
            unknown.append(f"AI analysis flagged missing evidence: {missing}.")
    if not retests:
        unknown.append("This finding has not been retested.")
    return unknown


def _validation_required(f: Finding, analysis: AIAnalysis | None) -> str:
    if f.status is FindingStatus.CONFIRMED:
        who = f.validated_by or "an operator"
        note = f" Note: {f.validation_note}" if f.validation_note else ""
        return f"Confirmed by {who} on review.{note}"
    if analysis is not None and analysis.recommended_validation:
        return analysis.recommended_validation
    return ("A human reviewer must reproduce the observation and decide whether it is "
            "a real weakness in this application's context.")


def _retest_status(remediation: RemediationAction | None,
                   retests: list[RetestRun]) -> dict[str, Any]:
    if remediation is None and not retests:
        return {"status": "NOT_TRACKED",
                "detail": "No remediation action has been opened for this finding."}
    latest = retests[-1] if retests else None
    status = remediation.status.value if remediation else (
        latest.verdict.value if latest else "OPEN")
    detail = ""
    if latest is not None:
        if latest.still_present is True:
            detail = "The most recent retest still observed the finding."
        elif latest.still_present is False:
            detail = ("The most recent retest did not observe the finding on a covered "
                      "endpoint.")
        else:
            detail = ("The most recent retest was inconclusive; absence of a detection "
                      "is not by itself evidence of a fix.")
        if latest.detail:
            detail = f"{detail} {latest.detail}".strip()
    return {
        "status": status,
        "detail": detail or "Tracked, but no retest has run yet.",
        "verified_at": remediation.verified_at.isoformat()
        if remediation and remediation.verified_at else None,
        "retests": [{"id": r.id, "verdict": r.verdict.value,
                     "still_present": r.still_present,
                     "retest_scan_id": r.retest_scan_id, "detail": r.detail}
                    for r in retests],
    }


def _finding_block(repo: Repository, f: Finding, evidence: list[dict[str, Any]],
                   analysis: AIAnalysis | None) -> dict[str, Any]:
    """One finding, with the explainable sections attached.

    The 1.x keys are unchanged; ``explanation`` is additive.
    """
    remediation = repo.get_remediation_for_finding(f.id)
    retests = repo.list_retests(f.id)
    reproduction = repo.get_reproduction_for_finding(f.id)
    knowledge = repo.list_knowledge_relationships(f.id)

    return {
        "id": f.id, "title": f.title, "category": f.category,
        "severity": f.severity.value, "confidence": f.confidence.value,
        "status": f.status.value, "endpoint": f.endpoint, "method": f.method,
        "priority_score": f.priority_score, "description": f.description,
        "impact": f.impact, "remediation": f.remediation,
        "references": f.references, "scanner": f.scanner,
        "validated_by": f.validated_by, "validation_note": f.validation_note,
        "cvss": _cvss_block(f),
        "evidence": evidence,
        # ---- Velora 2.0 ----
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "validation_state": f.validation_state.value,
        "fingerprint": f.fingerprint,
        "first_seen_scan_id": f.first_seen_scan_id,
        "knowledge_links": [
            {"relation": k.relation, "target_kind": k.target_kind,
             "target_id": k.target_id, "validation_status": k.validation_status.value,
             "confidence": k.confidence}
            for k in knowledge
        ],
        "reproduction": {
            "velora_version": reproduction.velora_version,
            "scanner_id": reproduction.scanner_id,
            "scan_profile": reproduction.scan_profile,
            "scope_policy_hash": reproduction.scope_policy_hash,
            "scope_summary": reproduction.scope_summary,
            "steps": reproduction.steps,
            "note": "The reproduction package contains no credentials or secret material.",
        } if reproduction else None,
        "explanation": {
            "what_was_observed": f.description or (
                f"The {f.scanner or 'detector'} check reported this condition on "
                f"{f.method} {f.endpoint}."),
            "why_it_matters": f.impact or (
                "No impact assessment was recorded for this detector. Severity reflects "
                "the class of issue, not a measured consequence in this application."),
            "evidence": evidence,
            "confidence": {
                "detector_confidence": f.confidence.value,
                "velora_priority_score": f.priority_score,
                "priority_note": "Velora priority is a ranking aid, not CVSS.",
                "cvss": _cvss_block(f),
                "ai_confidence": analysis.confidence if analysis else None,
                "ai_validation_status": analysis.validation_status.value
                if analysis else None,
            },
            "what_is_unknown": _what_is_unknown(f, evidence, analysis, retests),
            "validation_required": _validation_required(f, analysis),
            "recommended_remediation": f.remediation or (
                "No remediation guidance was recorded for this detector."),
            "retest_status": _retest_status(remediation, retests),
        },
    }


def assemble_report(repo: Repository, scan_id: str, settings: Settings) -> dict[str, Any]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"scan not found: {scan_id}")
    target = repo.get_target(scan.target_id)
    findings = repo.list_findings(scan_id)
    evidence = repo.list_evidence(scan_id)
    endpoints = repo.list_endpoints(scan_id)
    technologies = repo.list_technologies(scan_id)
    hosts = repo.list_hosts(scan_id)
    nodes = repo.list_nodes(scan_id)
    edges = repo.list_edges(scan_id)
    events = repo.list_events(scan_id)

    correlations = CorrelationEngine().correlate(findings)

    # ---- Velora 2.0 context -------------------------------------------
    engagement = repo.get_engagement(scan.engagement_id) if scan.engagement_id else None
    scope_record = repo.get_scope(scan.scope_policy_id) if scan.scope_policy_id else None
    analyses = repo.list_ai_analyses(scan_id)
    analysis_by_finding: dict[str, AIAnalysis] = {}
    for a in analyses:
        if a.finding_id:
            analysis_by_finding[a.finding_id] = a   # last one wins: most recent analysis
    regressions = repo.list_regressions(scan_id)
    gate_results = repo.list_gate_results(scan_id)
    postures = [p for p in repo.list_postures() if p.scan_id == scan_id]
    benchmarks = [b for b in repo.list_benchmark_runs() if b.scan_id == scan_id]
    authz_tests = repo.list_authz_tests(scan_id)
    differentials = repo.list_differentials(scan_id)
    identities = repo.list_identities(engagement.id if engagement else None)

    analyzer = AttackPathAnalyzer(nodes, edges)
    graph_paths = analyzer.find_paths()

    by_sev: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity.value] += 1

    findings_sorted = sorted(
        findings, key=lambda f: (-(f.priority_score or 0), -f.severity.rank)
    )
    ev_by_finding: dict[str, list[dict]] = {}
    for e in evidence:
        if e.finding_id:
            ev_by_finding.setdefault(e.finding_id, []).append(
                {
                    "test_name": e.test_name,
                    "status_code": e.status_code,
                    "content_type": e.content_type,
                    "excerpt": e.sanitized_excerpt,
                    "confidence": e.confidence,
                }
            )

    return {
        "meta": {
            "tool": "Velora",
            "tool_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "company_name": settings.reports.company_name,
            "operator": scan.operator,
        },
        "scan": {
            "id": scan.id,
            "profile": scan.profile.value,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "stats": scan.stats,
        },
        "target": {
            "id": target.id if target else "",
            "name": target.name if target else "",
            "url": target.url if target else "",
            "authorization_status": target.authorization_status.value if target else "",
            "owner": target.owner if target else "",
        } if target else {},
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_sev,
            "high_and_critical": [
                {"id": f.id, "title": f.title, "severity": f.severity.value,
                 "priority": f.priority_score}
                for f in findings_sorted
                if f.severity in {Severity.HIGH, Severity.CRITICAL}
            ],
        },
        "attack_surface": {
            "hosts": [{"hostname": h.hostname, "ips": h.ip_addresses} for h in hosts],
            "endpoints": [
                {"url": e.url, "method": e.method, "status": e.status_code,
                 "is_api": e.is_api, "params": e.parameters}
                for e in endpoints
            ],
            "technologies": [
                {"name": t.name, "version": t.version, "confidence": t.confidence,
                 "evidence": t.evidence}
                for t in technologies
            ],
        },
        "findings": [_finding_block(repo, f, ev_by_finding.get(f.id, []),
                                    analysis_by_finding.get(f.id))
                     for f in findings_sorted],
        "attack_path_hypotheses": [
            {"title": c.title, "description": c.description, "path": c.path,
             "finding_ids": c.finding_ids, "hypothesis": True}
            for c in correlations
        ],
        "attack_graph": {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label,
                       "attributes": n.attributes} for n in nodes],
            "edges": [{"source": e.source_id, "target": e.target_id,
                       "relation": e.relation, "hypothesis": e.hypothesis} for e in edges],
        },
        "engagement": {
            "id": engagement.id, "name": engagement.name, "client": engagement.client,
            "status": engagement.status.value, "operator": engagement.operator,
            "authorization_reference": engagement.authorization_reference,
            "authorization_granted_by": engagement.authorization_granted_by,
            "starts_at": engagement.starts_at.isoformat() if engagement.starts_at else None,
            "ends_at": engagement.ends_at.isoformat() if engagement.ends_at else None,
        } if engagement else None,
        "authorization": {
            "target_authorization_status": target.authorization_status.value if target else "",
            "target_authorization_note": target.authorization_note if target else "",
            "operator_acknowledged": scan.authorization_ack,
            "engagement_reference": engagement.authorization_reference if engagement else "",
            "statement": (
                "This assessment was run with an explicit authorization acknowledgement "
                "recorded against the scan." if scan.authorization_ack else
                "WARNING: no authorization acknowledgement is recorded for this scan."),
        },
        "scope": {
            "policy_id": scope_record.id if scope_record else None,
            "allowed_domains": scope_record.allowed_domains if scope_record else [],
            "allowed_ips": scope_record.allowed_ips if scope_record else [],
            "allowed_ports": scope_record.allowed_ports if scope_record else [],
            "allowed_schemes": scope_record.allowed_schemes if scope_record else [],
            "excluded_paths": scope_record.excluded_paths if scope_record else [],
            "max_requests": scope_record.max_requests if scope_record else None,
            "redirect_policy": scope_record.redirect_policy if scope_record else None,
            "allow_private_targets": scope_record.allow_private_targets
            if scope_record else None,
            "note": "Every request in this assessment was checked against this policy "
                    "before it was sent. Blocked requests are recorded in the audit log "
                    "as OUT_OF_SCOPE_REQUEST_BLOCKED.",
        },
        "identities": [
            {"name": i.name, "role": i.role.value, "auth_scheme": i.auth_scheme,
             "secret_reference": i.secret_ref or "(anonymous)",
             "owned_resource_hints": i.owned_resource_hints,
             "note": "Only the name of the environment variable is stored; the "
                     "credential value is never persisted."}
            for i in identities
        ],
        "authorization_tests": [
            {"identity_id": t.identity_id, "role": t.identity_role.value,
             "method": t.method, "url": t.url, "expected": t.expected.value,
             "observed": t.observed.value, "outcome": t.outcome.value,
             "status_code": t.status_code, "is_weakness": t.outcome.is_weakness,
             "notes": t.notes}
            for t in authz_tests
        ],
        "differential_observations": [
            {"label": d.label, "baseline": f"{d.baseline_method} {d.baseline_url}",
             "candidate": f"{d.candidate_method} {d.candidate_url}",
             "classifications": d.classifications, "confidence": d.confidence,
             "interpretation": d.interpretation,
             "validation_required": d.validation_required}
            for d in differentials
        ],
        "ai_analysis": {
            "count": len(analyses),
            "note": ("AI output is an interpretation of stored evidence. It cannot "
                     "confirm a finding, its confidence is capped by the deterministic "
                     "evidence matrix, and every prompt is sanitised against injection "
                     "from scanned page content."),
            "analyses": [
                {"id": a.id, "finding_id": a.finding_id, "provider": a.provider,
                 "model": a.model, "classification": a.classification,
                 "confidence": a.confidence,
                 "validation_status": a.validation_status.value,
                 "reasoning_summary": a.reasoning_summary,
                 "supporting_evidence": a.supporting_evidence,
                 "contradicting_evidence": a.contradicting_evidence,
                 "missing_evidence": a.missing_evidence,
                 "recommended_validation": a.recommended_validation,
                 "human_validation_required": a.human_validation_required,
                 "prompt_sanitized": a.prompt_sanitized}
                for a in analyses
            ],
        },
        "attack_paths": {
            "note": ("A path is a route through observed and inferred relationships. "
                     "Its validation status is that of its weakest link: a path "
                     "containing an INFERRED edge is a lead to investigate, not a "
                     "demonstrated attack."),
            "paths": [dict(p.to_dict(), explanation=analyzer.explain(p))
                      for p in graph_paths],
            "summary": analyzer.summary(),
        },
        "regression": {
            "count": len(regressions),
            "changes": [
                {"change": r.change.value, "subject": r.subject, "severity": r.severity,
                 "previous_scan_id": r.previous_scan_id, "detail": r.detail}
                for r in regressions
            ],
        },
        "posture": [
            {"id": p.id, "overall": p.overall, "categories": p.categories,
             "explanation": p.explanation,
             "methodology_version": p.methodology_version,
             "note": "The Velora Security Posture Score is a Velora-specific metric. "
                     "It is not CVSS and not an industry standard."}
            for p in postures
        ],
        "benchmark": [
            {"id": b.id, "suite": b.suite, "total_cases": b.total_cases,
             "true_positives": b.true_positives, "true_negatives": b.true_negatives,
             "false_positives": b.false_positives, "false_negatives": b.false_negatives,
             "precision": b.precision, "recall": b.recall, "f1": b.f1,
             "false_positive_rate": b.false_positive_rate,
             "false_negative_rate": b.false_negative_rate,
             "detection_coverage": b.detection_coverage,
             "evidence_completeness": b.evidence_completeness,
             "note": "Measured against this suite's ground truth only. Not a detection "
                     "rate for arbitrary web applications."}
            for b in benchmarks
        ],
        "security_gate": [
            {"decision": g.decision.value, "exit_code": g.decision.exit_code,
             "policy": g.policy, "violations": g.violations, "summary": g.summary}
            for g in gate_results
        ],
        "methodology": [
            "Scope validation and authorization check",
            "Passive reconnaissance (headers, DNS, TLS, robots/sitemap, HTTP methods)",
            "Same-origin crawling and attack-surface mapping",
            "Deterministic security checks (evidence-first)",
            "Evidence collection with secret redaction",
            "Risk prioritization (Velora Priority Score)",
            "Finding correlation (attack-path hypotheses)",
            "AI-assisted explanation (advisory only)",
            "Human validation of findings",
        ],
        "limitations": [
            "Automated checks detect indicators; they do not prove exploitability.",
            "Findings in categories such as authorization and input-validation are indicators "
            "that require manual validation.",
            "AI-generated content is advisory and must be validated by a human analyst.",
            "Testing was limited to the authorized scope and configured request budget.",
            "No destructive, exploitative, or evasion techniques were used.",
            "The absence of a finding is not evidence that the target is secure. It means "
            "the checks that ran did not detect anything, within the scope and budget "
            "configured for this scan.",
            "Attack paths marked INFERRED or HYPOTHESIZED are reasoning about observed "
            "relationships, not demonstrated attacks.",
            "A retest that did not cover the affected endpoint cannot verify a fix, and "
            "is not reported as one.",
            "Where a CWE, OWASP category, CVSS vector or CVE could not be established "
            "from the evidence, this report states UNKNOWN or Not Assessed rather than "
            "supplying a value.",
        ],
        "events": [
            {"event": ev.event, "level": ev.level, "message": ev.message,
             "at": ev.created_at.isoformat()}
            for ev in events
        ],
    }
