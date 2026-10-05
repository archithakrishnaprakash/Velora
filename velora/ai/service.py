"""AIService — assembles evidence, invokes providers, and persists analyses.

The pipeline is deliberately ordered so the deterministic work happens first:

    stored artifacts -> EvidenceMatrix (deterministic) -> AnalysisInput
    -> PromptEnvelope (trust boundary) -> provider -> enforce_safety(cap=matrix)
    -> persisted AIAnalysis

The provider can never be more confident than the evidence matrix allows, can never set
a finding's status, and can never mark anything VALIDATED.
"""
from __future__ import annotations

from ..config.settings import AIConfig
from ..database.repository import Repository
from ..models.domain import AIAnalysis, AuditLog, Finding
from ..models.enums import ValidationState
from ..utils.errors import AIProviderError
from ..utils.logging import get_logger
from .base import AIProvider, AnalysisInput
from .evidence_matrix import EvidenceMatrix, EvidenceMatrixBuilder
from .heuristic import HeuristicProvider
from .null import NullProvider

log = get_logger("ai.service")


def build_provider(config: AIConfig) -> AIProvider:
    """Select a provider from config. Falls back to heuristic if a remote one can't init."""
    provider = (config.provider or "heuristic").lower()
    if provider == "null":
        return NullProvider()
    if provider in {"openai", "openai_compatible"}:
        from .openai_compatible import OpenAICompatibleProvider

        key = config.api_key
        if not key:
            log.warning("AI provider '%s' selected but %s is unset; using heuristic provider",
                        provider, config.api_key_env)
            return HeuristicProvider()
        try:
            return OpenAICompatibleProvider(key, model=config.model, base_url=config.base_url,
                                            max_tokens=config.max_tokens,
                                            temperature=config.temperature,
                                            timeout=config.timeout)
        except AIProviderError as exc:
            log.warning("falling back to heuristic provider: %s", exc)
            return HeuristicProvider()
    return HeuristicProvider()


class AIService:
    def __init__(self, repo: Repository, config: AIConfig) -> None:
        self.repo = repo
        self.config = config
        self.provider = build_provider(config)
        self.matrix_builder = EvidenceMatrixBuilder()

    # ---- evidence assembly ----------------------------------------------
    def build_matrix(self, finding: Finding) -> EvidenceMatrix:
        """Compute the deterministic evidence matrix for a finding."""
        evidence = self.repo.list_evidence_for_finding(finding.id)
        differentials = [d for d in self.repo.list_differentials(finding.scan_id)
                         if finding.endpoint in (d.baseline_url, d.candidate_url)]
        authz_tests = [t for t in self.repo.list_authz_tests(finding.scan_id)
                       if t.url == finding.endpoint]
        related = [f for f in self.repo.list_findings(finding.scan_id)
                   if f.id != finding.id and f.category == finding.category]
        return self.matrix_builder.build(
            finding, evidence, differentials=differentials,
            authz_tests=authz_tests, related_findings=related)

    def build_input(self, finding: Finding, matrix: EvidenceMatrix | None = None) -> AnalysisInput:
        """Assemble the full structured input, separating trusted and untrusted data."""
        matrix = matrix or self.build_matrix(finding)
        evidence = self.repo.list_evidence_for_finding(finding.id)
        technologies = [{"name": t.name, "version": t.version, "confidence": t.confidence}
                        for t in self.repo.list_technologies(finding.scan_id)]
        related = [{"id": f.id, "title": f.title, "severity": f.severity.value,
                    "category": f.category}
                   for f in self.repo.list_findings(finding.scan_id)
                   if f.id != finding.id][:8]
        nodes = self.repo.list_nodes(finding.scan_id)
        edges = self.repo.list_edges(finding.scan_id)
        graph_context = {
            "nodes": len(nodes),
            "edges": len(edges),
            "hypothesis_edges": sum(1 for e in edges if e.hypothesis),
            "related_node_labels": [n.label for n in nodes if n.ref_id == finding.id][:5],
        }
        scan = self.repo.get_scan(finding.scan_id)
        target = self.repo.get_target(scan.target_id) if scan else None
        scope_meta = {
            "scan_id": finding.scan_id,
            "profile": scan.profile.value if scan else "unknown",
            "target": target.url if target else "",
            "authorization_status": target.authorization_status.value if target else "UNKNOWN",
        }
        history = [{"status": finding.status.value,
                    "validated_by": finding.validated_by or "",
                    "note": finding.validation_note or ""}]

        data = AnalysisInput(
            target=scope_meta["target"],
            endpoint=finding.endpoint,
            method=finding.method,
            finding_title=finding.title,
            finding_id=finding.id,
            category=finding.category,
            severity=finding.severity.value,
            scanner_confidence=finding.confidence.value,
            description=finding.description,
            evidence_excerpts=[e.sanitized_excerpt for e in evidence if e.sanitized_excerpt],
            status_code=next((e.status_code for e in evidence if e.status_code), None),
            headers={},
            evidence_matrix=matrix.to_dict(),
            differential_observations=[
                {"id": d.id, "classifications": d.classifications, "confidence": d.confidence}
                for d in self.repo.list_differentials(finding.scan_id)
                if finding.endpoint in (d.baseline_url, d.candidate_url)
            ],
            authorization_tests=[
                {"role": t.identity_role.value, "expected": t.expected.value,
                 "observed": t.observed.value, "outcome": t.outcome.value}
                for t in self.repo.list_authz_tests(finding.scan_id) if t.url == finding.endpoint
            ],
            technologies=technologies,
            related_findings=related,
            attack_graph_context=graph_context,
            scope_metadata=scope_meta,
            validation_history=history,
        )
        # Target-derived text is carried separately and treated as hostile.
        for row in evidence[:4]:
            if row.sanitized_excerpt:
                data.untrusted_content.append(
                    (f"evidence:{row.test_name}", row.sanitized_excerpt))
        return data

    # ---- analysis --------------------------------------------------------
    def analyze_finding(self, finding: Finding) -> AIAnalysis:
        matrix = self.build_matrix(finding)
        data = self.build_input(finding, matrix)
        try:
            result = self.provider.analyze(data)
        except AIProviderError as exc:
            log.error("AI analysis failed for %s (%s); using heuristic provider",
                      finding.id, type(exc).__name__)
            result = HeuristicProvider().analyze(data)

        analysis = AIAnalysis(
            scan_id=finding.scan_id,
            finding_id=finding.id,
            provider=result.provider,
            model=result.model,
            classification=result.classification,
            confidence=result.confidence,
            reasoning_summary=result.reasoning_summary,
            impact=result.impact,
            remediation=result.remediation,
            related_findings=result.related_findings,
            human_validation_required=True,          # enforced
            ai_generated=True,
            supporting_evidence=result.supporting_evidence,
            contradicting_evidence=result.contradicting_evidence,
            missing_evidence=result.missing_evidence,
            recommended_validation=result.recommended_validation,
            evidence_matrix=result.evidence_matrix,
            validation_status=(result.validation_state
                               if result.validation_state != ValidationState.VALIDATED
                               else ValidationState.HYPOTHESIZED),
            prompt_sanitized=result.prompt_sanitized,
            raw=result.raw,
        )
        self.repo.add_ai_analysis(analysis)
        # Link the analysis WITHOUT changing the finding's status (AI cannot confirm).
        finding.ai_analysis_id = analysis.id
        self.repo.update_finding(finding)
        self.repo.audit(AuditLog(
            action="ai_analysis_created", target_ref=finding.id,
            detail={"provider": result.provider, "model": result.model,
                    "confidence": result.confidence,
                    "validation_state": analysis.validation_status.value,
                    "injection_detected": result.injection_detected},
        ))
        if result.injection_detected:
            log.security("AI_PROMPT_INJECTION_DETECTED finding=%s provider=%s",
                         finding.id, result.provider)
        return analysis

    # ---- summaries -------------------------------------------------------
    def summarize_scan(self, scan_id: str) -> str:
        findings = self.repo.list_findings(scan_id)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return self.provider.summarize({"total": len(findings), "by_severity": by_sev})

    def generate_executive_summary(self, scan_id: str) -> str:
        findings = self.repo.list_findings(scan_id)
        highs = [f for f in findings if f.severity.value in {"High", "Critical"}]
        base = self.summarize_scan(scan_id)
        if highs:
            top = "; ".join(sorted({f.title for f in highs}))
            base += f" Priority items requiring attention: {top}."
        base += (" All items are evidence-backed indicators; confirmation and business-impact"
                 " assessment require human review.")
        return base

    def generate_remediation(self, finding: Finding) -> str:
        if finding.remediation:
            return finding.remediation
        return self.analyze_finding(finding).remediation

    def correlate_findings(self, scan_id: str) -> list[dict[str, object]]:
        """Deterministic correlation, surfaced through the AI service for convenience."""
        from ..correlation.engine import CorrelationEngine

        correlations = CorrelationEngine().correlate(self.repo.list_findings(scan_id))
        return [{"title": c.title, "path": c.path, "finding_ids": c.finding_ids,
                 "hypothesis": True, "description": c.description} for c in correlations]
