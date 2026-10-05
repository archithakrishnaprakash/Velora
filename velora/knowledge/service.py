"""Knowledge-graph materialization and finding enrichment.

Connects findings to standard identifiers and stores those links as first-class graph
edges carrying their epistemic status:

    Finding --MAPS_TO--> CWE --CATEGORIZED_AS--> OWASP
    Finding --AFFECTS--> Technology
    Finding --REMEDIATED_BY--> Remediation

A mapping asserted from a curated catalog is ``INFERRED`` (Velora is confident about the
weakness *class* it detected, not about a specific published vulnerability). Nothing here
fabricates CVE or CPE identifiers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..database.repository import Repository
from ..models.domain import Finding, KnowledgeEntity, KnowledgeRelationship
from ..models.enums import ValidationState
from ..utils.logging import get_logger
from .catalog import (
    AUTHZ_OUTCOME_MAPPINGS,
    UNKNOWN,
    Mapping,
    cwe_entry,
    mapping_for_check,
    owasp_entry,
    references_for,
)
from .cvss import CVSSAssessment, assess

log = get_logger("knowledge")


@dataclass
class EnrichmentResult:
    findings_enriched: int = 0
    entities_created: int = 0
    relationships_created: int = 0
    unmapped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings_enriched": self.findings_enriched,
            "entities_created": self.entities_created,
            "relationships_created": self.relationships_created,
            "unmapped_findings": self.unmapped,
        }


class KnowledgeService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # ---- entity management ----------------------------------------------
    def _ensure_entity(self, kind: str, identifier: str, title: str,
                       references: list[str] | None = None) -> KnowledgeEntity | None:
        if not identifier or identifier == UNKNOWN:
            return None
        existing = self.repo.get_knowledge_entity_by_identifier(identifier)
        if existing is not None:
            return existing
        entity = KnowledgeEntity(kind=kind, identifier=identifier, title=title,
                                 references=references or [])
        self.repo.add_knowledge_entity(entity)
        return entity

    def _link(self, source_id: str, target: KnowledgeEntity, relation: str,
              state: ValidationState, confidence: float,
              source_kind: str = "FINDING") -> KnowledgeRelationship:
        rel = KnowledgeRelationship(
            source_kind=source_kind, source_id=source_id,
            target_kind=target.kind, target_id=target.identifier,
            relation=relation, validation_status=state, confidence=confidence)
        self.repo.add_knowledge_relationship(rel)
        return rel

    # ---- mapping ---------------------------------------------------------
    def mapping_for_finding(self, finding: Finding) -> Mapping:
        """Resolve the best curated mapping for a finding.

        Authorization-matrix findings are mapped by outcome class (already set on the
        finding by the authz service); everything else maps by the detecting check id.
        """
        if finding.cwe_id and finding.cwe_id != UNKNOWN:
            # Already mapped by the producing service — trust it.
            return Mapping(cwe_id=finding.cwe_id, owasp=finding.owasp_category)
        if finding.scanner == "authz.matrix":
            for outcome, mapping in AUTHZ_OUTCOME_MAPPINGS.items():
                if outcome.lower().replace("_", " ") in finding.title.lower():
                    return mapping
        return mapping_for_check(finding.scanner)

    def enrich_finding(self, finding: Finding, *, persist: bool = True) -> Mapping:
        """Attach CWE/OWASP metadata and references to a finding."""
        mapping = self.mapping_for_finding(finding)
        changed = False
        if mapping.cwe_id != UNKNOWN and finding.cwe_id != mapping.cwe_id:
            finding.cwe_id = mapping.cwe_id
            changed = True
        if mapping.owasp != UNKNOWN:
            entry = owasp_entry(mapping.owasp)
            label = f"{mapping.owasp}-{entry.title}" if entry else mapping.owasp
            if finding.owasp_category != label:
                finding.owasp_category = label
                changed = True
        for ref in references_for(mapping.cwe_id, mapping.owasp):
            if ref not in finding.references:
                finding.references.append(ref)
                changed = True
        if changed and persist:
            self.repo.update_finding(finding)
        return mapping

    # ---- CVSS ------------------------------------------------------------
    def set_cvss(self, finding: Finding, vector: str | None, *,
                 source: str = "manual") -> CVSSAssessment:
        """Attach a CVSS assessment from a vector. Never invents a score."""
        assessment = assess(vector, source=source)
        if assessment.assessed:
            finding.cvss_version = assessment.version
            finding.cvss_vector = assessment.vector
            finding.cvss_base_score = assessment.base_score
            finding.cvss_severity = assessment.severity
        else:
            finding.cvss_version = None
            finding.cvss_vector = None
            finding.cvss_base_score = None
            finding.cvss_severity = None
        self.repo.update_finding(finding)
        return assessment

    # ---- graph materialization -------------------------------------------
    def build_for_scan(self, scan_id: str) -> EnrichmentResult:
        """Enrich every finding in a scan and materialize the knowledge graph."""
        result = EnrichmentResult()
        seen_entities: set[str] = {e.identifier for e in self.repo.list_knowledge_entities()}

        for finding in self.repo.list_findings(scan_id):
            mapping = self.enrich_finding(finding)
            if mapping.cwe_id == UNKNOWN and mapping.owasp == UNKNOWN:
                result.unmapped.append(finding.id)
                continue
            result.findings_enriched += 1

            cwe = cwe_entry(mapping.cwe_id)
            if cwe is not None:
                entity = self._ensure_entity("CWE", cwe.cwe_id, cwe.title, [cwe.reference])
                if entity and entity.identifier not in seen_entities:
                    seen_entities.add(entity.identifier)
                    result.entities_created += 1
                if entity:
                    self._link(finding.id, entity, "MAPS_TO", ValidationState.INFERRED, 0.8)
                    result.relationships_created += 1

            owasp = owasp_entry(mapping.owasp)
            if owasp is not None:
                entity = self._ensure_entity("OWASP", owasp.category, owasp.title,
                                             [owasp.reference])
                if entity and entity.identifier not in seen_entities:
                    seen_entities.add(entity.identifier)
                    result.entities_created += 1
                if entity:
                    self._link(finding.id, entity, "CATEGORIZED_AS",
                               ValidationState.INFERRED, 0.8)
                    result.relationships_created += 1

            if finding.remediation:
                entity = self._ensure_entity(
                    "REMEDIATION", f"REM::{finding.id}", finding.remediation[:120])
                if entity:
                    seen_entities.add(entity.identifier)
                    result.entities_created += 1
                    self._link(finding.id, entity, "REMEDIATED_BY",
                               ValidationState.INFERRED, 0.7)
                    result.relationships_created += 1

        # Technologies observed on the target become entities too.
        for tech in self.repo.list_technologies(scan_id):
            identifier = f"TECH::{tech.name}{(':' + tech.version) if tech.version else ''}"
            entity = self._ensure_entity("TECHNOLOGY", identifier,
                                         f"{tech.name} {tech.version or ''}".strip())
            if entity and entity.identifier not in seen_entities:
                seen_entities.add(entity.identifier)
                result.entities_created += 1

        log.info("knowledge graph materialized for scan=%s: %s", scan_id, result.to_dict())
        return result

    # ---- querying --------------------------------------------------------
    def context_for_finding(self, finding: Finding) -> dict[str, Any]:
        """Standards context for one finding, with explicit UNKNOWNs."""
        mapping = self.mapping_for_finding(finding)
        cwe = cwe_entry(mapping.cwe_id)
        owasp = owasp_entry(mapping.owasp)
        cvss = (assess(finding.cvss_vector, source="stored")
                if finding.cvss_vector else CVSSAssessment())
        return {
            "finding_id": finding.id,
            "cwe": {"id": mapping.cwe_id,
                    "title": cwe.title if cwe else UNKNOWN,
                    "reference": cwe.reference if cwe else None},
            "owasp": {"category": mapping.owasp,
                      "title": owasp.title if owasp else UNKNOWN,
                      "reference": owasp.reference if owasp else None},
            "alternate_cwes": list(mapping.alternates),
            "cve": UNKNOWN,   # never synthesized
            "cpe": UNKNOWN,   # never synthesized
            "cvss": cvss.to_dict(),
            "note": mapping.note,
        }
