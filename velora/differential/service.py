"""Persistence and live-capture for differential analysis.

Live capture always goes through the scope-gated ``SafeHTTPClient``, so a differential
comparison can never reach a target the ScopePolicy forbids.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.http import HttpResponse, SafeHTTPClient
from ..database.repository import Repository
from ..evidence.store import EvidenceStore
from ..models.domain import AuditLog, DifferentialObservation
from ..scanners.base import EvidenceItem
from ..utils.errors import ScopeViolation
from ..utils.logging import get_logger
from .engine import DifferentialEngine, DifferentialResult

log = get_logger("differential.service")


@dataclass
class ExchangeSpec:
    """Description of one side of a comparison."""

    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    label: str = ""


class DifferentialService:
    def __init__(self, repo: Repository, engine: DifferentialEngine | None = None) -> None:
        self.repo = repo
        self.engine = engine or DifferentialEngine()
        self.evidence = EvidenceStore(repo)

    # ---- live capture ---------------------------------------------------
    async def capture(self, client: SafeHTTPClient, spec: ExchangeSpec) -> HttpResponse | None:
        """Fetch one side of the comparison. Returns None if scope blocks it."""
        try:
            return await client.request(spec.method, spec.url, headers=spec.headers)
        except ScopeViolation as exc:
            log.security("DIFFERENTIAL_EXCHANGE_BLOCKED url=%s reason=%s", spec.url, exc.reason)
            return None

    async def run(
        self,
        client: SafeHTTPClient,
        baseline: ExchangeSpec,
        candidate: ExchangeSpec,
        *,
        scan_id: str | None = None,
        engagement_id: str | None = None,
        label: str = "",
        persist: bool = True,
    ) -> tuple[DifferentialResult | None, DifferentialObservation | None]:
        """Capture both sides, compare, and (optionally) persist the observation."""
        base_resp = await self.capture(client, baseline)
        cand_resp = await self.capture(client, candidate)
        if base_resp is None or cand_resp is None:
            return None, None
        result = self.engine.compare_responses(base_resp, cand_resp)
        observation = self.persist(result, baseline, candidate,
                                   scan_id=scan_id, engagement_id=engagement_id,
                                   label=label) if persist else None
        return result, observation

    # ---- persistence ----------------------------------------------------
    def persist(
        self,
        result: DifferentialResult,
        baseline: ExchangeSpec,
        candidate: ExchangeSpec,
        *,
        scan_id: str | None = None,
        engagement_id: str | None = None,
        label: str = "",
    ) -> DifferentialObservation:
        observation = DifferentialObservation(
            scan_id=scan_id,
            engagement_id=engagement_id,
            label=label or f"{baseline.label or 'baseline'} vs {candidate.label or 'candidate'}",
            baseline_url=baseline.url,
            candidate_url=candidate.url,
            baseline_method=baseline.method,
            candidate_method=candidate.method,
            baseline_fingerprint=result.baseline.to_dict(),
            candidate_fingerprint=result.candidate.to_dict(),
            differences=[d.to_dict() for d in result.differences],
            classifications=result.classifications,
            confidence=result.confidence,
            interpretation=result.interpretation,
            validation_required=True,
        )
        if scan_id:
            item = EvidenceItem(
                test_name="differential.compare",
                request={"baseline": baseline.url, "candidate": candidate.url,
                         "method": baseline.method},
                response={"baseline_status": result.baseline.status_code,
                          "candidate_status": result.candidate.status_code},
                status_code=result.candidate.status_code,
                excerpt=result.interpretation,
                confidence=result.confidence,
            )
            record = self.evidence.persist(scan_id, item)
            observation.evidence_ids = [record.id]
        self.repo.add_differential(observation)
        self.repo.audit(AuditLog(
            action="differential_observed",
            target_ref=observation.id,
            detail={"classifications": result.classifications,
                    "confidence": result.confidence,
                    "changed": result.changed},
        ))
        return observation
