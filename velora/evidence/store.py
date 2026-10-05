"""Evidence store.

Persists ``EvidenceItem`` objects produced by checks as ``Evidence`` records. Redaction
is applied again here defensively, so nothing sensitive is written even if a check forgot
to redact. Evidence is immutable once written.
"""
from __future__ import annotations

from ..database.repository import Repository
from ..models.domain import Evidence
from ..scanners.base import EvidenceItem
from ..utils.redaction import redact_headers, redact_mapping, redact_text


class EvidenceStore:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def persist(self, scan_id: str, item: EvidenceItem, finding_id: str | None = None) -> Evidence:
        record = Evidence(
            scan_id=scan_id,
            finding_id=finding_id,
            test_name=item.test_name,
            request_metadata=redact_mapping(item.request),
            response_metadata=redact_mapping(item.response),
            headers=redact_headers(item.headers),
            status_code=item.status_code,
            content_type=item.content_type,
            response_size=item.response_size,
            sanitized_excerpt=redact_text(item.excerpt),
            confidence=item.confidence,
        )
        self.repo.add_evidence(record)
        return record
