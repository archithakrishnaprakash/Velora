"""Reproducibility packages.

For any finding, produce everything a third party needs to re-run the observation —
and nothing that would leak a secret. A reproduction record captures the tool version,
the detecting check, the scan configuration, a hash of the scope policy that was in
force, the (already-redacted) request/response metadata, and concrete steps.

The scope policy is recorded as a **hash plus a human summary**, not as raw credentials
or a full config dump, so two runs can be proven to have used the same boundary without
publishing it.

Reproduction is scope-controlled: ``build_command`` emits the exact Velora invocation,
which re-applies the ScopePolicy when run. Velora never produces a bare curl command that
would bypass its own controls.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .. import __version__
from ..database.repository import Repository
from ..models.domain import AuditLog, Finding, ReproductionRecord, ScopePolicyRecord
from ..utils.logging import get_logger
from ..utils.redaction import redact_headers, redact_mapping

log = get_logger("reproduce")


def scope_hash(record: ScopePolicyRecord | None) -> str:
    """Stable hash of the scope boundary that was in force."""
    if record is None:
        return "UNKNOWN"
    canonical = json.dumps({
        "allowed_domains": sorted(record.allowed_domains),
        "allowed_ips": sorted(record.allowed_ips),
        "allowed_ports": sorted(record.allowed_ports),
        "allowed_schemes": sorted(record.allowed_schemes),
        "excluded_paths": sorted(record.excluded_paths),
        "excluded_domains": sorted(record.excluded_domains),
        "redirect_policy": record.redirect_policy,
        "allow_private_targets": record.allow_private_targets,
        "max_requests": record.max_requests,
        "max_concurrency": record.max_concurrency,
    }, sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def scope_summary(record: ScopePolicyRecord | None) -> str:
    if record is None:
        return "scope policy not recorded"
    return (f"domains={record.allowed_domains or '-'} ips={record.allowed_ips or '-'} "
            f"ports={record.allowed_ports} schemes={record.allowed_schemes} "
            f"redirects={record.redirect_policy} "
            f"private_allowed={record.allow_private_targets}")


class ReproductionService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def _scope_for(self, finding: Finding) -> ScopePolicyRecord | None:
        scan = self.repo.get_scan(finding.scan_id)
        if scan is None:
            return None
        if scan.scope_policy_id:
            record = self.repo.get_scope(scan.scope_policy_id)
            if record is not None:
                return record
        target = self.repo.get_target(scan.target_id)
        if target and target.scope_policy_id:
            return self.repo.get_scope(target.scope_policy_id)
        return None

    def build_command(self, finding: Finding) -> str:
        """The exact Velora invocation that re-runs this observation, scope-controlled."""
        scan = self.repo.get_scan(finding.scan_id)
        target = self.repo.get_target(scan.target_id) if scan else None
        url = target.url if target else finding.endpoint
        profile = scan.profile.value if scan else "safe"
        scope = self._scope_for(finding)
        private = " --allow-private" if (scope and scope.allow_private_targets) else ""
        return (f"velora scan --target {url} --profile {profile}{private} "
                f"--i-am-authorized")

    def steps(self, finding: Finding) -> list[str]:
        scan = self.repo.get_scan(finding.scan_id)
        evidence = self.repo.list_evidence_for_finding(finding.id)
        steps = [
            f"Install Velora {__version__} (see docs/INSTALLATION.md).",
            f"Confirm you are authorized to test {finding.endpoint}.",
            f"Recreate the scope boundary: {scope_summary(self._scope_for(finding))}",
            f"Run: {self.build_command(finding)}",
            f"Locate the finding produced by check '{finding.scanner}' at "
            f"{finding.method} {finding.endpoint}.",
        ]
        if evidence:
            steps.append(
                "Compare the recorded evidence excerpt(s) against the new run: "
                + "; ".join(e.sanitized_excerpt[:120] for e in evidence[:3]))
        steps.append(
            f"Expected fingerprint: {finding.fingerprint or '(not computed)'} — a matching "
            "fingerprint means the same issue was reproduced.")
        if scan is not None and scan.stats.get("blocked_requests"):
            steps.append(f"Note: {scan.stats['blocked_requests']} request(s) were blocked "
                         "by the scope policy during the original scan.")
        return steps

    def build(self, finding: Finding, *, persist: bool = True) -> ReproductionRecord:
        scan = self.repo.get_scan(finding.scan_id)
        evidence = self.repo.list_evidence_for_finding(finding.id)
        scope = self._scope_for(finding)

        request_meta: dict[str, Any] = {}
        response_meta: dict[str, Any] = {}
        if evidence:
            first = evidence[0]
            # Already redacted at write time; redact again for defence in depth.
            request_meta = redact_mapping(first.request_metadata)
            response_meta = redact_mapping(first.response_metadata)
            response_meta.setdefault("status_code", first.status_code)
            response_meta.setdefault("content_type", first.content_type)
            if first.headers:
                response_meta["headers"] = redact_headers(first.headers)

        record = ReproductionRecord(
            finding_id=finding.id,
            velora_version=__version__,
            scanner_id=finding.scanner,
            scan_id=finding.scan_id,
            scan_profile=scan.profile.value if scan else "unknown",
            scope_policy_hash=scope_hash(scope),
            scope_summary=scope_summary(scope),
            request_metadata=request_meta,
            response_metadata=response_meta,
            evidence_ids=list(finding.evidence_ids),
            validation_state=finding.status.value,
            steps=self.steps(finding),
        )
        if persist:
            self.repo.add_reproduction(record)
            self.repo.audit(AuditLog(action="reproduction_package_created",
                                     target_ref=finding.id,
                                     detail={"scope_policy_hash": record.scope_policy_hash}))
        log.info("reproduction package built for %s (scope %s)",
                 finding.id, record.scope_policy_hash)
        return record

    def to_dict(self, record: ReproductionRecord) -> dict[str, Any]:
        return {
            "finding_id": record.finding_id,
            "velora_version": record.velora_version,
            "scanner": record.scanner_id,
            "scan_id": record.scan_id,
            "scan_profile": record.scan_profile,
            "scope_policy_hash": record.scope_policy_hash,
            "scope_summary": record.scope_summary,
            "request_metadata": record.request_metadata,
            "response_metadata": record.response_metadata,
            "evidence_ids": record.evidence_ids,
            "validation_state": record.validation_state,
            "steps": record.steps,
            "created_at": record.created_at.isoformat(),
            "note": ("This package contains no credentials or secret material. The scope "
                     "policy is identified by hash so two runs can be proven equivalent "
                     "without publishing the boundary."),
        }
