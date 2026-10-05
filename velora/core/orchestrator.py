"""Scan orchestrator — the end-to-end authorized-assessment pipeline.

    Target -> Authorization check -> Scope -> Recon -> Crawl -> Scanners -> Evidence
    -> Findings (Potential) -> Correlation (Hypotheses) -> Attack graph -> Report-ready.

Authorization is enforced up front: a target that is not scannable, or a scan without an
explicit authorization acknowledgement, is refused before any request is sent.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..config.settings import Settings
from ..correlation.engine import CorrelationEngine
from ..crawler import Crawler
from ..attack_graph.builder import AttackGraphBuilder
from ..database.db import Database
from ..database.repository import Repository
from ..findings.service import FindingService
from ..fingerprint import FingerprintEngine
from ..models.domain import AuditLog, Endpoint, Host, Scan, ScanEvent, Target, Technology
from ..models.enums import ScanProfile, ScanStatus
from ..knowledge.service import KnowledgeService
from ..reconnaissance import ReconEngine
from ..scanners import ScanContext, ScanRunner
from ..scope.manager import ScopeManager
from ..core.http import SafeHTTPClient
from ..core.scope_factory import default_policy_for_target, policy_from_record
from ..utils.errors import AuthorizationError
from ..utils.logging import get_logger

log = get_logger("orchestrator")


class ScanOrchestrator:
    def __init__(self, settings: Settings, db: Database) -> None:
        self.settings = settings
        self.db = db
        self.repo = Repository(db.conn)

    def _resolve_scope(self, target: Target):
        if target.scope_policy_id:
            record = self.repo.get_scope(target.scope_policy_id)
            if record is not None:
                return policy_from_record(record)
        return default_policy_for_target(target, self.settings)

    def _event(self, scan_id: str, event: str, message: str = "", level: str = "INFO", **data):
        self.repo.add_event(ScanEvent(scan_id=scan_id, level=level, event=event,
                                      message=message, data=data))

    async def run_scan(
        self,
        target: Target,
        *,
        profile: ScanProfile = ScanProfile.SAFE,
        operator: str = "",
        authorization_ack: bool = False,
    ) -> Scan:
        # ---- authorization gate ----
        if not target.authorization_status.scannable:
            raise AuthorizationError(
                f"target {target.id} is {target.authorization_status.value}; "
                "mark it AUTHORIZED or LAB_ONLY before scanning."
            )
        if not authorization_ack:
            raise AuthorizationError(
                "authorization acknowledgement required: pass --i-am-authorized (CLI) "
                "or authorization_ack=true (API) to confirm you are permitted to test this target."
            )

        policy = self._resolve_scope(target)
        scan = Scan(target_id=target.id, profile=profile, status=ScanStatus.RUNNING,
                    operator=operator, authorization_ack=True,
                    started_at=datetime.now(timezone.utc))
        self.repo.add_scan(scan)
        self.repo.audit(AuditLog(action="scan_started", actor=operator, target_ref=scan.id,
                                 detail={"target": target.url, "profile": profile.value,
                                         "scope": policy.summary()}))
        self._event(scan.id, "SCAN_STARTED", f"target={target.url} profile={profile.value}")
        log.info("SCAN_STARTED scan=%s target=%s profile=%s", scan.id, target.url, profile.value)

        scope = ScopeManager(policy, scan_id=scan.id)
        stats: dict = {}
        try:
            async with SafeHTTPClient(
                scope,
                user_agent=self.settings.scanner.user_agent,
                timeout=policy.timeout,
                verify_tls=self.settings.scanner.verify_tls,
                request_delay=policy.request_delay,
            ) as client:
                fp = FingerprintEngine()

                # Recon
                recon = await ReconEngine(client, fp).run(target.url)
                self._persist_recon(scan.id, target.url, recon)
                self._event(scan.id, "RECON_COMPLETED",
                            f"methods={recon.allowed_methods} techs={len(recon.technologies)}")

                # Crawl
                crawler = Crawler(client, max_depth=self.settings.scanner.max_crawl_depth,
                                  max_pages=self.settings.scanner.max_crawl_pages)
                crawl = await crawler.crawl(target.url)
                self._persist_endpoints(scan.id, crawl)
                self._event(scan.id, "CRAWL_COMPLETED",
                            f"pages={crawl.pages_fetched} endpoints={len(crawl.endpoints)} "
                            f"blocked={crawl.blocked}")

                # Scanners
                ctx = ScanContext(target=target.url, client=client, scope=scope,
                                  recon=recon, crawl=crawl, profile=profile.value)
                outcome = await ScanRunner(profile=profile.value).run(ctx)
                self._event(scan.id, "SCAN_CHECKS_COMPLETED",
                            f"checks={len(outcome.checks_run)} failed={len(outcome.checks_failed)}")

                # Findings
                service = FindingService(self.repo)
                findings = [service.record(scan, out, target) for out in outcome.outputs]
                for f in findings:
                    self._event(scan.id, "POTENTIAL_FINDING",
                                f"{f.severity.value}: {f.title}", level="WARNING")

                # Standards enrichment (CWE / OWASP), then correlation + attack graph.
                knowledge = KnowledgeService(self.repo)
                enrichment = knowledge.build_for_scan(scan.id)
                findings = self.repo.list_findings(scan.id)
                self._event(scan.id, "KNOWLEDGE_ENRICHED",
                            f"enriched={enrichment.findings_enriched} "
                            f"entities={enrichment.entities_created}")

                # Correlation + attack graph
                correlations = CorrelationEngine().correlate(findings)
                builder = AttackGraphBuilder(self.repo)
                nodes, edges = builder.build(
                    scan.id, target.url,
                    self.repo.list_endpoints(scan.id),
                    self.repo.list_technologies(scan.id),
                    findings, correlations,
                    hosts=self.repo.list_hosts(scan.id),
                    identities=self.repo.list_identities(target.engagement_id)
                    if target.engagement_id else [],
                    authz_tests=self.repo.list_authz_tests(scan.id),
                )
                builder.persist(nodes, edges)

                stats = {
                    "requests": scope.request_count,
                    "blocked_requests": scope.blocked_count,
                    "endpoints": len(crawl.endpoints),
                    "technologies": len(recon.technologies),
                    "findings": len(findings),
                    "correlations": len(correlations),
                    "knowledge_entities": enrichment.entities_created,
                    "findings_enriched": enrichment.findings_enriched,
                    "checks_run": len(outcome.checks_run),
                    "checks_failed": outcome.checks_failed,
                }
            scan.status = ScanStatus.COMPLETED
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.FAILED
            stats["error"] = str(exc)
            self._event(scan.id, "SCAN_FAILED", str(exc), level="ERROR")
            log.error("SCAN_FAILED scan=%s error=%s", scan.id, exc)
        finally:
            scan.finished_at = datetime.now(timezone.utc)
            scan.stats = stats
            self.repo.update_scan(scan)
            self.repo.audit(AuditLog(action="scan_finished", actor=operator, target_ref=scan.id,
                                     detail={"status": scan.status.value, **stats}))
            self._event(scan.id, "SCAN_COMPLETED", f"status={scan.status.value}")
            log.info("SCAN_COMPLETED scan=%s status=%s stats=%s", scan.id, scan.status.value, stats)
        return scan

    # ---- persistence helpers -------------------------------------------
    def _persist_recon(self, scan_id: str, target: str, recon) -> None:
        from urllib.parse import urlsplit
        host = urlsplit(target).hostname or target
        ips = (recon.dns.get("A", []) + recon.dns.get("AAAA", [])) if recon.dns else []
        self.repo.add_host(Host(scan_id=scan_id, hostname=host, ip_addresses=ips))
        for tech in recon.technologies:
            self.repo.add_technology(Technology(scan_id=scan_id, name=tech.name,
                                                version=tech.version, categories=tech.categories,
                                                evidence=tech.evidence, confidence=tech.confidence))

    def _persist_endpoints(self, scan_id: str, crawl) -> None:
        for ep in crawl.endpoints:
            self.repo.add_endpoint(Endpoint(scan_id=scan_id, url=ep.url, method=ep.method,
                                            status_code=ep.status_code,
                                            content_type=ep.content_type,
                                            response_size=ep.response_size,
                                            parent_url=ep.parent_url, parameters=ep.parameters,
                                            forms=ep.forms, is_api=ep.is_api))
