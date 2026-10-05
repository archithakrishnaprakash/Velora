"""Attack-surface graph construction (Velora 2.0).

Every node and edge carries its epistemic status, confidence, the evidence that supports
it, and which component asserted it. That is what lets the graph distinguish a *fact*
(an endpoint that returned 200) from a *hypothesis* (a correlated attack path).

Node kinds emitted by this builder:
    Application, Host, Port, Technology, Endpoint, Parameter, Identity, Finding,
    Impact, Remediation, Path

Edge relations emitted by this builder:
    HOSTS, CONTAINS, USES, AFFECTS, EXPOSES, CAN_ACCESS, LEADS_TO, MITIGATED_BY

``REL_REQUIRES`` and ``REL_DEPENDS_ON`` are part of the vocabulary but nothing emits
them yet; they are kept so a plugin or a later builder can use the same names rather
than inventing parallel ones. ``AttackNode.kind`` is a free-form string, so this list
is the builder's contract, not an enforced schema.

The 1.x ``hypothesis`` boolean is retained and kept consistent with
``validation_status`` so existing consumers and stored rows keep working.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..correlation.engine import Correlation
from ..database.repository import Repository
from ..models.domain import (
    AttackEdge,
    AttackNode,
    AuthorizationTest,
    Endpoint,
    Finding,
    Host,
    Identity,
    Technology,
)
from ..models.enums import ValidationState

# Relationship vocabulary (documented in docs/ATTACK_GRAPH.md).
REL_HOSTS = "HOSTS"
REL_CONTAINS = "CONTAINS"
REL_USES = "USES"
REL_AFFECTS = "AFFECTS"
REL_EXPOSES = "EXPOSES"
REL_CAN_ACCESS = "CAN_ACCESS"
REL_LEADS_TO = "LEADS_TO"
REL_REQUIRES = "REQUIRES"
REL_DEPENDS_ON = "DEPENDS_ON"
REL_MITIGATED_BY = "MITIGATED_BY"


def _edge(scan_id: str, source: AttackNode, target: AttackNode, relation: str, *,
          confidence: float, state: ValidationState, source_component: str,
          evidence_ids: list[str] | None = None,
          attributes: dict | None = None) -> AttackEdge:
    """Create an edge with its epistemic metadata populated consistently."""
    return AttackEdge(
        scan_id=scan_id,
        source_id=source.id,
        target_id=target.id,
        relation=relation,
        attributes=attributes or {},
        confidence=confidence,
        validation_status=state,
        evidence_ids=evidence_ids or [],
        source=source_component,
        # Keep the 1.x flag consistent so old consumers still work.
        hypothesis=not state.is_fact,
    )


class AttackGraphBuilder:
    """Builds an evidence-aware attack-surface graph from scan artifacts."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def build(
        self,
        scan_id: str,
        target: str,
        endpoints: list[Endpoint],
        technologies: list[Technology],
        findings: list[Finding],
        correlations: list[Correlation] | None = None,
        *,
        hosts: list[Host] | None = None,
        identities: list[Identity] | None = None,
        authz_tests: list[AuthorizationTest] | None = None,
    ) -> tuple[list[AttackNode], list[AttackEdge]]:
        nodes: list[AttackNode] = []
        edges: list[AttackEdge] = []
        parts = urlsplit(target)
        app_label = parts.netloc or target

        # --- Application (observed: we fetched it) ---
        app = AttackNode(scan_id=scan_id, kind="Application", label=app_label,
                         attributes={"target": target, "scheme": parts.scheme},
                         confidence=1.0, validation_status=ValidationState.OBSERVED)
        nodes.append(app)

        # --- Hosts and ports ---
        for host in hosts or []:
            host_node = AttackNode(
                scan_id=scan_id, kind="Host", label=host.hostname,
                attributes={"ip_addresses": host.ip_addresses},
                confidence=1.0, validation_status=ValidationState.OBSERVED, ref_id=host.id)
            nodes.append(host_node)
            edges.append(_edge(scan_id, host_node, app, REL_HOSTS, confidence=1.0,
                               state=ValidationState.OBSERVED, source_component="recon"))
            port = parts.port or (443 if parts.scheme == "https" else 80)
            port_node = AttackNode(
                scan_id=scan_id, kind="Port", label=str(port),
                attributes={"scheme": parts.scheme},
                confidence=1.0, validation_status=ValidationState.OBSERVED)
            nodes.append(port_node)
            edges.append(_edge(scan_id, host_node, port_node, REL_EXPOSES, confidence=1.0,
                               state=ValidationState.OBSERVED, source_component="recon"))

        # --- Endpoints (observed) + their parameters ---
        ep_node_by_url: dict[str, AttackNode] = {}
        for ep in endpoints:
            node = AttackNode(
                scan_id=scan_id, kind="Endpoint", label=urlsplit(ep.url).path or "/",
                attributes={"status": ep.status_code, "is_api": ep.is_api,
                            "method": ep.method, "url": ep.url},
                confidence=1.0 if ep.status_code else 0.6,
                validation_status=(ValidationState.OBSERVED if ep.status_code
                                   else ValidationState.INFERRED),
                ref_id=ep.id)
            nodes.append(node)
            ep_node_by_url[ep.url] = node
            edges.append(_edge(scan_id, app, node, REL_CONTAINS, confidence=1.0,
                               state=ValidationState.OBSERVED, source_component="crawler"))
            for param in ep.parameters[:10]:
                p_node = AttackNode(
                    scan_id=scan_id, kind="Parameter", label=param,
                    attributes={"endpoint": ep.url},
                    confidence=1.0, validation_status=ValidationState.OBSERVED)
                nodes.append(p_node)
                edges.append(_edge(scan_id, node, p_node, REL_CONTAINS, confidence=1.0,
                                   state=ValidationState.OBSERVED, source_component="crawler"))

        # --- Technologies (confidence comes from the fingerprint engine) ---
        for tech in technologies:
            label = f"{tech.name}{(' ' + tech.version) if tech.version else ''}"
            node = AttackNode(
                scan_id=scan_id, kind="Technology", label=label,
                attributes={"confidence": tech.confidence, "evidence": tech.evidence},
                confidence=tech.confidence,
                validation_status=(ValidationState.OBSERVED if tech.confidence >= 0.85
                                   else ValidationState.INFERRED),
                ref_id=tech.id)
            nodes.append(node)
            edges.append(_edge(scan_id, app, node, REL_USES, confidence=tech.confidence,
                               state=node.validation_status, source_component="fingerprint",
                               attributes={"evidence": tech.evidence}))

        # --- Identities and observed access (from the authorization matrix) ---
        identity_nodes: dict[str, AttackNode] = {}
        for identity in identities or []:
            node = AttackNode(
                scan_id=scan_id, kind="Identity", label=identity.name,
                attributes={"role": identity.role.value},
                confidence=1.0, validation_status=ValidationState.OBSERVED, ref_id=identity.id)
            nodes.append(node)
            identity_nodes[identity.id] = node

        for test in authz_tests or []:
            src = identity_nodes.get(test.identity_id)
            dst = ep_node_by_url.get(test.url)
            if src is None or dst is None:
                continue
            if test.observed.value != "GRANTED":
                continue
            edges.append(_edge(
                scan_id, src, dst, REL_CAN_ACCESS, confidence=0.9,
                state=ValidationState.OBSERVED, source_component="authz.matrix",
                evidence_ids=list(test.evidence_ids),
                attributes={"expected": test.expected.value, "observed": test.observed.value,
                            "outcome": test.outcome.value, "status": test.status_code}))

        # --- Findings (observed detections) ---
        finding_nodes: dict[str, AttackNode] = {}
        for f in findings:
            node = AttackNode(
                scan_id=scan_id, kind="Finding", label=f.title,
                attributes={"severity": f.severity.value, "status": f.status.value,
                            "priority": f.priority_score, "category": f.category,
                            "cwe": f.cwe_id, "owasp": f.owasp_category},
                confidence=f.confidence.score,
                validation_status=(ValidationState.VALIDATED
                                   if f.status.value == "Confirmed"
                                   else ValidationState.OBSERVED),
                evidence_ids=list(f.evidence_ids),
                ref_id=f.id)
            nodes.append(node)
            finding_nodes[f.id] = node
            # Direction follows the attack narrative so paths are traversable:
            #   Application -CONTAINS-> Endpoint -EXPOSES-> Finding -AFFECTS-> Impact
            # (1.x emitted Finding -AFFECTS-> Endpoint, which pointed against the flow
            # and made path analysis impossible. Documented in the release notes.)
            anchor = ep_node_by_url.get(f.endpoint, app)
            edges.append(_edge(scan_id, anchor, node, REL_EXPOSES,
                               confidence=f.confidence.score,
                               state=node.validation_status,
                               source_component=f.scanner or "scanner",
                               evidence_ids=list(f.evidence_ids),
                               attributes={"severity": f.severity.value,
                                           "finding_id": f.id}))

            # Remediation node — a control that would mitigate the finding.
            if f.remediation:
                rem = AttackNode(
                    scan_id=scan_id, kind="Remediation", label=f.remediation[:80],
                    attributes={"finding_id": f.id},
                    confidence=1.0, validation_status=ValidationState.INFERRED)
                nodes.append(rem)
                edges.append(_edge(scan_id, node, rem, REL_MITIGATED_BY, confidence=0.8,
                                   state=ValidationState.INFERRED,
                                   source_component="remediation-catalog"))

        # --- Correlation hypotheses: Path + Impact nodes, clearly HYPOTHESIZED ---
        for corr in correlations or []:
            path_node = AttackNode(
                scan_id=scan_id, kind="Path", label=f"[HYPOTHESIS] {corr.title}",
                attributes={"path": corr.path, "hypothesis": True,
                            "description": corr.description},
                confidence=0.4, validation_status=ValidationState.HYPOTHESIZED)
            nodes.append(path_node)
            impact = AttackNode(
                scan_id=scan_id, kind="Impact", label=f"Potential impact: {corr.title}",
                attributes={"hypothesis": True},
                confidence=0.35, validation_status=ValidationState.HYPOTHESIZED)
            nodes.append(impact)
            edges.append(_edge(scan_id, path_node, impact, REL_AFFECTS, confidence=0.35,
                               state=ValidationState.HYPOTHESIZED,
                               source_component="correlation"))
            for fid in corr.finding_ids:
                src = finding_nodes.get(fid)
                if src is not None:
                    edges.append(_edge(scan_id, src, path_node, REL_LEADS_TO, confidence=0.4,
                                       state=ValidationState.HYPOTHESIZED,
                                       source_component="correlation",
                                       evidence_ids=list(src.evidence_ids)))
        return nodes, edges

    def persist(self, nodes: list[AttackNode], edges: list[AttackEdge]) -> None:
        for n in nodes:
            self.repo.add_node(n)
        for e in edges:
            self.repo.add_edge(e)
