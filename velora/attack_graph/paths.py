"""Attack-path analysis over the evidence-aware graph.

Path analysis answers: *from an entry point, what chain of relationships reaches an
impact, and how much of that chain is actually evidenced?*

The critical property is that a path's strength is bounded by its **weakest** link, and
a path containing any HYPOTHESIZED edge is itself a hypothesis. Velora never presents a
path as proven because its individual steps look plausible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models.domain import AttackEdge, AttackNode
from ..models.enums import ValidationState

# Node kinds that can start a path (reachable surface).
ENTRY_KINDS = frozenset({"Application", "Endpoint", "Identity", "Host"})
# Node kinds that represent a consequence worth reporting.
IMPACT_KINDS = frozenset({"Impact", "Path", "Finding"})

_STATE_RANK = {
    ValidationState.VALIDATED: 4,
    ValidationState.OBSERVED: 3,
    ValidationState.INFERRED: 2,
    ValidationState.HYPOTHESIZED: 1,
    ValidationState.UNKNOWN: 0,
}


@dataclass
class GraphPath:
    """One route through the graph, with its weakest-link epistemic status."""

    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def confidence(self) -> float:
        """A path is only as strong as its weakest edge."""
        if not self.edges:
            return 0.0
        return round(min(e.confidence for e in self.edges), 3)

    @property
    def validation_status(self) -> ValidationState:
        """The weakest epistemic state along the path governs the whole path."""
        if not self.edges:
            return ValidationState.UNKNOWN
        return min((e.validation_status for e in self.edges),
                   key=lambda s: _STATE_RANK.get(s, 0))

    @property
    def is_hypothesis(self) -> bool:
        return not self.validation_status.is_fact

    @property
    def evidence_ids(self) -> list[str]:
        out: list[str] = []
        for edge in self.edges:
            for eid in edge.evidence_ids:
                if eid not in out:
                    out.append(eid)
        return out

    def labels(self) -> list[str]:
        return [n.label for n in self.nodes]

    def render(self) -> str:
        arrow = " -> "
        chain = arrow.join(f"{n.kind}:{n.label[:40]}" for n in self.nodes)
        marker = "HYPOTHESIS" if self.is_hypothesis else "EVIDENCED"
        return (f"[{marker}] {chain}\n"
                f"    confidence={self.confidence:.2f} "
                f"status={self.validation_status.value} "
                f"evidence={len(self.evidence_ids)} item(s)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label} for n in self.nodes],
            "relations": [e.relation for e in self.edges],
            "confidence": self.confidence,
            "validation_status": self.validation_status.value,
            "is_hypothesis": self.is_hypothesis,
            "evidence_ids": self.evidence_ids,
            "length": self.length,
        }


class AttackPathAnalyzer:
    """Finds and explains paths in a stored attack graph."""

    def __init__(self, nodes: list[AttackNode], edges: list[AttackEdge]) -> None:
        self.nodes = {n.id: n for n in nodes}
        self.edges = edges
        self._adjacency: dict[str, list[AttackEdge]] = {}
        for edge in edges:
            self._adjacency.setdefault(edge.source_id, []).append(edge)

    # ---- traversal -------------------------------------------------------
    def find_paths(
        self,
        *,
        max_depth: int = 6,
        max_paths: int = 50,
        entry_kinds: frozenset[str] = ENTRY_KINDS,
        impact_kinds: frozenset[str] = IMPACT_KINDS,
        min_length: int = 2,
    ) -> list[GraphPath]:
        """Enumerate simple paths from an entry node to an impact node.

        Depth-bounded and path-count-bounded so a dense graph cannot exhaust memory.
        """
        results: list[GraphPath] = []
        starts = [n for n in self.nodes.values() if n.kind in entry_kinds]

        for start in starts:
            if len(results) >= max_paths:
                break
            stack: list[tuple[str, list[str], list[AttackEdge]]] = [(start.id, [start.id], [])]
            while stack and len(results) < max_paths:
                current, visited, path_edges = stack.pop()
                if len(path_edges) >= max_depth:
                    continue
                for edge in self._adjacency.get(current, []):
                    if edge.target_id in visited:
                        continue  # simple paths only — no cycles
                    target = self.nodes.get(edge.target_id)
                    if target is None:
                        continue
                    new_edges = [*path_edges, edge]
                    new_visited = [*visited, edge.target_id]
                    if target.kind in impact_kinds and len(new_edges) >= min_length:
                        results.append(GraphPath(
                            nodes=[self.nodes[i] for i in new_visited], edges=new_edges))
                        if len(results) >= max_paths:
                            break
                    stack.append((edge.target_id, new_visited, new_edges))

        # Strongest, shortest first.
        results.sort(key=lambda p: (-p.confidence, p.length))
        return results

    # ---- explanation -----------------------------------------------------
    def explain(self, path: GraphPath) -> str:
        """A factual, non-speculative narration of one path."""
        lines: list[str] = []
        status = path.validation_status
        header = ("This path is a HYPOTHESIS: at least one step is not directly evidenced."
                  if path.is_hypothesis else
                  "Every step in this path is backed by a direct observation.")
        lines.append(header)
        lines.append("")
        for i, edge in enumerate(path.edges, start=1):
            src = self.nodes.get(edge.source_id)
            dst = self.nodes.get(edge.target_id)
            if src is None or dst is None:
                continue
            marker = "OBSERVED " if edge.validation_status.is_fact else "ASSERTED "
            lines.append(
                f"  {i}. [{marker}] {src.kind} '{src.label[:44]}' --{edge.relation}--> "
                f"{dst.kind} '{dst.label[:44]}'")
            detail = (f"       confidence={edge.confidence:.2f} "
                      f"state={edge.validation_status.value} source={edge.source or 'n/a'}")
            if edge.evidence_ids:
                detail += f" evidence={','.join(edge.evidence_ids[:3])}"
            lines.append(detail)
        lines.append("")
        lines.append(f"Path confidence (weakest link): {path.confidence:.2f}")
        lines.append(f"Path status (weakest link): {status.value}")
        if path.is_hypothesis:
            lines.append("Validation required before this path is treated as real.")
        else:
            lines.append("Note: an evidenced path describes observed reachability. It does "
                         "not by itself prove exploitability or business impact.")
        return "\n".join(lines)

    # ---- summary ---------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for node in self.nodes.values():
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        by_relation: dict[str, int] = {}
        by_state: dict[str, int] = {}
        for edge in self.edges:
            by_relation[edge.relation] = by_relation.get(edge.relation, 0) + 1
            key = edge.validation_status.value
            by_state[key] = by_state.get(key, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "nodes_by_kind": by_kind,
            "edges_by_relation": by_relation,
            "edges_by_validation_status": by_state,
            "hypothesis_edges": sum(1 for e in self.edges if not e.validation_status.is_fact),
        }
