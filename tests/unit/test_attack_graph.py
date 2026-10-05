import unittest

from velora.attack_graph.paths import AttackPathAnalyzer, GraphPath
from velora.models.domain import AttackEdge, AttackNode
from velora.models.enums import ValidationState


def node(kind, label, **kw):
    return AttackNode(scan_id="S", kind=kind, label=label, **kw)


def edge(src, dst, relation="LEADS_TO", confidence=0.9,
         state=ValidationState.OBSERVED, evidence_ids=None):
    return AttackEdge(scan_id="S", source_id=src.id, target_id=dst.id, relation=relation,
                      confidence=confidence, validation_status=state,
                      evidence_ids=evidence_ids or [], hypothesis=not state.is_fact)


class TestGraphPath(unittest.TestCase):
    def test_confidence_is_the_weakest_link(self):
        a, b, c = node("Application", "app"), node("Endpoint", "/x"), node("Finding", "f")
        path = GraphPath(nodes=[a, b, c],
                         edges=[edge(a, b, confidence=0.95), edge(b, c, confidence=0.4)])
        self.assertEqual(path.confidence, 0.4)

    def test_status_is_the_weakest_link(self):
        a, b, c = node("Application", "app"), node("Endpoint", "/x"), node("Impact", "i")
        path = GraphPath(nodes=[a, b, c], edges=[
            edge(a, b, state=ValidationState.OBSERVED),
            edge(b, c, state=ValidationState.HYPOTHESIZED)])
        self.assertEqual(path.validation_status, ValidationState.HYPOTHESIZED)
        self.assertTrue(path.is_hypothesis)

    def test_fully_observed_path_is_not_a_hypothesis(self):
        a, b = node("Endpoint", "/x"), node("Finding", "f")
        path = GraphPath(nodes=[a, b], edges=[edge(a, b, state=ValidationState.OBSERVED)])
        self.assertFalse(path.is_hypothesis)

    def test_evidence_ids_are_deduplicated(self):
        a, b, c = node("A", "1"), node("B", "2"), node("C", "3")
        path = GraphPath(nodes=[a, b, c], edges=[
            edge(a, b, evidence_ids=["EV1", "EV2"]), edge(b, c, evidence_ids=["EV2", "EV3"])])
        self.assertEqual(path.evidence_ids, ["EV1", "EV2", "EV3"])

    def test_empty_path_has_unknown_status(self):
        self.assertEqual(GraphPath().validation_status, ValidationState.UNKNOWN)
        self.assertEqual(GraphPath().confidence, 0.0)


class TestPathAnalyzer(unittest.TestCase):
    def setUp(self):
        self.app = node("Application", "app")
        self.ep = node("Endpoint", "/admin")
        self.finding = node("Finding", "weak authz")
        self.path_node = node("Path", "[HYPOTHESIS] chain")
        self.impact = node("Impact", "data exposure")
        self.nodes = [self.app, self.ep, self.finding, self.path_node, self.impact]
        self.edges = [
            edge(self.app, self.ep, "CONTAINS", 1.0, ValidationState.OBSERVED),
            edge(self.ep, self.finding, "EXPOSES", 0.9, ValidationState.OBSERVED),
            edge(self.finding, self.path_node, "LEADS_TO", 0.4, ValidationState.HYPOTHESIZED),
            edge(self.path_node, self.impact, "AFFECTS", 0.35, ValidationState.HYPOTHESIZED),
        ]
        self.analyzer = AttackPathAnalyzer(self.nodes, self.edges)

    def test_finds_paths_to_impact(self):
        paths = self.analyzer.find_paths()
        self.assertTrue(paths)
        self.assertTrue(any(p.nodes[-1].kind == "Impact" for p in paths))

    def test_hypothesis_and_evidenced_paths_are_distinguished(self):
        paths = self.analyzer.find_paths()
        self.assertTrue(any(not p.is_hypothesis for p in paths))
        self.assertTrue(any(p.is_hypothesis for p in paths))

    def test_cycles_do_not_hang_traversal(self):
        cyclic = [*self.edges, edge(self.impact, self.app, "LEADS_TO")]
        analyzer = AttackPathAnalyzer(self.nodes, cyclic)
        paths = analyzer.find_paths(max_depth=8, max_paths=20)
        for path in paths:
            ids = [n.id for n in path.nodes]
            self.assertEqual(len(ids), len(set(ids)), "path revisited a node")

    def test_max_paths_is_respected(self):
        self.assertLessEqual(len(self.analyzer.find_paths(max_paths=2)), 2)

    def test_max_depth_is_respected(self):
        for path in self.analyzer.find_paths(max_depth=2):
            self.assertLessEqual(path.length, 2)

    def test_paths_sorted_strongest_first(self):
        paths = self.analyzer.find_paths()
        confidences = [p.confidence for p in paths]
        self.assertEqual(confidences, sorted(confidences, reverse=True))

    def test_explain_labels_observed_and_asserted_steps(self):
        path = next(p for p in self.analyzer.find_paths() if p.is_hypothesis)
        text = self.analyzer.explain(path)
        self.assertIn("OBSERVED", text)
        self.assertIn("ASSERTED", text)
        self.assertIn("HYPOTHESIS", text)
        self.assertIn("Validation required", text)

    def test_explain_of_evidenced_path_still_disclaims_exploitability(self):
        path = next(p for p in self.analyzer.find_paths() if not p.is_hypothesis)
        text = self.analyzer.explain(path)
        self.assertIn("does not by itself prove exploitability", text)

    def test_summary_counts_by_status(self):
        summary = self.analyzer.summary()
        self.assertEqual(summary["nodes"], 5)
        self.assertEqual(summary["edges"], 4)
        self.assertEqual(summary["hypothesis_edges"], 2)
        self.assertIn("OBSERVED", summary["edges_by_validation_status"])


if __name__ == "__main__":
    unittest.main()
