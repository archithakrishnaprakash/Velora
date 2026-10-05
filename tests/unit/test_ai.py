import unittest

from velora.ai.base import AnalysisInput, AnalysisResult
from velora.ai.heuristic import HeuristicProvider
from velora.ai.null import NullProvider
from velora.ai.openai_compatible import OpenAICompatibleProvider
from velora.utils.errors import AIProviderError


def _inp(category="configuration"):
    return AnalysisInput(target="http://x/", endpoint="http://x/", method="GET",
                         finding_title="Missing header", category=category, severity="Medium",
                         scanner_confidence="Certain", description="d", evidence_excerpts=["e"])


class TestAI(unittest.TestCase):
    def test_heuristic_requires_human_validation(self):
        res = HeuristicProvider().analyze(_inp())
        self.assertTrue(res.human_validation_required)
        self.assertTrue(res.ai_generated)
        self.assertTrue(0.0 <= res.confidence <= 1.0)

    def test_safety_clamp_neutralizes_confirmed(self):
        r = AnalysisResult(classification="confirmed-rce", confidence=2.0,
                           reasoning_summary="", impact="", remediation="")
        r.enforce_safety()
        self.assertTrue(r.classification.startswith("potential-"))
        self.assertEqual(r.confidence, 1.0)
        self.assertTrue(r.human_validation_required)

    def test_null_provider(self):
        res = NullProvider().analyze(_inp())
        self.assertEqual(res.classification, "not-analyzed")

    def test_openai_parser_handles_wrapped_json(self):
        parsed = OpenAICompatibleProvider._parse('prefix {"classification":"x","confidence":0.4} suffix')
        self.assertEqual(parsed["classification"], "x")

    def test_openai_parser_rejects_non_json(self):
        with self.assertRaises(AIProviderError):
            OpenAICompatibleProvider._parse("no json here")

    def test_openai_requires_key(self):
        with self.assertRaises(AIProviderError):
            OpenAICompatibleProvider("")


if __name__ == "__main__":
    unittest.main()
