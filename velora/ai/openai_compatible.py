"""OpenAI-compatible provider (pluggable external LLM).

Talks to any OpenAI-style ``/chat/completions`` endpoint configured via ``base_url`` and
a model name. The API key is read from the environment (never hard-coded, never stored,
never logged, never reported).

All prompt construction goes through :class:`~velora.ai.envelope.PromptEnvelope`, so
target-derived content is sanitized, nonce-fenced and explicitly labelled as data before
it reaches the model. The response is parsed defensively and then clamped by
``enforce_safety`` against the deterministic evidence matrix.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..models.enums import ValidationState
from ..utils.errors import AIProviderError
from ..utils.logging import get_logger
from .base import AIProvider, AnalysisInput, AnalysisResult

log = get_logger("ai.openai")

RESPONSE_SCHEMA_HINT = """\
Return exactly one JSON object with these keys:
  classification            string   - short kebab-case label, never containing "confirmed"
  confidence                number   - 0..1, your confidence in the ANALYSIS, not the risk
  supporting_evidence       string[] - statements grounded in the EVIDENCE section
  contradicting_evidence    string[] - evidence that argues against the finding
  missing_evidence          string[] - what was NOT tested and would change the conclusion
  reasoning_summary         string   - under 120 words, no chain-of-thought
  impact                    string
  remediation               string
  recommended_validation    string   - what a human should do to validate
  related_findings          string[]
  validation_state          string   - one of OBSERVED, INFERRED, HYPOTHESIZED, UNKNOWN
"""


class OpenAICompatibleProvider(AIProvider):
    name = "openai_compatible"

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gpt-4o-mini",
        base_url: str | None = None,
        max_tokens: int = 800,
        temperature: float = 0.1,
        timeout: float = 30.0,
    ) -> None:
        if not api_key:
            raise AIProviderError("no API key configured for openai_compatible provider")
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

    def analyze(self, data: AnalysisInput) -> AnalysisResult:
        envelope = data.build_envelope()
        messages = envelope.to_messages()
        # Append the response schema to the system message so it is instruction-side.
        messages[0]["content"] += "\n--- RESPONSE SCHEMA ---\n" + RESPONSE_SCHEMA_HINT

        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            # Never include the key or headers in the error path.
            raise AIProviderError(f"LLM request failed: {type(exc).__name__}: {exc}") from exc

        parsed = self._parse(content)
        matrix = data.evidence_matrix or {}
        try:
            state = ValidationState(str(parsed.get("validation_state", "HYPOTHESIZED")).upper())
        except ValueError:
            state = ValidationState.HYPOTHESIZED

        return AnalysisResult(
            classification=str(parsed.get("classification", "potential-issue")),
            confidence=float(parsed.get("confidence", 0.5) or 0.5),
            reasoning_summary=str(parsed.get("reasoning_summary", ""))[:1200],
            impact=str(parsed.get("impact", "")),
            remediation=str(parsed.get("remediation", "")),
            related_findings=[str(x) for x in parsed.get("related_findings", []) or []],
            supporting_evidence=[str(x) for x in parsed.get("supporting_evidence", []) or []],
            contradicting_evidence=[str(x) for x in
                                    parsed.get("contradicting_evidence", []) or []],
            missing_evidence=[str(x) for x in parsed.get("missing_evidence", []) or []],
            recommended_validation=str(parsed.get("recommended_validation", "")),
            validation_state=state,
            evidence_matrix=matrix,
            prompt_sanitized=True,
            injection_detected=envelope.injection_detected,
            provider=self.name,
            model=self.model,
            raw={"usage": body.get("usage", {}),
                 "sanitization": envelope.sanitization_summary()},
        ).enforce_safety(max_confidence=matrix.get("confidence"))

    @staticmethod
    def _parse(content: str) -> dict[str, Any]:
        content = (content or "").strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start, end = content.find("{"), content.rfind("}")
            if 0 <= start < end:
                try:
                    return json.loads(content[start : end + 1])
                except json.JSONDecodeError as exc:
                    raise AIProviderError(f"could not parse LLM JSON: {exc}") from exc
            raise AIProviderError("LLM response was not JSON")
