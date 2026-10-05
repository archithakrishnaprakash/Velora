# Evidence model

Velora's central claim is that a finding means something because of what was observed,
not because a tool said so. The evidence model is what makes that claim checkable.

## Epistemic states

Every finding, graph node, graph edge and AI analysis carries a `ValidationState`. It
answers one question: *how do we know this?*

| State | Meaning | Who sets it |
|---|---|---|
| `OBSERVED` | Seen directly in a response Velora captured. | Deterministic checks |
| `INFERRED` | Derived from observations by a rule. | Correlation, graph builder |
| `HYPOTHESIZED` | Proposed by reasoning, not derived. | The AI layer |
| `VALIDATED` | A human reproduced it and confirmed it. | `velora finding validate` |
| `UNKNOWN` | Not established. | Rejections, undeterminable cases |

`OBSERVED` and `VALIDATED` are facts (`ValidationState.is_fact`). The others are not,
and anything built on them inherits that.

## The lifecycle of a finding

```
check observes something
        │
        ▼
CheckOutput + EvidenceItem(s)
        │
        ▼
Finding(status=Potential, validation_state=OBSERVED)
        │
        ├── AI analysis (advisory, capped, never confirming)
        │
        ▼
human review ──► Confirmed / Rejected
        │
        ▼
remediation ──► retest ──► FIX_VERIFIED | FIX_FAILED
```

A finding enters at `Potential`. Nothing a check, a plugin, a correlation rule or the AI
layer can do moves it past that. Only `velora finding validate` — run by a person —
sets `Confirmed`, and that is also the one action that sets `VALIDATED`.

## What an evidence record holds

| Field | Purpose |
|---|---|
| `test_name` | Which check produced it |
| `request_metadata` | URL, method, redacted request headers |
| `response_metadata` | Status, content type, size, redirect chain, truncation flag |
| `headers` | Redacted response headers |
| `sanitized_excerpt` | A bounded, redacted slice of the body |
| `confidence` | How reliable the *observation* is — not how exploitable the issue is |
| `created_at` | When it was captured |

Everything is redacted before storage. Credentials, tokens, cookie values and API keys
never reach the database, a report, a log line or an AI prompt. `tests/security/
test_secret_persistence.py` reads the SQLite file as raw bytes to prove it.

## Confidence means reliability, not severity

`Confidence` (Tentative / Firm / Certain) says how sure Velora is that it *saw* what it
says it saw. It does not say how bad the issue is; that is `Severity`, and how urgent it
is to look at; that is the Velora priority score. Keeping the three separate is what
lets a Certain-confidence Informational finding and a Tentative High coexist without the
report contradicting itself.

## Truncated responses

A response that hit the download ceiling is marked `truncated`. This matters for any
check that reasons about *absence* — "the body does not contain X" is not a safe
conclusion from a body that was cut off. The flag travels into the evidence metadata so
a reviewer can see it.

## The AI evidence matrix

Before the AI layer says anything about a finding, a deterministic matrix is computed
from the stored evidence: what supports the claim, what contradicts it, and what is
missing. That matrix caps the AI's confidence:

```python
score = base * (0.55 + 0.45 * coverage) - 0.08 * len(contradicting)
return max(0.05, min(0.9, round(score, 3)))
```

The cap is 0.9. The AI cannot reach certainty about anything, by construction, because
the thing it is reasoning about is a set of observations that a human has not yet
checked.

## What "no findings" means

It means the checks that ran did not detect anything, within the configured scope and
request budget. It is not a statement about the target's security, and every report says
so in its limitations section. The same applies to a retest: if the retest did not cover
the affected endpoint, the absence of a detection verifies nothing, and Velora reports
`READY_FOR_RETEST` rather than `FIX_VERIFIED`.

## Reproducibility

Each validated finding can carry a reproduction package: Velora version, detector id,
scan profile, a hash of the scope policy that was in force, bounded request and response
metadata, the evidence ids, and the steps to run it again. It contains no credentials.

```bash
velora reproduce show WEB-XXXXXX
```

Related: [SECURITY_MODEL.md](SECURITY_MODEL.md), [AI_SECURITY_MODEL.md](AI_SECURITY_MODEL.md),
[SCOPE_MODEL.md](SCOPE_MODEL.md).
