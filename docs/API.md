# Velora dashboard and JSON API

The ASGI application is built by the factory `velora.api.app:create_asgi_app`. It serves
24 server-rendered HTML pages and 23 JSON endpoints from one Starlette app.

Start it with the CLI:

```bash
velora dashboard --host 127.0.0.1 --port 8787
```

or directly with uvicorn:

```bash
python -m uvicorn --factory velora.api.app:create_asgi_app --host 127.0.0.1 --port 8811
```

The response shapes below were captured by curling a running instance that had seeded
demo data. Empty-collection behaviour was confirmed separately.

## The dashboard is read-only by design

The application never launches a scan, never mutates a finding, and never sends a request
to a target. Every route is registered without a `methods` argument, so Starlette allows
only `GET` and `HEAD`; a `POST` to any route returns `405`.

That is deliberate. Scope enforcement, the authorization acknowledgement
(`--i-am-authorized`), operator attribution and audit logging all live in the CLI. Putting
a "scan" button on a web page would move an action with legal weight behind an
unauthenticated HTTP request. The dashboard has no authentication of its own and binds to
loopback by default, so anything it could trigger would be triggerable by anything that
can reach the port. Reading is safe to expose that way; acting is not.

The consequence for operators: use the dashboard to read results, then act in a terminal.
Scans, finding validation, remediation transitions and gate evaluation all go through
`velora <command>`.

## Security headers

`SecurityHeadersMiddleware` sets the same six headers on **every** response, including
JSON responses and 404s:

| Header | Value |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Content-Security-Policy` | see below |

The CSP is:

```text
default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

`default-src 'none'` means no scripts, fonts, frames, connections or media may load at
all — there is no `script-src` allowance of any kind, so the dashboard cannot execute
JavaScript even if a template were made to emit some. Charts are server-rendered inline
SVG (`velora/api/charts.py`) precisely so no charting library or CDN is needed; the
dashboard works on an air-gapped machine. `style-src` permits `'unsafe-inline'` because
styles are inlined in the templates. `frame-ancestors 'none'` and `X-Frame-Options: DENY`
both block framing. `Cache-Control: no-store` keeps assessment data out of disk caches.

There is no `/static` mount. The `velora/api/static/` directory exists but is empty, no
template references it, and a request to `/static/anything` returns `404`.

## Page routes

All pages return `200` with `text/html; charset=utf-8`. All 24 were confirmed against a
running instance.

| Path | Page | Query parameters |
| --- | --- | --- |
| `/` | Dashboard overview | — |
| `/engagements` | Engagements | — |
| `/targets` | Targets | — |
| `/scans` | Scans | — |
| `/scans/{scan_id}` | Scan detail | — |
| `/attack-surface` | Attack surface | `scan` |
| `/attack-graph` | Attack graph | `scan` |
| `/differential` | Differential observations | `scan` |
| `/findings` | Findings | `scan`, `severity`, `status` |
| `/findings/{finding_id}` | Finding detail | — |
| `/evidence` | Evidence | `scan` |
| `/ai-analyst` | AI analyses | `scan` |
| `/authorization` | Authorization testing | `scan` |
| `/workflows` | Workflows | — |
| `/remediation` | Remediation | — |
| `/regression` | Regression | `scan` |
| `/posture` | Security posture | — |
| `/benchmarks` | Benchmarks | — |
| `/plans` | Assessment plans | — |
| `/reports` | Reports | — |
| `/ci-cd` | CI/CD gate results | — |
| `/plugins` | Plugins / checks | — |
| `/audit` | Audit log | — |
| `/settings` | Effective settings | — |

### The `scan` query parameter

Eight pages resolve a selected scan through one shared helper:

- Omitted: the most recent scan is selected (scans sorted by `started_at`, then id).
- Present and matching a stored scan: that scan is used.
- Present but matching nothing: **no** scan is selected and the page renders its empty
  state. It does not silently fall back to the most recent scan. The status is still
  `200`.

### The `findings` filters

`severity` and `status` are exact, case-sensitive matches against the stored display
values — `High`, `Medium`, `Low`, `Informational`, `Critical` for severity and `Potential`,
`Confirmed`, `Rejected`, `Remediated` and similar for status. An unknown value yields an
empty table with `200`, not an error.

### Page 404s

`/scans/{scan_id}` and `/findings/{finding_id}` return `404` with the `notfound.html`
template when the id does not exist. Any unmatched non-`/api/` path does the same.

## JSON endpoints

All return `application/json`. All were confirmed against a running instance.

| Path | Query parameters | Response |
| --- | --- | --- |
| `/api/health` | — | Object, see below |
| `/api/targets` | — | Array of target objects |
| `/api/scans` | — | Array of scan objects |
| `/api/scans/{scan_id}/graph` | — | `{"nodes": [...], "edges": [...]}` |
| `/api/scans/{scan_id}/sarif` | — | SARIF 2.1.0 document |
| `/api/findings` | `scan` | Array of finding objects |
| `/api/findings/{finding_id}` | — | One finding object |
| `/api/evidence` | `scan` (**required**) | Array of evidence objects |
| `/api/plugins` | — | Array, see below |
| `/api/engagements` | — | Array of engagement objects |
| `/api/identities` | `engagement` | Array of identity objects |
| `/api/differential` | `scan` | Array of differential observations |
| `/api/authorization-tests` | `scan` | Array of authorization test results |
| `/api/workflows` | — | Array of workflows, each with an embedded `steps` array |
| `/api/assessment-plans` | — | Array of plans, each with an embedded `steps` array |
| `/api/remediation` | — | Array of remediation actions, each with an embedded `retests` array |
| `/api/regression` | `scan` | Array of regression results |
| `/api/benchmark` | — | Array of benchmark runs |
| `/api/posture` | `target` | Array of posture snapshots |
| `/api/reproduction` | `finding` (**required**) | One reproduction record |
| `/api/security-gate` | `scan` | Array of gate results |
| `/api/ai-analyses` | `scan` | Array of AI analyses |
| `/api/audit` | — | Array of audit entries, newest first, capped at 500 |

Except where marked **required**, an omitted or empty query parameter means "no filter"
and the full collection is returned. A filter value that matches nothing returns `[]` with
`200`:

```bash
curl 'http://127.0.0.1:8811/api/findings?scan=BOGUS'
# []
```

`/api/audit` is hard-capped at 500 entries in the code and takes no `limit` parameter.

### Status codes

| Code | When |
| --- | --- |
| `200` | Success, including an empty array |
| `400` | `/api/evidence` without `scan`, or `/api/reproduction` without `finding` |
| `404` | Unknown `finding_id` on `/api/findings/{id}`, a `finding` with no stored reproduction record on `/api/reproduction`, unknown `scan_id` on `/sarif`, or any unmatched `/api/*` path |
| `405` | Any method other than `GET` or `HEAD` |

The `400` and `404` bodies are both a single-key object:

```json
{"error": "scan query parameter is required"}
{"error": "not found"}
```

A `404` under `/api/` always returns JSON; a `404` elsewhere returns the HTML not-found
page.

Note: `/api/scans/{scan_id}/graph` does **not** check that the scan exists. An unknown scan
id returns `200` with `{"nodes": [], "edges": []}`, not a `404`. `/api/scans/{scan_id}/sarif`
does check, and returns `404`.

### `/api/health`

```json
{"status": "ok", "version": "0.1.0", "checks": 11}
```

`checks` is the number of registered security checks in the current process.

### `/api/plugins`

A hand-built projection, not a full model dump:

```json
[
  {
    "id": "auth.indicators",
    "name": "Authentication configuration indicators",
    "category": "authentication",
    "safe_mode": true,
    "severity": "Medium",
    "description": "Flags credential forms served over HTTP and forms without CSRF tokens."
  }
]
```

It carries no `version`, `sdk_version` or `enabled` field — use `velora plugins list` or
`velora plugins show <id>` for those.

### Model-backed endpoints

Every other endpoint serialises stored pydantic models with `model_dump_json`, so the JSON
field names are the model field names exactly. Representative shapes:

`/api/targets`:

```json
[
  {
    "id": "TGT-KS2M74",
    "engagement_id": "ENG-R38T8X",
    "name": "labshop",
    "url": "http://lab.local/",
    "description": "",
    "owner": "platform",
    "authorization_status": "LAB_ONLY",
    "authorization_note": "",
    "scope_policy_id": "SCOPE-E699K7",
    "created_at": "2026-09-22T15:20:12.588373Z",
    "updated_at": "2026-09-22T15:20:12.588378Z"
  }
]
```

`/api/scans`:

```json
[
  {
    "id": "SCAN-8ZEAJN",
    "engagement_id": "ENG-R38T8X",
    "baseline_scan_id": null,
    "is_retest": false,
    "target_id": "TGT-KS2M74",
    "profile": "safe",
    "status": "completed",
    "operator": "alice",
    "authorization_ack": true,
    "scope_policy_id": "SCOPE-E699K7",
    "started_at": "2026-09-01T09:00:00",
    "finished_at": null,
    "stats": {"findings": 14},
    "created_at": "2026-09-22T15:20:12.588942Z"
  }
]
```

`/api/findings` — note `evidence_ids` is a list of ids, not embedded evidence, and the
lifecycle fields (`status`, `validation_state`, `validated_by`, `remediation_status`) are
separate from the severity fields:

```json
[
  {
    "id": "WEB-MDRDRG",
    "scan_id": "SCAN-8ZEAJN",
    "title": "High issue on /p1",
    "description": "Observed on the response to a scope-checked GET.",
    "category": "headers",
    "severity": "High",
    "confidence": "Tentative",
    "status": "Potential",
    "endpoint": "http://lab.local/p1",
    "method": "GET",
    "evidence_ids": [],
    "cvss_version": null,
    "cvss_vector": null,
    "cvss_base_score": null,
    "cvss_severity": null,
    "references": [],
    "impact": "Weakens a defence-in-depth control.",
    "remediation": "Set the header at the edge for every response.",
    "scanner": "headers.security_headers",
    "priority_score": 98.0,
    "ai_analysis_id": null,
    "validated_by": null,
    "validation_note": "",
    "engagement_id": null,
    "identity_id": null,
    "cwe_id": "CWE-693",
    "owasp_category": "A05:2021",
    "remediation_status": "OPEN",
    "fingerprint": "VF-Hi-1",
    "first_seen_scan_id": null,
    "validation_state": "OBSERVED",
    "created_at": "2026-09-22T15:20:12.597459Z",
    "updated_at": "2026-09-22T15:20:12.597467Z"
  }
]
```

`/api/identities` — identities expose only a `secret_ref` naming an environment variable.
Credential values are never stored and never served:

```json
[
  {
    "id": "IDENT-JTWFMH",
    "engagement_id": "ENG-R38T8X",
    "name": "user-a",
    "role": "user_a",
    "description": "",
    "secret_ref": "VELORA_IDENTITY_USER_A_TOKEN",
    "auth_scheme": "bearer",
    "auth_header_name": "Authorization",
    "owned_resource_hints": ["/api/orders/1"],
    "created_at": "2026-09-22T15:20:12.731258Z"
  }
]
```

`/api/authorization-tests` — `expected` vs `observed` is the core of the record, and
`outcome` is the classification derived from the pair:

```json
[
  {
    "id": "AUTHZ-78CTGP",
    "scan_id": "SCAN-JNKR36",
    "engagement_id": null,
    "plan_id": null,
    "identity_id": "IDENT-JTWFMH",
    "identity_role": "user_a",
    "resource_owner_identity_id": null,
    "url": "http://lab.local/api/orders/2",
    "method": "GET",
    "expected": "DENY",
    "observed": "GRANTED",
    "outcome": "HORIZONTAL_AUTHORIZATION_WEAKNESS",
    "status_code": 200,
    "response_size": 0,
    "differential_id": null,
    "evidence_ids": [],
    "notes": "Another user's order was returned.",
    "created_at": "2026-09-22T15:20:12.732283Z"
  }
]
```

`/api/differential` — every observation carries `validation_required`:

```json
[
  {
    "id": "DIFF-7ZJQMG",
    "scan_id": "SCAN-JNKR36",
    "label": "owner vs other user",
    "baseline_url": "http://lab.local/api/orders/1",
    "candidate_url": "http://lab.local/api/orders/2",
    "baseline_method": "GET",
    "candidate_method": "GET",
    "baseline_fingerprint": {},
    "candidate_fingerprint": {},
    "differences": [
      {"classification": "BODY_STRUCTURE_CHANGE"},
      {"classification": "SIZE_BUCKET_CHANGE"}
    ],
    "classifications": ["BODY_STRUCTURE_CHANGE", "SIZE_BUCKET_CHANGE"],
    "confidence": 0.62,
    "interpretation": "Response content differs between identities; requires validation.",
    "validation_required": true,
    "evidence_ids": [],
    "created_at": "2026-09-22T15:20:12.733Z"
  }
]
```

`/api/ai-analyses` — `human_validation_required` and `ai_generated` are always present,
alongside the evidence matrix fields:

```json
[
  {
    "id": "AI-CYJNBK",
    "finding_id": "WEB-CSWQ2D",
    "scan_id": "SCAN-JNKR36",
    "provider": "heuristic",
    "model": "rules-1",
    "classification": "missing control",
    "confidence": 0.3,
    "reasoning_summary": "The observed response lacks the header the check requires.",
    "impact": "",
    "remediation": "",
    "related_findings": [],
    "human_validation_required": true,
    "ai_generated": true,
    "raw": {},
    "supporting_evidence": ["EV-1"],
    "contradicting_evidence": [],
    "missing_evidence": [],
    "recommended_validation": "Re-request with a browser and inspect response headers.",
    "evidence_matrix": {},
    "validation_status": "INFERRED",
    "prompt_sanitized": true,
    "created_at": "2026-09-22T15:20:12.746Z"
  }
]
```

`/api/security-gate`:

```json
[
  {
    "id": "GATE-Z5A4W9",
    "scan_id": "SCAN-JNKR36",
    "engagement_id": "ENG-R38T8X",
    "decision": "FAIL",
    "policy": {"fail_on": ["critical", "high"], "max_cvss": 7.0},
    "violations": [{"rule": "fail_on", "severity": "High", "count": 2}],
    "summary": "2 finding(s) at or above High severity.",
    "created_at": "2026-09-22T15:20:12.754699Z"
  }
]
```

`/api/benchmark` returns the measured metrics plus a `per_case` array with one entry per
ground-truth case (`case_id`, `outcome`, `detected`, `detail`). `/api/posture` returns
snapshots with `overall`, a `categories` object, a `contributors` array, an `explanation`
string and `methodology_version`. `/api/audit` returns entries with `action`, `actor`,
`target_ref` and a free-form `detail` object.

### `/api/scans/{scan_id}/sarif`

Builds a SARIF 2.1.0 document on demand from stored findings. The tool driver reports
`"name": "Velora"` with the package version, and each detecting check becomes a rule with
`shortDescription`, `fullDescription` and `help` (text and markdown). This is the same
document `velora report --format sarif` writes to disk, which is what GitHub code scanning
consumes.

```bash
curl http://127.0.0.1:8811/api/scans/SCAN-8ZEAJN/sarif
```

## Deployment notes

`api.host` defaults to `127.0.0.1` and `api.port` to `8787`. There is no authentication,
no session handling and no CSRF machinery, because there is nothing to authenticate against
and no state-changing route to protect. Keep it on loopback, or put it behind a reverse
proxy that terminates TLS and performs authentication.

`api.cors_allow_origins` exists in the settings model but the application registers no CORS
middleware, so the value currently has no effect.

The app opens one `Database` at factory time and constructs a fresh `Repository` per
request. `app.state.settings` and `app.state.db` are set for embedding.
