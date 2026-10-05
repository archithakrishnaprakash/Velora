# Differential analysis

Differential analysis compares a **baseline** exchange against a **candidate** exchange
produced by one controlled variation — a different identity, a changed parameter, a
removed cookie — and reports the structural differences between them.

It reports differences. It does not decide that a difference is a vulnerability. Every
result is stored with `validation_required = True`, and nothing in this subsystem can
create a `Confirmed` finding.

Source: `velora/differential/` (`fingerprint.py`, `engine.py`, `service.py`).

---

## Why it exists

A raw byte-diff of two HTTP responses is useless on a live application. Dates, request
IDs, CSRF tokens, nonces and session cookies change on every response, so a naive
comparison reports a difference every time and the operator learns nothing.

The subsystem solves that in two stages:

1. **Normalize** each response into a `ResponseFingerprint` that captures its *shape*
   and deliberately discards values that legitimately vary.
2. **Compare** two fingerprints field by field, emitting a classified `Difference` for
   each real change, with a confidence score that says how reliable the *observation*
   is — not how bad it is.

The module docstring in `velora/differential/__init__.py` states the design rule
directly: *a difference is not a vulnerability.*

---

## Data model

### `ResponseFingerprint`

Defined in `velora/differential/fingerprint.py`. Built from a `HttpResponse` by
`fingerprint_response()`.

| Field | Type | What it holds |
|---|---|---|
| `url` | `str` | Requested URL. Recorded but never compared. |
| `method` | `str` | HTTP method. Recorded but never compared. |
| `status_code` | `int` | Response status. |
| `content_type` | `str` | Normalized content type from the response. |
| `header_names` | `list[str]` | Sorted lowercase header names, **excluding** `VOLATILE_HEADERS`. |
| `security_headers` | `dict[str, str]` | Lowercase name → value, restricted to `SECURITY_HEADERS`. |
| `cookie_names` | `list[str]` | Sorted names parsed from `Set-Cookie`. |
| `cookie_flags` | `dict[str, list[str]]` | Per-cookie sorted attribute names (e.g. `httponly`, `secure`), lowercased, values dropped. |
| `redirect_target` | `str` | `Location` reduced to `scheme://netloc/path` (query and fragment dropped). |
| `size_bucket` | `int` | Index into `_SIZE_BUCKETS`. |
| `response_size` | `int` | Raw byte count. |
| `timing_bucket` | `int` | Index into `_TIME_BUCKETS`. |
| `body_kind` | `str` | One of `json`, `html`, `text`, `empty`, `other`. |
| `body_shape` | `list[str]` | Structure descriptors; meaning depends on `body_kind`. |
| `body_hash` | `str` | First 32 hex chars of SHA-256 over the **normalized** body. |
| `auth_challenge` | `bool` | True when `WWW-Authenticate` is present or the status is 401/403. |
| `error` | `str \| None` | Transport error, if the exchange failed. |

`to_dict()` truncates `body_shape` to the first 200 entries for storage. Comparison uses
the full list.

### `Difference`

One classified change. Fields: `classification` (a `DiffClassification`), `field_name`,
`baseline`, `candidate`, `note`.

`to_dict()` passes `baseline` and `candidate` through `_safe()`, which:

- runs strings through `redact_text()` and truncates to 400 characters,
- truncates lists and tuples to 25 items,
- truncates dicts to 25 entries,
- recurses into each of the above.

This is why a secret that appears only in the candidate body cannot reach stored
evidence through a JSON-shape difference.

### `DifferentialResult`

Holds `baseline`, `candidate`, `differences`, `confidence`, `interpretation`,
`validation_required`, plus three derived properties:

| Property | Meaning |
|---|---|
| `classifications` | De-duplicated classification values, in first-seen order. |
| `changed` | `True` when `differences` is non-empty. |
| `indicates_access_change` | `True` when any difference is `AUTHORIZATION_BEHAVIOR_CHANGE`, `STATUS_CHANGE` or `REDIRECT_CHANGE`. |

### `DifferentialObservation`

The persisted record, defined in `velora/models/domain.py`. ID prefix `DIFF`.

| Field | Notes |
|---|---|
| `id`, `created_at` | Generated. |
| `scan_id`, `engagement_id` | Optional anchors. |
| `label` | From `--label`, else `"<baseline label> vs <candidate label>"`. |
| `baseline_url`, `candidate_url`, `baseline_method`, `candidate_method` | From the `ExchangeSpec`s. |
| `baseline_fingerprint`, `candidate_fingerprint` | The `to_dict()` payloads. |
| `differences`, `classifications`, `confidence`, `interpretation` | Copied from the result. |
| `validation_required` | Hard-coded `True` at persistence time in `DifferentialService.persist()`. |
| `evidence_ids` | Populated only when a `scan_id` was supplied. |

---

## Normalization

### Volatile headers

`VOLATILE_HEADERS` names the headers removed from `header_names` before comparison:

```
date, expires, last-modified, etag, age, x-request-id, x-correlation-id,
x-trace-id, x-runtime, x-amzn-requestid, x-amz-cf-id, cf-ray, report-to,
keep-alive, content-length, set-cookie, nel, server-timing
```

`content-length` is excluded because it is a function of body size, which is compared
separately. `set-cookie` is excluded from the *name* set because cookies get their own
dedicated comparator.

### Security headers

`SECURITY_HEADERS` names the headers whose **values** are compared, not just their
presence:

```
content-security-policy, strict-transport-security, x-frame-options,
x-content-type-options, referrer-policy, permissions-policy,
access-control-allow-origin, access-control-allow-credentials,
www-authenticate, cache-control, location, content-type
```

`location` and `content-type` are captured here but skipped by the header comparator,
because `_redirect()` and `_content_type()` handle them with their own classifications.

### Volatile body tokens

`normalize_body()` replaces each match of these patterns with the literal
`<VOLATILE>` before hashing or shape extraction:

| Pattern | Catches |
|---|---|
| `[0-9a-f]{8}-…-[0-9a-f]{12}` | UUIDs |
| `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}` | ISO-8601-ish timestamps |
| `csrf[_-]?token\s*[=:]\s*["']?[A-Za-z0-9_\-]{8,}` | CSRF tokens (case-insensitive) |
| `nonce\s*[=:]\s*["']?[A-Za-z0-9_\-]{8,}` | Nonces (case-insensitive) |
| `[0-9a-fA-F]{32,}` | Long hex blobs — session IDs, digests |

### Body shape

Shape extraction depends on the detected `body_kind`:

- **json** — chosen when the content type contains `json`, or the normalized body starts
  with `{` or `[`. `_json_shape()` walks the document and emits sorted `path:type`
  descriptors. Values are discarded; only paths and Python type names survive. Lists
  contribute `path[]:len=N` plus the shape of their first element. Recursion stops at
  depth 6 with a `<deep>` marker.
- **html** — chosen when the content type contains `html`, or `<html` appears in the
  first 2000 characters. `_html_skeleton()` parses with BeautifulSoup and emits per-tag
  counts (`div=12`), the `<title>` text truncated to 80 characters, and one descriptor
  per form: `form:<METHOD>:<action>:<comma-separated input names>`. Text content is
  ignored, so wording changes are not differences. A parse failure returns an empty
  skeleton rather than raising.
- **text** — fallback: `["lines=N", "words=M"]`.
- **empty** — a blank or whitespace-only body. `body_hash` is left empty and the
  function returns early.

### Buckets

Small deltas are absorbed by bucketing. `_bucket()` returns the index of the highest
edge that the value reaches or exceeds.

| Buckets | Edges |
|---|---|
| `_SIZE_BUCKETS` (bytes) | 0, 256, 1024, 4096, 16384, 65536, 262144 |
| `_TIME_BUCKETS` (ms) | 0, 50, 150, 500, 1500, 5000 |

---

## Comparison algorithm

`DifferentialEngine.compare()` runs the comparators in a fixed order — status, headers,
cookies, redirect, content type, body, and timing unless `ignore_timing` is set — then
scores and interprets the collected differences.

| Comparator | Emits | Condition |
|---|---|---|
| `_status` | `AUTHORIZATION_BEHAVIOR_CHANGE` | Status crossed an allow/deny boundary: 401/403 → 2xx, or 2xx → 401/403. |
| `_status` | `STATUS_CHANGE` | Any other status difference. |
| `_headers` | `HEADER_CHANGE` (`header_names`) | The non-volatile header name sets differ. `baseline` carries removed names, `candidate` carries added names. |
| `_headers` | `HEADER_CHANGE` (`header:<name>`) | A `SECURITY_HEADERS` value differs, excluding `location` and `content-type`. |
| `_cookies` | `COOKIE_CHANGE` (`cookie_names`) | The sorted cookie-name lists differ. |
| `_cookies` | `COOKIE_CHANGE` (`cookie_flags:<name>`) | A cookie present in both has different attributes. |
| `_redirect` | `REDIRECT_CHANGE` | `redirect_target` differs. |
| `_content_type` | `CONTENT_TYPE_CHANGE` | `content_type` differs. |
| `_body` | `BODY_STRUCTURE_CHANGE` (`body_kind`) | The body kinds differ. Returns immediately — no further body comparison is attempted. |
| `_body` | `JSON_FIELD_CHANGE` | Both are `json` and the shape sets differ. |
| `_body` | `BODY_STRUCTURE_CHANGE` (`html_skeleton`) | Both are `html` and the skeleton sets differ. Added/removed lists are truncated to 20 entries. |
| `_body` | `CONTENT_CHANGE` | `body_hash` differs **and no other body difference was found** — same structure, different normalized content. If the size buckets also differ, that is appended to the note. |
| `_timing` | `TIMING_CHANGE` | `abs(baseline.timing_bucket - candidate.timing_bucket) >= 2`. A one-bucket shift is treated as noise and never reported. |

Some fingerprint fields are recorded but never compared: `url` and `method` (the caller
chose them) and `auth_challenge` (computed and serialized, but read by no comparator).
`size_bucket` never produces a difference on its own — it only decorates a
`CONTENT_CHANGE` note.

### Confidence

`_confidence()` answers "how likely is it that this difference is real rather than
noise?" It is explicitly **not** a severity or exploitability score.

- No differences → `0.0`.
- Either fingerprint carries a transport `error` → `0.2`, because a failed exchange
  makes the whole comparison unreliable. This check runs before the weight table, so a
  transport error caps the score regardless of what was classified.
- Otherwise: the **maximum** weight across the observed differences.

| Classification | Weight |
|---|---|
| `AUTHORIZATION_BEHAVIOR_CHANGE` | 0.95 |
| `STATUS_CHANGE` | 0.90 |
| `REDIRECT_CHANGE` | 0.85 |
| `JSON_FIELD_CHANGE` | 0.80 |
| `COOKIE_CHANGE` | 0.75 |
| `BODY_STRUCTURE_CHANGE` | 0.70 |
| `CONTENT_TYPE_CHANGE` | 0.70 |
| `HEADER_CHANGE` | 0.60 |
| `CONTENT_CHANGE` | 0.45 |
| `TIMING_CHANGE` | 0.25 |
| anything unmapped | 0.40 |

Timing sits at 0.25 because it is a weak signal on shared infrastructure. That is also
why `AuthzRunner` constructs its engine with `ignore_timing=True`.

### Interpretation

`_interpret()` produces one factual sentence. It has exactly three shapes:

- **No differences** — "No structural difference observed between baseline and
  candidate. This does not prove equivalent behaviour." The second sentence is the
  point: absence of a structural difference is not evidence of equivalent behaviour,
  and the engine refuses to imply otherwise.
- **Transport error** — "One or both exchanges failed at the transport layer; the
  comparison is unreliable and should be repeated."
- **Differences present** — a count and the classification list, followed by either the
  access-boundary sentence (when `indicates_access_change` is true) which labels the
  result an "INDICATOR only", or a sentence stating that structural differences "do not
  by themselves indicate a security weakness".

`validation_required` is then set to `True` unconditionally, on every result, in both
`compare()` and `DifferentialService.persist()`.

### `DiffClassification` reference

Defined in `velora/models/enums.py`.

| Value | Emitted by |
|---|---|
| `NO_CHANGE` | Nothing. The enum member exists; the engine never produces it. A no-difference result carries an empty `differences` list. |
| `STATUS_CHANGE` | `_status` |
| `HEADER_CHANGE` | `_headers` |
| `COOKIE_CHANGE` | `_cookies` |
| `REDIRECT_CHANGE` | `_redirect` |
| `CONTENT_TYPE_CHANGE` | `_content_type` |
| `CONTENT_CHANGE` | `_body` |
| `BODY_STRUCTURE_CHANGE` | `_body` |
| `JSON_FIELD_CHANGE` | `_body` |
| `TIMING_CHANGE` | `_timing` |
| `AUTHORIZATION_BEHAVIOR_CHANGE` | `_status` |

---

## Capture and persistence

`DifferentialService` (`velora/differential/service.py`) owns live capture and storage.

`capture()` issues one request through the scope-gated `SafeHTTPClient`. A
`ScopeViolation` is caught, logged at SECURITY level as
`DIFFERENTIAL_EXCHANGE_BLOCKED`, and turned into `None` — the comparison is abandoned
rather than completed with a missing side.

`run()` captures both sides, and returns `(None, None)` if either was blocked. Otherwise
it compares and, when `persist=True` (the default), writes a `DifferentialObservation`.

`persist()` additionally:

- creates an `EvidenceItem` named `differential.compare` **only when a `scan_id` was
  supplied**, and stores its record ID in `evidence_ids`,
- writes an `AuditLog` entry with `action="differential_observed"` carrying the
  classifications, confidence and `changed` flag.

---

## CLI

All commands below were run against the local lab fixture
(`tests/fixtures/labapp.py`) on `127.0.0.1:8099`.

```
velora diff --help
```

```
Commands:
  compare  Fetch a baseline and a candidate exchange, then classify the...
  create   Fetch a baseline and a candidate exchange, then classify the...
  list     List stored differential observations.
  show     Show a stored differential observation.
```

`compare` and `create` are the same function registered twice: running a comparison is
what *creates* the stored observation, so there is no separate create step.

### `velora diff compare`

| Option | Meaning |
|---|---|
| `--baseline TEXT` | Baseline URL. Required. |
| `--candidate TEXT` | Candidate URL. Required. |
| `--method TEXT` | HTTP method, applied to **both** exchanges. Default `GET`. |
| `--baseline-header TEXT` | `'Name: value'` header for the baseline request. Repeatable. |
| `--candidate-header TEXT` | `'Name: value'` header for the candidate request. Repeatable. |
| `--label TEXT` | Label stored with the observation. |
| `--scan TEXT` | Attach to an existing scan ID. Required for evidence to be written. |
| `--scope TEXT` | Additional in-scope domain. Repeatable. |
| `--allow-private` | Permit private/loopback targets (lab). |
| `--ignore-timing` | Ignore response-timing differences. |
| `--json` | Emit the full result as JSON. |
| `--i-am-authorized` | Required. Without it the command refuses to send anything. |

The ad-hoc scope policy built for this command caps the run at 20 requests.

### `velora diff list`

Takes an optional `--scan TEXT`. Columns: `ID`, `LABEL`, `CONF`, `CLASSIFICATIONS`,
`NEEDS REVIEW`.

### `velora diff show`

Takes a `DIFFERENTIAL_ID` argument and an optional `--json` flag.

---

## Worked example

Traced end to end against the lab fixture. `/api/profile` returns 401 to an
unauthenticated request and 200 with the profile to an authenticated one.

```
velora diff compare \
  --baseline  http://127.0.0.1:8099/api/profile \
  --candidate http://127.0.0.1:8099/api/profile \
  --candidate-header 'Authorization: Bearer alice-token' \
  --label "profile anon vs alice" \
  --allow-private --i-am-authorized
```

```
Differential: http://127.0.0.1:8099/api/profile  ->  http://127.0.0.1:8099/api/profile
observation: DIFF-2KP2KM
baseline  : 401 application/json (24B)
candidate : 200 application/json (42B)
confidence: 0.95   validation_required: True

Differences
CLASSIFICATION                 FIELD        NOTE
AUTHORIZATION_BEHAVIOR_CHANGE  status_code  response crossed an allow/deny boundary
JSON_FIELD_CHANGE              json_shape   1 field(s) absent / 2 field(s) added in candidate

Interpretation
2 difference(s) observed: AUTHORIZATION_BEHAVIOR_CHANGE, JSON_FIELD_CHANGE. The candidate
response crossed an access-behaviour boundary relative to the baseline. This is an
INDICATOR only — it requires manual validation and does not by itself establish an
authorization flaw.
```

What produced each line:

- The baseline body is `{"error":"unauthorized"}`, so `body_shape` is `["error:str"]`.
  The candidate body is `{"user":"alice","email":"alice@lab.local"}`, so its shape is
  `["email:str", "user:str"]`. The set difference is one removed and two added — exactly
  the note text.
- `401 → 200` satisfies `crossed_access_boundary`, so `_status` emits
  `AUTHORIZATION_BEHAVIOR_CHANGE` rather than the generic `STATUS_CHANGE`.
- Confidence is `max(0.95, 0.80) = 0.95`.
- Both responses are 24 B and 42 B, which fall in size bucket 0 (< 256), so no size
  signal appears.
- `auth_challenge` is `true` on the baseline and `false` on the candidate in the JSON
  output, but it contributes nothing to the differences — no comparator reads it.

The important part is the interpretation. The engine observed a real, reproducible
behavioural difference and still refused to call it an authorization flaw. That
`/api/profile` correctly rejects anonymous callers is exactly what this difference looks
like — the difference is the *control working*. Only a human who knows the intended
access model can tell the two cases apart, which is why `validation_required` stays
`True`.

A contrasting run on the same fixture, comparing Alice's own order against Bob's view of
it, returns `confidence: 0.00` and "no structural difference observed" — because the lab
app's missing ownership check makes the two responses byte-identical. A no-difference
result is data, not a clean bill of health.

---

## What this subsystem does not claim

- **It never asserts exploitability.** No code path produces a `Confirmed` finding, a
  severity, or a CVSS-style score. The unit suite pins this: the interpretation for a
  403 → 200 comparison must contain "indicator" and must not contain "vulnerable" or
  "confirmed".
- **It never claims equivalence.** A zero-difference result explicitly says "This does
  not prove equivalent behaviour."
- **Confidence is not severity.** It measures observation reliability. A transport error
  hard-caps it at 0.2 precisely so a broken measurement cannot look like a strong
  signal.
- **It does not interpret timing.** A timing shift is reported at weight 0.25 and only
  after a two-bucket move, and callers that know their infrastructure is noisy disable
  it entirely.
- **It is not a crawler or a fuzzer.** The caller supplies both exchanges. The engine
  compares exactly the two it is given.

---

## Behaviour worth knowing

- `indicates_access_change` is true for **any** `STATUS_CHANGE`, not only the allow/deny
  transitions that `_status` classifies as `AUTHORIZATION_BEHAVIOR_CHANGE`. A plain
  200 → 500 comparison therefore produces the "crossed an access-behaviour boundary"
  sentence even though the engine deliberately declined to classify it as an
  authorization change. Read the classification list, not the prose, when triaging.
- `_parse_cookies()` splits multiple `Set-Cookie` values on `\n`, but the HTTP client
  collapses repeated headers with `, ` (httpx behaviour). Two cookies in one response
  are therefore parsed as one: the second name is absorbed into the first cookie's flag
  list. Single-cookie responses are parsed correctly.
- `--scan` is not optional bookkeeping. Without it, `persist()` skips evidence creation
  entirely and `evidence_ids` stays empty, though the observation itself is still
  stored.

---

## How it is tested

`tests/unit/test_differential.py` — 16 tests, no network, built on synthetic
`HttpResponse` objects.

`TestFingerprint` covers normalization:

- volatile headers (`Date`, `ETag`, `X-Request-Id`) are dropped while a custom header
  survives,
- two JSON bodies with identical structure and different values produce the same
  `body_shape`,
- two HTML bodies with identical markup and different text produce the same
  `body_shape`,
- cookie names and lowercase flags are captured.

`TestDifferentialEngine` covers the comparison and, more importantly, the restraint:

| Test | What it pins |
|---|---|
| `test_identical_responses_produce_no_difference` | Confidence 0.0 **and** the interpretation contains "does not prove". |
| `test_volatile_content_is_not_a_difference` | Two responses differing only in a UUID and a `Date` header compare as unchanged. |
| `test_deny_to_allow_flagged_as_authorization_behavior_change` | 403 → 200 yields the specific classification and confidence ≥ 0.9. |
| `test_plain_status_change_is_not_authorization_change` | 200 → 500 must **not** be classified as an authorization change. |
| `test_json_field_addition_detected` | Adding `is_admin` to a JSON body is caught. |
| `test_cookie_change_detected`, `test_redirect_change_detected` | Cookie and `Location` comparators fire. |
| `test_transport_error_lowers_confidence` | Confidence ≤ 0.3 and the interpretation contains "unreliable". |
| `test_validation_always_required` | `validation_required` is true. |
| `test_interpretation_never_asserts_vulnerability` | The text contains "indicator" and contains neither "vulnerable" nor "confirmed". |
| `test_secrets_redacted_in_serialized_result` | An `sk_live_…` key present only in the candidate body does not survive into `to_dict()`. |
| `test_ignore_timing_option` | With `ignore_timing=True`, a 1 ms vs 9000 ms pair emits no `TIMING_CHANGE`. |

Run them with:

```
python -m unittest tests.unit.test_differential
```

The last three tests are the ones that encode the project's principle. They assert what
the engine must *not* say, which is harder to preserve under change than what it must
say.
