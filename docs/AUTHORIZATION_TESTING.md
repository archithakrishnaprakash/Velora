# Authorization testing

Authorization testing builds a matrix of *identity × resource* requests, declares what
the operator **expects** each cell to do, executes every cell as an ordinary scope-gated
request, and compares expectation against observation.

It does not escalate privileges and it does not exploit anything. It issues configured
requests as configured identities and records what came back. Weaknesses become
`Potential` findings; a human moves them further.

Source: `velora/authz/` (`identity.py`, `matrix.py`, `runner.py`, `plan_io.py`,
`service.py`).

---

## Why it exists

Broken access control is a *relational* defect: a response is only wrong relative to who
asked for it and what they were supposed to be allowed to see. A single-identity scanner
cannot see it, because a 200 is a perfectly normal response — it is only interesting when
the identity that received it should have been denied.

That requires three things the framework makes explicit:

1. **Multiple identities**, whose credentials are supplied safely.
2. **A declared expectation** per identity/resource pair. Without it there is no ground
   truth and nothing can be judged.
3. **A conservative mapping from expectation + observation to outcome**, which prefers
   `INCONCLUSIVE` over a guess.

---

## Safety properties

These are stated in `velora/authz/__init__.py` and enforced in code:

- Credentials are never stored, logged, or reported. An `Identity` holds only a
  `secret_ref` — the *name* of an environment variable. The value is read at request time
  and discarded.
- Every request goes through the scope-gated `SafeHTTPClient`.
- Nothing attempts privilege escalation or exploitation.
- Weaknesses are created as `Potential` findings requiring human validation. The
  framework never self-confirms an authorization weakness.

---

## Data model

### `Identity` (`velora/models/domain.py`)

ID prefix `IDENT`.

| Field | Notes |
|---|---|
| `name` | Required. Must be unique within a plan; resources reference owners by name. |
| `role` | An `IdentityRole`. Default `ANONYMOUS`. |
| `description` | Free text. |
| `secret_ref` | The **name** of an environment variable, e.g. `VELORA_IDENTITY_ALICE`. Never the value. |
| `auth_scheme` | `bearer`, `header`, `cookie` or `none`. Default `bearer`. |
| `auth_header_name` | Header used by the `bearer` and `header` schemes. Default `Authorization`. |
| `owned_resource_hints` | Loaded from the plan; not consumed by the matrix builder or runner. |
| `engagement_id`, `created_at` | Set by the CLI / generated. |

### `IdentityRole`

| Value | `privilege_rank` |
|---|---|
| `anonymous` | 0 |
| `user_a` | 1 |
| `user_b` | 1 |
| `privileged_user` | 2 |
| `admin` | 3 |

`user_a` and `user_b` share rank 1 deliberately: they are peers, which is what makes a
horizontal (cross-account) test meaningful.

### `ResourceSpec` (`velora/authz/matrix.py`)

A dataclass, not a persisted model.

| Field | Meaning |
|---|---|
| `url` | Required. |
| `method` | Default `GET`. |
| `name` | Display label. Falls back to `"<METHOD> <url>"`. |
| `owner` | Identity **name** that legitimately owns this resource. Drives horizontal tests. |
| `requires_role` | Minimum `IdentityRole` needed to reach it. Drives vertical tests. |
| `expectations` | `{identity_name: "ALLOW" \| "DENY" \| "UNKNOWN"}` overrides. |

### `AuthzCase` and `AuthzMatrix`

`AuthzCase` is one cell: `identity`, `resource`, `expected`, and the `rationale` string
explaining how the expectation was derived. `AuthzMatrix` holds the case list and
supports `len()` and `for_resource(url)`.

### `AuthzTestResult` (`velora/authz/runner.py`)

What executing a cell produced: `case`, `observed`, `outcome`, `status_code`,
`response_size`, `reason`, an optional `differential` (`DifferentialResult`),
`identity_summary`, and `error`.

### `AuthorizationTest` (`velora/models/domain.py`)

The persisted row. ID prefix `AUTHZ`.

| Field | Notes |
|---|---|
| `scan_id`, `engagement_id`, `plan_id` | Anchors. `plan_id` is never set by the CLI. |
| `identity_id` | The `Identity.id`. |
| `identity_role` | Copied from the identity. |
| `resource_owner_identity_id` | Set from `ResourceSpec.owner`, which is an identity **name**, not an ID. |
| `url`, `method` | The tested request. |
| `expected`, `observed`, `outcome` | The three enums below. |
| `status_code`, `response_size` | From the response. |
| `differential_id` | Never populated by `AuthorizationTestingService`. |
| `evidence_ids` | Populated only when the run had a scan to anchor to. |
| `notes` | `"<observation reason>; <outcome reason>"`. |

### The three enums

`AccessExpectation` — what the operator declared should happen.

| Value | Meaning |
|---|---|
| `ALLOW` | This identity should reach the resource. |
| `DENY` | This identity should be refused. |
| `UNKNOWN` | Not declared. No judgement will be made. |

`AccessObservation` — what actually happened.

| Value | Meaning |
|---|---|
| `GRANTED` | The response looks like the resource. |
| `DENIED` | The response is an explicit refusal or a sign-in surface. |
| `INCONCLUSIVE` | The response does not decide the question. |
| `ERROR` | Transport failure, scope block, or exhausted request budget. |

`AuthzOutcome` — the comparison of the two. `is_weakness` is true for everything except
`AS_EXPECTED` and `INCONCLUSIVE`.

| Value | Weakness | Meaning |
|---|---|---|
| `AS_EXPECTED` | no | Expectation and observation agree. |
| `HORIZONTAL_AUTHORIZATION_WEAKNESS` | yes | A non-owner reached an owned resource. |
| `VERTICAL_AUTHORIZATION_WEAKNESS` | yes | An identity below the required rank reached the resource. |
| `UNAUTHENTICATED_ACCESS` | yes | An anonymous identity reached a resource expected to be protected. |
| `PRIVILEGE_BOUNDARY_WEAKNESS` | yes | Access granted where the plan expected denial, with no more specific class available. |
| `INCONCLUSIVE` | no | No judgement is possible. |

---

## Identity resolution

`IdentityResolver` (`velora/authz/identity.py`) turns an `Identity` into request headers
using the environment. The environment dict is injectable, which is how the tests avoid
touching real process state.

`available(identity)` returns true for an anonymous identity or an identity whose
`auth_scheme` is `none`; otherwise it requires both a `secret_ref` and a non-empty value
for it in the environment. This is what the `CREDENTIAL` column of `velora authz plan`
reports, without ever reading the value into output.

`resolve(identity, strict=...)` builds the headers:

| `auth_scheme` | Headers produced |
|---|---|
| `bearer` | `{auth_header_name: "Bearer <secret>"}` |
| `header` | `{auth_header_name: "<secret>"}` |
| `cookie` | `{"Cookie": "<secret>"}` |
| `none` | `{}` |

An unrecognised scheme raises `ValueError`. Anonymous identities and `none` return empty
headers with `resolved=True`.

### Why `strict` matters

When a credential is missing, the non-strict path logs a warning naming only the
*variable*, and returns a `ResolvedIdentity` with empty headers, `resolved=False`, and a
`reason` explaining why.

That degraded identity is still executed — as an unauthenticated request. If the
operator does not notice, a misconfigured run reads as "anonymous could reach
everything", which is a fabricated result. `strict=True` raises `MissingCredentialError`
instead, and `velora authz run --strict` surfaces it as a clean CLI error and marks the
scan `FAILED`:

```
Error: environment variable 'VELORA_IDENTITY_BOB' is not set for identity 'bob'
```

`--strict` is documented in the CLI as "recommended" for exactly this reason.

### `ResolvedIdentity.safe_summary()`

`ResolvedIdentity.headers` may hold a live credential, so the object is never persisted
or logged. Anything recorded goes through `safe_summary()`, which emits
`identity_id`, `name`, `role`, `authenticated` (a bool derived from whether any headers
exist), `auth_scheme`, `header_names` (names only), `secret_ref`, `resolved` and
`reason`. Header *names* and the variable *name* are safe; neither the header value nor
the variable value appears.

---

## Building the matrix

`build_matrix(identities, resources)` is the full cross product: every identity against
every resource, in resource-major order. Each cell calls `expectation_for()`.

### How expectation is resolved

`expectation_for(identity, resource)` applies four rules in order and returns the first
that matches, together with a rationale string.

1. **Explicit override.** If `resource.expectations[identity.name]` exists and parses as
   an `AccessExpectation`, use it — rationale `"explicit expectation from plan"`. An
   unparseable value falls through to the derivation rules rather than raising.
2. **Ownership** (`resource.owner` is set):
   - the owner itself → `ALLOW`, *"identity owns this resource"*;
   - an `anonymous` identity → `DENY`, *"anonymous access to an owned resource"*;
   - an identity whose `privilege_rank` is **greater than** `USER_A`'s (that is,
     `privileged_user` or `admin`) → `UNKNOWN`, *"higher-privilege identity may
     legitimately access this resource; declare an explicit expectation to test it"*;
   - anything else — a same-privilege peer → `DENY`, *"cross-account access by a
     same-privilege identity"*.
3. **Required role** (`resource.requires_role` is set): rank at or above the requirement
   → `ALLOW`; below it → `DENY`.
4. **Nothing declared** → `UNKNOWN`, *"no ownership or required role declared"*.

The third clause of rule 2 is the most important line in the module. An administrator
reading another user's order is, in most applications, correct behaviour. A tool that
assumed `DENY` there would generate a confident high-severity false positive on every
well-built admin panel it ever saw. Instead the matrix returns `UNKNOWN` and tells the
operator how to make it testable — declare the expectation explicitly. The framework
will not judge what the operator did not declare.

Rules 2 and 3 are mutually exclusive in practice: a resource with an `owner` never
reaches the `requires_role` branch, because every ownership case returns.

---

## Plan files

`velora/authz/plan_io.py` loads a YAML plan into `(identities, resources)`.

```yaml
identities:
  - name: anonymous
    role: anonymous

  - name: alice
    role: user_a
    secret_ref: VELORA_IDENTITY_ALICE
    auth_scheme: bearer          # bearer | header | cookie | none

resources:
  - name: alice's order
    url: http://127.0.0.1:8099/api/orders/1
    method: GET
    owner: alice

  - name: admin console
    url: http://127.0.0.1:8099/admin/console
    method: GET
    requires_role: admin

  - name: public health endpoint
    url: http://127.0.0.1:8099/api/public
    method: GET
    expectations:
      anonymous: ALLOW
```

### Credentials cannot be written into a plan

`_check_no_secrets()` walks the parsed YAML recursively before anything else happens and
refuses any mapping key in `FORBIDDEN_KEYS`:

```
password, secret, token, api_key, credential, cookie_value
```

The refusal names the path and explains the alternative:

```
ConfigError: plan contains a forbidden key 'token' at identities[0]. Credentials must be
supplied via an environment variable named by 'secret_ref', never written into the plan
file.
```

This is a structural guarantee rather than a convention: a plan file that would leak a
credential into version control cannot be loaded at all.

### Other validation

`load_plan` raises `ConfigError` for a missing file, invalid YAML, a non-mapping root, an
identity without `name`, a resource without `url`, an invalid `role` or `requires_role`
(the message lists the valid values), a non-mapping `expectations`, an empty identity or
resource list, duplicate identity names, and an `owner` that is not a defined identity.

Defaults applied while parsing: `method` is upper-cased and defaults to `GET`;
`auth_scheme` defaults to `none` for an anonymous role and `bearer` otherwise;
`auth_header_name` defaults to `Authorization`.

---

## Execution

`AuthzRunner.run()` (`velora/authz/runner.py`) makes two passes over the matrix.

**Pass 1 — owner baselines.** For every case where the identity *is* the resource owner,
fetch the resource and, if the response has no transport error, store it as the baseline
for that URL. Each identity is resolved once and cached.

**Pass 2 — every cell.** Fetch each cell. Then:

- Classify the response with `classify_observation()`.
- If an owner baseline exists for the URL, the identity is **not** the owner, and the
  observation is `GRANTED`, compare the two responses with a `DifferentialEngine`
  constructed with `ignore_timing=True`. If the comparison finds **no** difference,
  append to the reason: *"response is structurally identical to the owner's response
  (strong cross-account signal)"*.
- Classify the outcome with `classify_outcome()`.

The differential step is what separates a meaningful cross-account result from a bare
`200`. Bob receiving *the same bytes Alice receives* is a far stronger statement than
Bob receiving some `200`.

A `ScopeViolation` is logged at SECURITY level as `AUTHZ_REQUEST_BLOCKED` and a
`RateLimitExceeded` stops the run with a warning; both produce `None`, and the cell is
recorded as `observed=ERROR`, `outcome=INCONCLUSIVE`, `error="blocked"`. A blocked
request never becomes evidence of anything.

### `classify_observation()`

Evaluated in this order:

| Condition | Result | Reasoning |
|---|---|---|
| `resp.error` set | `ERROR` | Nothing was measured. |
| 401, 403 | `DENIED` | Explicit refusal. |
| 404, 410 | `INCONCLUSIVE` | Could be genuinely absent, or a deliberate "hide it" response. Either way it is **not a grant**. |
| 5xx | `INCONCLUSIVE` | A server error says nothing about the access decision. |
| 3xx with a `Location` matching `/(login\|signin\|sign-in\|auth\|account/login)` | `DENIED` | Redirected to a sign-in surface. |
| any other 3xx | `INCONCLUSIVE` | The redirect target is not recognisable as a decision. |
| 2xx whose body matches a denial marker | `DENIED` | "status 200 but the body is a sign-in/denial surface". |
| any other 2xx | `GRANTED` | |
| anything else | `INCONCLUSIVE` | Unhandled status. |

The denial markers are three regexes: a `<form>` tag whose attributes mention
login/signin/sign-in; prose such as "please log in", "sign in to continue", "access
denied", "not authorized/authorised", "permission denied", "forbidden"; and a JSON
`"error": "unauthorized|forbidden|access denied"` pair.

Two of these rows are the interesting ones. A 404 is not treated as a denial, because
hiding a resource is not the same as refusing access to it. And a 200 that renders a
login page is not treated as a grant, because applications routinely answer
unauthenticated requests with a sign-in page and HTTP 200. Both rules exist to stop the
status code alone from deciding the question.

### `classify_outcome()`

Evaluated in this order:

| Condition | Outcome |
|---|---|
| `expected == UNKNOWN` | `INCONCLUSIVE` — *"no expectation was declared for this pair, so no judgement is made"*. |
| `observed` is `ERROR` or `INCONCLUSIVE` | `INCONCLUSIVE` — *"observation was not decisive"*. |
| `expected == ALLOW` and `observed == GRANTED` | `AS_EXPECTED` |
| `expected == ALLOW` and observation says denied | `INCONCLUSIVE` — *"expected ALLOW but access was denied — check the identity's credential or the expectation; this is not treated as a security weakness"*. |
| `expected == DENY` and `observed == DENIED` | `AS_EXPECTED` |
| `expected == DENY`, granted, identity role is `anonymous` | `UNAUTHENTICATED_ACCESS` |
| `expected == DENY`, granted, resource has an `owner` that is not this identity | `HORIZONTAL_AUTHORIZATION_WEAKNESS` |
| `expected == DENY`, granted, identity rank below `requires_role` | `VERTICAL_AUTHORIZATION_WEAKNESS` |
| `expected == DENY`, granted, none of the above | `PRIVILEGE_BOUNDARY_WEAKNESS` |

Three of these rows exist specifically to *avoid* claiming a weakness.

- **`UNKNOWN` expectation → `INCONCLUSIVE`, always.** It is checked first, before the
  observation is even looked at. A granted request against an undeclared resource cannot
  become a finding, no matter how it looks.
- **Indecisive observation → `INCONCLUSIVE`.** A 404, a 500 or a transport failure never
  becomes a weakness, because the framework did not measure an access decision.
- **Expected ALLOW but denied → `INCONCLUSIVE`, with the reason saying so explicitly.**
  A broken token, an expired session or a wrong expectation produces exactly this
  pattern. Reporting it as a security weakness would be reporting the tester's own
  misconfiguration as the target's defect.

The ordering matters as much as the rules. Because the anonymous check precedes the
ownership check, an anonymous identity reaching an owned resource is reported as
`UNAUTHENTICATED_ACCESS` rather than a horizontal weakness — the more fundamental
failure wins.

---

## Recording results

`AuthorizationTestingService.record()` (`velora/authz/service.py`) converts runner
results into rows, evidence, and findings.

For each result it writes an `AuthorizationTest` row. When a `scan_id` exists it first
persists an `EvidenceItem` named `authz.matrix` whose request payload carries the
identity **summary** — never headers, never credentials — and whose excerpt is
`expected=… observed=… outcome=…: <reason>`.

Weaknesses (`outcome.is_weakness`) additionally produce a `Finding`, but only when
`create_findings` is true **and** a scan exists.

### Confidence

`_confidence_for()` scores how reliable the observation is, not how exploitable it is:

| Situation | `Confidence` |
|---|---|
| `observed != GRANTED` | `TENTATIVE` |
| A differential against the owner baseline exists and found **no** difference | `FIRM` |
| Status is 2xx | `FIRM` |
| Otherwise | `TENTATIVE` |

`Confidence.CERTAIN` is never assigned here. Reaching a resource is an observation about
behaviour, not a directly observable fact like a header literally being present, so the
service does not claim the top bucket.

### Finding profile

`_OUTCOME_PROFILE` maps each weakness class to a fixed severity, CWE, OWASP category,
title and remediation:

| Outcome | Severity | CWE | Title |
|---|---|---|---|
| `UNAUTHENTICATED_ACCESS` | High | CWE-306 | Unauthenticated access to a protected resource |
| `HORIZONTAL_AUTHORIZATION_WEAKNESS` | High | CWE-639 | Cross-account access to another user's resource |
| `VERTICAL_AUTHORIZATION_WEAKNESS` | High | CWE-269 | Privileged functionality reachable by a lower-privileged identity |
| `PRIVILEGE_BOUNDARY_WEAKNESS` | Medium | CWE-285 | Access granted where the assessment plan expected denial |

All four carry `A01:2021-Broken Access Control` and reference the OWASP Top 10 page.

Every finding is created with:

- `status = FindingStatus.POTENTIAL`,
- `validation_state = ValidationState.OBSERVED` — directly measured, not yet validated,
- `scanner = "authz.matrix"`, `category = "authorization"`,
- a description that names the identity, its role, the request, the expectation *and its
  rationale*, the observation, and closes with: *"This is an evidence-backed INDICATOR
  of an access-control gap and requires human validation before it is treated as
  confirmed."*

`compute_priority()` is then called with the severity and confidence above plus fixed
inputs `exposure=0.7`, `asset_importance=0.6`, `evidence_quality=confidence.score`, and
`unauthenticated=True` only for `UNAUTHENTICATED_ACCESS`.

Confirmation is a separate, human-only action: `velora finding validate <id> --operator
<name>` moves the finding's `status` from `Potential` to `Confirmed` and records
`validated_by` and `validation_note`. Nothing in the authorization subsystem can perform
that transition.

---

## CLI

Verified against the local lab fixture (`tests/fixtures/labapp.py`) on
`127.0.0.1:8099`, which contains two deliberately broken access controls and two correct
ones.

```
velora authz --help
```

```
Commands:
  compare  Show recorded expected-vs-observed access for every tested pair.
  init     Write a starter authorization plan file.
  plan     Build and display the identity x resource matrix without...
  report   Summarize authorization testing coverage and outcomes.
  run      Execute the authorization matrix and record the results.
```

### `velora authz init`

Writes the plan template. Option: `-o, --output PATH` (default `authz-plan.yaml`). It
refuses to overwrite an existing file.

### `velora authz plan`

Options: `--config PATH` (required), `--json`.

Builds and prints the matrix and **sends no requests**. Use it to check that the
expectations you get are the expectations you meant before anything touches the target.

```
velora authz plan --config authz-plan.yaml
```

```
Identities (4)
NAME       ROLE       SCHEME  SECRET REF             CREDENTIAL
anonymous  anonymous  none    (none)                 yes
alice      user_a     bearer  VELORA_IDENTITY_ALICE  yes
bob        user_b     bearer  VELORA_IDENTITY_BOB    yes
admin      admin      bearer  VELORA_IDENTITY_ADMIN  yes

Authorization matrix (12 cases)
IDENTITY   ROLE       METHOD  RESOURCE                             EXPECTED  WHY
anonymous  anonymous  GET     http://127.0.0.1:8099/api/orders/1   DENY      anonymous access to an owned resource
alice      user_a     GET     http://127.0.0.1:8099/api/orders/1   ALLOW     identity owns this resource
bob        user_b     GET     http://127.0.0.1:8099/api/orders/1   DENY      cross-account access by a same-privilege ident
admin      admin      GET     http://127.0.0.1:8099/api/orders/1   UNKNOWN   higher-privilege identity may legitimately acc
anonymous  anonymous  GET     http://127.0.0.1:8099/admin/console  DENY      identity rank below required role 'admin'
alice      user_a     GET     http://127.0.0.1:8099/admin/console  DENY      identity rank below required role 'admin'
bob        user_b     GET     http://127.0.0.1:8099/admin/console  DENY      identity rank below required role 'admin'
admin      admin      GET     http://127.0.0.1:8099/admin/console  ALLOW     identity meets the required role
anonymous  anonymous  GET     http://127.0.0.1:8099/api/public     ALLOW     explicit expectation from plan
alice      user_a     GET     http://127.0.0.1:8099/api/public     UNKNOWN   no ownership or required role declared
bob        user_b     GET     http://127.0.0.1:8099/api/public     UNKNOWN   no ownership or required role declared
admin      admin      GET     http://127.0.0.1:8099/api/public     UNKNOWN   no ownership or required role declared

No requests were sent. Run with:  velora authz run --config authz-plan.yaml --i-am-authorized
```

An identity whose credential is missing prints `MISSING` in the `CREDENTIAL` column and
triggers a warning that those identities would run unauthenticated.

### `velora authz run`

| Option | Meaning |
|---|---|
| `--config PATH` | Plan file. Required. |
| `--target TEXT` | Stored target id/name to attach the scan to. Optional — but see below. |
| `--scope TEXT` | Additional in-scope domain. Repeatable. |
| `--allow-private` | Permit private/loopback targets (lab). |
| `--operator TEXT` | Recorded on the scan. |
| `--engagement TEXT` | Engagement ID. |
| `--strict` | Fail if any identity's credential is missing. Recommended. |
| `--no-findings` | Record tests but do not create findings. |
| `--i-am-authorized` | Required. Without it the command refuses to send anything. |

The request budget is `max(50, len(matrix) * 3)`.

Identities are persisted before the run, matched by name: an existing identity of the
same name is reused (its stored ID is adopted) rather than duplicated.

**`--target` is load-bearing.** Without it no `Scan` row is created, and with no scan the
service writes no evidence and creates no findings. The run still executes and the
summary line still counts weaknesses, but nothing lands in the findings table. Verified:
the same plan run with and without `--target` prints identical result tables, and only
the `--target` run reports "3 Potential finding(s) created".

### `velora authz compare`

Options: `--scan TEXT`, `--json`. Prints one row per stored `AuthorizationTest` with its
expected, observed and outcome values. `--json` emits the full model dump of each row.

### `velora authz report`

Options: `--scan TEXT`, `--json`. Aggregates stored tests into counts by outcome, the
number of distinct resources, the roles covered, and a list of weaknesses with their
notes. Every rendering ends with:

```
Outcomes are evidence-backed indicators. A weakness is Potential until a human validates
it; 'AS_EXPECTED' does not prove the control is complete.
```

---

## Worked example

Run against the lab fixture with the plan shown above and all three tokens exported.

```
velora authz run --config authz-plan.yaml --target lab \
  --allow-private --operator docs --strict --i-am-authorized
```

```
IDENTITY   METHOD  RESOURCE                             EXPECTED  OBSERVED  OUTCOME                            CODE
anonymous  GET     http://127.0.0.1:8099/api/orders/1   DENY      DENIED    AS_EXPECTED                        401
alice      GET     http://127.0.0.1:8099/api/orders/1   ALLOW     GRANTED   AS_EXPECTED                        200
bob        GET     http://127.0.0.1:8099/api/orders/1   DENY      GRANTED   HORIZONTAL_AUTHORIZATION_WEAKNESS  200
admin      GET     http://127.0.0.1:8099/api/orders/1   UNKNOWN   GRANTED   INCONCLUSIVE                       200
anonymous  GET     http://127.0.0.1:8099/admin/console  DENY      DENIED    AS_EXPECTED                        401
alice      GET     http://127.0.0.1:8099/admin/console  DENY      GRANTED   VERTICAL_AUTHORIZATION_WEAKNESS    200
bob        GET     http://127.0.0.1:8099/admin/console  DENY      GRANTED   VERTICAL_AUTHORIZATION_WEAKNESS    200
admin      GET     http://127.0.0.1:8099/admin/console  ALLOW     GRANTED   AS_EXPECTED                        200
anonymous  GET     http://127.0.0.1:8099/api/public     ALLOW     GRANTED   AS_EXPECTED                        200
alice      GET     http://127.0.0.1:8099/api/public     UNKNOWN   GRANTED   INCONCLUSIVE                       200
bob        GET     http://127.0.0.1:8099/api/public     UNKNOWN   GRANTED   INCONCLUSIVE                       200
admin      GET     http://127.0.0.1:8099/api/public     UNKNOWN   GRANTED   INCONCLUSIVE                       200

cases=12  as_expected=5  weaknesses=3  inconclusive=4
WARN 3 Potential finding(s) created — all require human validation:
  WEB-224C46  [High] Cross-account access to another user's resource: alice's order
  WEB-7YSNB4  [High] Privileged functionality reachable by a lower-privileged identity: admin console
  WEB-E4ZD7J  [High] Privileged functionality reachable by a lower-privileged identity: admin console
```

Tracing four of these rows through the code:

**Row 3 (bob → alice's order).** `owner: alice` and bob is rank 1, so rule 2's last
clause gave `DENY`. The lab app returns the order with no ownership check, so
`classify_observation` saw a 2xx with no denial marker and returned `GRANTED`.
`classify_outcome` reached the ownership branch and returned
`HORIZONTAL_AUTHORIZATION_WEAKNESS`. Pass 1 had captured Alice's own response as the
owner baseline, so the runner ran a differential and found no difference; the stored note
reads:

```
status 200 with resource-like content; response is structurally identical to the owner's
response (strong cross-account signal); identity 'bob' reached a resource owned by 'alice'
```

That no-difference result is why `_confidence_for()` returned `FIRM` rather than relying
on the 2xx alone.

**Row 4 (admin → alice's order).** Identical HTTP behaviour to row 3 — a 200 with the
same body. It is reported as `INCONCLUSIVE`, because `admin` outranks `user_a` and rule 2
returned `UNKNOWN`. The framework saw the same evidence and declined to call it a finding,
because an administrator reading a user's order may be correct. To test it, the operator
adds `expectations: {admin: DENY}` to the resource.

**Rows 6 and 7 (alice and bob → admin console).** `requires_role: admin`, both are rank
1, so rule 3 gave `DENY`. The lab app accepts any authenticated token on
`/admin/console`, so both were `GRANTED` and classified vertical. Both produced their own
finding — findings are per matrix cell, not per resource.

**Row 5 (anonymous → admin console).** Same resource, same `DENY` expectation, but the
lab app returns 401 to unauthenticated callers, so the observation was `DENIED` and the
outcome `AS_EXPECTED`. The correctly-enforced half of the control is visible alongside
the broken half.

The `/api/public` rows show the cost of not declaring expectations: only `anonymous` had
an explicit `ALLOW`, so the other three cells are `UNKNOWN` → `INCONCLUSIVE` despite
having been executed. Coverage is a function of what the operator declares.

---

## What this subsystem does not claim

- **It does not confirm anything.** Findings are created as `Potential` with
  `ValidationState.OBSERVED`. Only a human, through `velora finding validate`, moves a
  finding's status to `Confirmed`. The integration suite asserts the `Potential` status
  for every finding a run produces.
- **It does not claim exploitability.** The finding description says "INDICATOR" and
  "requires human validation"; the impact statement is phrased as what an actor *could*
  reach, not what was reached and used.
- **It does not judge undeclared pairs.** `UNKNOWN` expectations yield `INCONCLUSIVE`
  unconditionally.
- **It does not treat a 404 as a denial, or a 200 as a grant, on status alone.** Both
  rules exist to prevent status-code-driven false conclusions in either direction.
- **It does not report the tester's own misconfiguration as the target's defect.** An
  expected-`ALLOW` pair that was denied is `INCONCLUSIVE` with an explicit note.
- **`AS_EXPECTED` is not a pass.** The report text states it directly: *"'AS_EXPECTED'
  does not prove the control is complete."* It proves one identity was refused on one
  URL with one method.
- **It does not escalate privileges.** There is no token manipulation, no parameter
  tampering and no forced browsing. Every request is one the plan declared.
- **Confidence is reliability, not severity.** `CERTAIN` is never assigned.

---

## Behaviour worth knowing

- `AuthorizationTest.differential_id` is never populated, even when the runner produced
  a differential comparison. `velora/ai/evidence_matrix.py` credits an
  "owner-baseline comparison performed" signal off that field, so that signal is
  currently unreachable. The differential's substance does survive, but only as prose in
  `notes`.
- `AuthorizationTest.resource_owner_identity_id` stores the owner's **name** from the
  plan (e.g. `"alice"`), not an `Identity.id`, despite the field name.
- `AuthorizationTest.plan_id` is never set by the CLI.
- `Identity.owned_resource_hints` is parsed from the plan and persisted, but no code in
  `velora/authz/` reads it.
- A `ConfigError` raised by `load_plan` is not caught by either `authz plan` or
  `authz run` — a bad plan file produces a Python traceback rather than a clean
  `Error:` line. The `try/except` in `authz run` wraps only the request phase.
- `velora finding validate` changes a finding's `status` to `Confirmed` but leaves its
  `validation_state` at `OBSERVED`. No code path in the project sets
  `ValidationState.VALIDATED` on a `Finding`, so `status` is the field that records human
  confirmation.

---

## How it is tested

### `tests/unit/test_authz.py` — 27 tests, no network

`TestIdentityResolver` (6): anonymous needs no credential; a bearer header is built from
the environment; a missing credential degrades but is marked `resolved=False` with the
variable named in the reason; `strict=True` raises `MissingCredentialError`;
`safe_summary()` contains the variable name and the header name but **not** the secret
value; `available()` tracks the environment.

`TestMatrix` (7): owner allowed and peer denied; anonymous denied on an owned resource;
**admin on another user's resource is `UNKNOWN`, not `DENY`** — the test carries the
docstring *"An admin may legitimately read another user's record — don't assume a
weakness"*; `requires_role` governs the vertical expectation in both directions; an
explicit expectation overrides derivation; an undeclared resource yields `UNKNOWN`; the
matrix is the full cross product (2 identities × 3 resources = 6 cases).

`TestObservationClassification` (7): 401 and 403 are `DENIED`; a 200 with a resource body
is `GRANTED`; **a 200 rendering a login form is `DENIED`, not `GRANTED`**; a redirect to
`/login` is `DENIED`; **404 is `INCONCLUSIVE`, not `GRANTED`**; 500 is `INCONCLUSIVE`; a
transport error is `ERROR`.

`TestOutcomeClassification` (7): the three weakness classes are reached correctly; denied
where denied was expected is not a weakness; an `UNKNOWN` expectation never produces a
weakness; **expected-`ALLOW`-but-denied is `INCONCLUSIVE`** and the reason string contains
"not treated as a security weakness" (docstring: *"A broken credential must not be
reported as a security weakness"*); an `INCONCLUSIVE` observation never becomes a
weakness.

### `tests/integration/test_authz_flow.py` — 7 tests, real HTTP

Runs the full stack against the lab fixture over loopback with an injected credential
environment. The fixture is built so both directions are checked: `/api/orders/1` and
`/admin/console` are deliberately broken, `/admin/settings` and `/api/profile` are
correct.

| Test | What it proves |
|---|---|
| `test_detects_horizontal_weakness` | The intentional IDOR is found, attributed to `bob`. |
| `test_detects_vertical_weakness` | Both `alice` and `bob` are flagged on the broken admin endpoint. |
| `test_correct_control_is_not_flagged` | `/admin/settings`, which enforces the role correctly, produces **zero** weaknesses. This is the false-positive check. |
| `test_anonymous_denied_is_as_expected` | The correct 401 on `/api/profile` is recorded as `AS_EXPECTED`. |
| `test_findings_created_as_potential_only` | Every finding has `status == POTENTIAL`, `category == "authorization"`, a real CWE (not `UNKNOWN`), and non-empty `evidence_ids`. |
| `test_no_credentials_persisted_anywhere` | The SQLite database file is read as **raw bytes** after a full run and asserted not to contain any of the three tokens. |
| `test_tests_are_persisted_with_expected_and_observed` | One stored row per matrix cell, each with both expectation and observation. |

Run them with:

```
python -m unittest tests.unit.test_authz
python -m unittest tests.integration.test_authz_flow
```

`tests/__init__.py` puts `tests/fixtures` on `sys.path`, so the lab app imports under
both `unittest` and `pytest` without extra setup.

`test_correct_control_is_not_flagged` and `test_no_credentials_persisted_anywhere` are
the two that matter most. The first asserts the absence of a finding, which is the
property a detection tool loses first under change. The second checks the credential
guarantee at the only layer where it cannot be faked — the bytes on disk.
