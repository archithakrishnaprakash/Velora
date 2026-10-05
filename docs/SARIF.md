# SARIF export

Velora exports findings as SARIF 2.1.0 so they can be consumed by GitHub code scanning,
GitLab's SAST widget and other SARIF-aware tooling.

Code: `velora/reporting/sarif.py`. Tests: `tests/unit/test_gate_sarif.py` (`TestSarif`).

```bash
velora report --scan <scan-id> --format sarif --output-dir velora-reports
```

The file is written as `<scan_id>.sarif` by `ReportGenerator.generate()`.

## Document shape

`build_sarif(repo, scan_id, include_rejected=False)` returns a log with one run.

| Field | Value |
| --- | --- |
| `$schema` | `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json` |
| `version` | `"2.1.0"` |
| `runs[0].tool.driver.name` | `"Velora"` |
| `runs[0].tool.driver.fullName` | `"Velora — AI-Assisted Web Application Security Assessment & Validation Platform"` |
| `runs[0].tool.driver.version` / `semanticVersion` | `velora.__version__` |
| `runs[0].tool.driver.informationUri` | `https://github.com/architha/velora` |
| `runs[0].tool.driver.rules` | One rule per detecting check |
| `runs[0].invocations[0]` | Execution success, command line, profile, operator, request counts, start/end times |
| `runs[0].automationDetails.id` | `velora/<scan-id>` |
| `runs[0].results` | One result per finding |
| `runs[0].properties` | Scan id, target, authorization status, and the locations note |

`invocations[0].executionSuccessful` is `scan.status.value == "completed"` — a failed or
cancelled scan is reported as an unsuccessful invocation rather than as a clean run with
no results. `startTimeUtc` and `endTimeUtc` are included only when the scan actually
recorded them.

`build_sarif` raises `ValueError` when the scan id does not exist. It does not return an
empty document.

## Severity mapping

SARIF levels are `error`, `warning`, `note` and `none`.

| Velora `Severity` | SARIF `level` | Rule `security-severity` |
| --- | --- | --- |
| `Critical` | `error` | `"90.0"` |
| `High` | `error` | `"70.0"` |
| `Medium` | `warning` | `"50.0"` |
| `Low` | `note` | `"30.0"` |
| `Informational` | `note` | `"10.0"` |

`Critical` and `High` both map to `error` because SARIF has no severity above `error`;
the distinction survives in `properties["velora/severity"]`, which carries the exact
Velora severity on every result.

`test_severity_maps_to_sarif_levels` pins `Critical → error`, `Medium → warning` and
`Informational → note`.

## Rules

`_build_rules()` emits one rule per detecting check, deduplicated by rule id. The rule id
is `finding.scanner` — the check id such as `headers.security_headers` — falling back to
`velora.unknown`.

| Rule field | Source |
| --- | --- |
| `id` | `finding.scanner` |
| `name` | the id with `.` replaced by `_` |
| `shortDescription.text` | finding title, truncated to 120 characters |
| `fullDescription.text` | finding description (or title), truncated to 900 characters |
| `help.text` | finding remediation, or "See the Velora report for remediation." |
| `help.markdown` | remediation and impact, when remediation exists |
| `defaultConfiguration.level` | the severity mapping above |
| `helpUri` | the finding's first reference, when it has one |

Rule `properties`:

| Property | Source |
| --- | --- |
| `category` | `finding.category` |
| `precision` | `Certain → very-high`, `Firm → high`, `Tentative → medium` |
| `problem.severity` | the SARIF level |
| `security-severity` | the severity rank from the table above |
| `tags` | `security`, `velora`, plus `external/cwe/<cwe>` when the CWE is known and the OWASP prefix (the part before the first `-`) when that is known |

The first finding of each check supplies the rule's descriptive text, so a rule reads like
whichever of its findings came first in the scan.

Rule-level `security-severity` is derived from the Velora severity. Result-level
`security-severity` is not — see below.

## Results

One result per exported finding. Rejected findings are excluded unless
`include_rejected=True`.

| Result field | Value |
| --- | --- |
| `ruleId` | the check id |
| `level` | the severity mapping |
| `message.text` | status prefix + title + description + validation note, truncated to 1800 characters |
| `locations` | a single location — see below |
| `properties` | the `velora/*` block below |
| `partialFingerprints` | `{"veloraFingerprint/v1": finding.fingerprint}`, when a fingerprint is set |
| `suppressions` | present only when the finding's status is `Rejected` |

### Message: validation state is carried, not hidden

A finding whose status is not `Confirmed` is prefixed with its status in square brackets —
`[Potential] `, `[Needs Review] ` — and a finding whose status is neither `Confirmed` nor
`Rejected` gets the sentence appended:

> This is an evidence-backed indicator and requires human validation before it is treated
> as confirmed.

This is the core principle reaching the place it matters most. Once findings leave Velora
for a code-scanning UI, they are rendered next to results from tools that *do* claim
confirmation, and the reviewer sees a list of alerts with no way to tell which ones a
human has actually looked at. Hiding the status would let an unvalidated indicator read as
a confirmed vulnerability in someone else's dashboard. Carrying it in the message text
means the caveat survives whatever the consumer does with the properties.

`test_validation_state_is_visible_not_hidden` asserts both `[Potential]` and "requires
human validation" appear in the message text.

### Result properties

| Property | Value |
| --- | --- |
| `velora/findingId` | finding id |
| `velora/scanId` | scan id |
| `velora/category` | finding category |
| `velora/severity` | exact Velora severity |
| `velora/confidence` | `Certain` / `Firm` / `Tentative` |
| `velora/status` | `Potential` / `Needs Review` / `Confirmed` / `Rejected` / `Remediated` |
| `velora/validationState` | `OBSERVED` / `INFERRED` / `HYPOTHESIZED` / `VALIDATED` / `UNKNOWN` |
| `velora/remediationStatus` | the `RemediationStatus` value |
| `velora/priorityScore` | the Velora Priority Score |
| `velora/priorityScoreNote` | `"Velora Priority Score — a triage metric, not CVSS."` |
| `velora/cwe` | CWE id or `UNKNOWN` |
| `velora/owasp` | OWASP category or `UNKNOWN` |
| `velora/evidence` | up to 5 sanitized evidence excerpts |
| `velora/cvssBaseScore`, `velora/cvssVector`, `security-severity` | only when a real CVSS base score exists |
| `velora/cvss` | `"Not Assessed"` when no CVSS base score exists |

Two of these carry weight.

`velora/priorityScoreNote` ships next to the number so the score cannot be mistaken for a
CVSS value in a consumer that sorts by whatever number it finds.

`velora/cvss: "Not Assessed"` is a deliberate refusal. A finding with no CVSS vector could
have been given a plausible score derived from severity, and every consumer would render
it as a real assessment. Velora writes the string instead, so the absence of an assessment
is visible as an absence. `test_unscored_cvss_is_reported_as_not_assessed` pins it.

Result-level `security-severity` — the field GitHub sorts alerts by — is set **only** from
a real `cvss_base_score`, as the exact score: a finding with CVSS 7.5 gets
`"security-severity": "7.5"`. `test_security_severity_only_from_real_cvss` asserts this.
The rule-level `security-severity` is a different field and is derived from severity, so a
consumer reading rule properties rather than result properties sees a severity-derived
rank. The comment above `_RANK` in the source describes the intent as "Velora only emits
it when a real CVSS base score exists — it never derives one from severity", which is
accurate for results and not for rules.

### Fingerprints

`partialFingerprints` carries `veloraFingerprint/v1` set to `Finding.fingerprint`, the
stable cross-scan identity computed by `velora/findings/fingerprint.py` from the check,
category, method, normalized endpoint and normalized title. It deliberately excludes the
scan id, timestamps, priority score and severity, so a SARIF consumer tracks one issue
across runs instead of opening a new alert every scan and closing the old one.
`test_fingerprint_is_exported_for_tracking` asserts the key is present.

### Rejected findings are suppressed, not deleted

With `include_rejected=True`, a `Rejected` finding is exported carrying:

```json
"suppressions": [{"kind": "external", "justification": "<validation note or 'rejected by a human reviewer'>"}]
```

The reviewer's decision travels with the result, so a consumer can show that someone
looked and dismissed it rather than the finding silently disappearing.
`test_rejected_findings_are_suppressed_not_deleted` covers it. By default
(`include_rejected=False`) rejected findings are filtered out entirely.

## Locations: endpoint URIs with no region

This is the modelling decision the module leads with.

```python
def _location(finding: Finding) -> dict[str, Any]:
    """Endpoint URI as the location. No file path, no line number, ever."""
```

Each result has exactly one location:

```json
{
  "physicalLocation": {
    "artifactLocation": {
      "uri": "http://target.example/login",
      "description": {"text": "HTTP endpoint assessed by Velora (not a source-code location)"}
    }
  },
  "logicalLocations": [
    {"name": "POST http://target.example/login", "kind": "resource",
     "fullyQualifiedName": "http://target.example/login"}
  ]
}
```

**There is no `region` key.** No `startLine`, no `startColumn`, no `endLine`. The module
docstring gives the reason:

> Velora assesses running web applications, not source files. Inventing `file.py:42` would
> be a lie that tools would render as fact.

That is the whole argument. SARIF's physical location was designed for static analysers
that genuinely know which line produced a result. Velora observed an HTTP response. It has
no knowledge of which source file emitted a missing `Content-Security-Policy` header —
that could be a framework default, a reverse proxy, a middleware, or a CDN. A synthesised
line number would be rendered by GitHub as an annotation on a specific line of a specific
file, and a reviewer would read it as the tool's assertion that the defect lives there.
The annotation would look identical to one from a tool that actually knew. Fabricating the
location does not merely add a wrong field; it launders a guess into a claim, in a UI
where the reviewer has no way to tell the difference.

The truthful answer is the URI. The module docstring closes the point: "Consumers that
require a file path will show the URI instead, which is the truthful answer." A consumer
that cannot render a URI degrades gracefully; a consumer that renders a fabricated line
does not.

`logicalLocations` adds `kind: "resource"` with the method and URI, which is what a web
finding's location actually is.

`test_no_invented_source_locations` enforces it on every result in the document:

```python
physical = result["locations"][0]["physicalLocation"]
self.assertNotIn("region", physical)
self.assertTrue(physical["artifactLocation"]["uri"].startswith("http"))
```

A finding with an empty `endpoint` produces an empty `uri` string rather than a
substituted placeholder.

## Run-level note

Every document repeats the point at the run level, in `runs[0].properties`:

```json
"velora/note": "Locations are HTTP endpoint URIs, not source-code paths. Velora assesses running applications and does not map findings to source files. Findings marked Potential are unvalidated indicators."
```

Run properties also carry `velora/scanId`, `velora/target` and
`velora/authorizationStatus` — the last being the target's `AuthorizationStatus`, so the
exported document records that the assessed target was marked `AUTHORIZED` or `LAB_ONLY`.
