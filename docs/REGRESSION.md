# Regression analysis

Velora compares two scans of the same target and classifies what changed between them. The
engine is `velora/regression/engine.py` (`RegressionEngine`, `RegressionSummary`,
`severity_delta`); the CLI surface is `velora/cli/commands/regression.py`.

Findings are matched across scans by a stable fingerprint, never by id. Finding ids are
generated per scan and carry no cross-run meaning, so an id-based comparison would report
every finding in every scan as both fixed and new.

## The finding fingerprint

`velora/findings/fingerprint.py`. The fingerprint answers one question: *is this the same
issue we saw last time?* It is a SHA-256 over the properties that define the issue rather
than the run.

### What goes in

`fingerprint.compute` joins these five parts with `|` and hashes them:

| Part | Source | Normalization |
| --- | --- | --- |
| Detecting check | `finding.scanner` (or `"unknown"`) | stripped, lowercased |
| Category | `finding.category` | stripped, lowercased |
| HTTP method | `finding.method` (or `"GET"`) | stripped, uppercased |
| Endpoint | `finding.endpoint` | `normalize_endpoint` |
| Title | `finding.title` | `normalize_title` |

The result is the first 24 hex characters of the digest, prefixed: `VF-<24 hex chars>`.

The module docstring lists only four parts and omits the HTTP method. The code includes it;
the docstring is out of date.

`fingerprint.ensure(finding)` computes and attaches the fingerprint only if the field is
empty, so a fingerprint persisted by an earlier run is never silently recomputed.

### What is deliberately excluded, and why

| Excluded | Reason |
| --- | --- |
| Scan id | The whole point is to match *across* scans |
| Timestamps | Volatile per run |
| Priority score | Derived and re-derivable; not part of the issue's identity |
| **Severity** | A re-rating of the same issue must read as *persisting* |
| Evidence ids | New evidence rows are created on every scan |
| Port (in the endpoint) | Moving a lab app to another port is not a new finding |
| Numeric / UUID / long-hex path segments | Object ids, not endpoint shape |
| Numbers inside the title | Counts and ids embedded in the title text |

#### The consequence of excluding severity

This is the most load-bearing exclusion, and it is deliberate.

If severity were part of the fingerprint, re-rating a finding — by a scanner tweak, a
CVSS-vector correction, or an analyst's judgement — would change its identity. The
comparison would then report the old-severity finding as `FIXED_FINDING` and the
new-severity finding as `NEW_FINDING`. The issue never moved, but the report would claim
one issue was fixed.

That is a false fix claim, which is the failure mode Velora treats as unacceptable: it
would let a vulnerability disappear from the "still open" list without anyone having
touched the target. By excluding severity, a re-rated finding stays one issue and is
classified `PERSISTING_FINDING`. The severity change is still surfaced, but as a detail on
the persisting row rather than as a fix:

```python
{"previous_finding_id": ..., "current_finding_id": ...,
 "severity_changed": prev.severity.value != finding.severity.value}
```

The unit test `tests/unit/test_fingerprint_regression.py::
test_severity_change_keeps_the_same_fingerprint` pins this: a `Low` and a `Critical`
finding that are otherwise identical must hash to the same value.

The same exclusion is what makes remediation retesting sound. `RemediationService` decides
`still_present` by fingerprint membership; if severity were included, an issue whose
severity drifted between the original scan and the retest would not match, and the retest
would conclude the issue was gone.

### `normalize_endpoint`

```python
fp.normalize_endpoint("http://lab.local:8080/api/orders/42")  # -> "lab.local/api/orders/{id}"
```

- Splits the URL; only the hostname and path survive. Scheme, port, query and fragment are
  dropped.
- Empty path segments are removed.
- A segment matching `^\d+$`, a canonical UUID, or 16-or-more hex characters becomes
  `{id}`.
- Everything else is lowercased.
- An empty input returns an empty string.

So `/api/orders/1` and `/api/orders/9987` are one endpoint. Port changes do not create a
new finding. This same function defines coverage matching in retest verification, which is
why a retest of one object id counts as covering a finding filed against another.

### `normalize_title`

Lowercases, replaces every `\b\d+\b` run with `#`, and collapses whitespace. "Risky HTTP
methods enabled: 3 found" and "... 5 found" normalize to the same string.

### `index_by_fingerprint`

Builds `fingerprint -> Finding` for a list of findings, keeping the **highest-severity**
duplicate when several findings share a fingerprint (compared on `Severity.rank`). Both
sides of every comparison go through this index, so a scan that produced the same issue
twice contributes one entry, at its worst observed severity.

This index does **not** filter by `FindingStatus`. A finding marked `Rejected` or
`Remediated` still participates in the comparison and can be reported as
`PERSISTING_FINDING`. This differs from the posture engine, which excludes those statuses
from scoring.

## Change classifications

`RegressionChange` in `velora/models/enums.py`:

| Change | Subject field holds | Produced when |
| --- | --- | --- |
| `NEW_FINDING` | fingerprint | In current, not in previous, no history |
| `FIXED_FINDING` | fingerprint | In previous, not in current |
| `PERSISTING_FINDING` | fingerprint | In both |
| `REINTRODUCED_FINDING` | fingerprint | In current, not in previous, but seen before |
| `NEW_ENDPOINT` | normalized URL | Endpoint in current scan only |
| `REMOVED_ENDPOINT` | normalized URL | Endpoint in previous scan only |
| `CHANGED_TECHNOLOGY` | `name:version` | Technology set differs either way |
| `CHANGED_SECURITY_CONTROL` | finding title | A control-category finding appeared or disappeared |

Each row is persisted as a `RegressionResult` (`velora/models/domain.py`):

| Field | Type | Notes |
| --- | --- | --- |
| `id` | str | `REG-...` |
| `engagement_id` | str \| None | Taken from the current scan |
| `previous_scan_id` / `current_scan_id` | str | |
| `change` | `RegressionChange` | Defaults to `PERSISTING_FINDING` |
| `subject` | str | Fingerprint, endpoint URL, or technology string |
| `severity` | str | Populated for finding-derived rows; empty for endpoint/technology/control rows |
| `detail` | dict | Title, endpoint, and change-specific keys |

### `REINTRODUCED_FINDING` requires history

An issue that is absent from the previous scan and present now is `NEW_FINDING` by default.
It is only upgraded to `REINTRODUCED_FINDING` on positive evidence of one of two things:

```python
history = self._historical_fingerprints(current.target_id,
                                        exclude={previous.id, current.id})
verified_fixed = self._verified_fixed(set(curr_index))
...
elif signature in history or signature in verified_fixed:
```

- `_historical_fingerprints` walks every other scan of the same target and collects their
  fingerprints. The issue was seen in an earlier run, was absent in the previous run, and
  is back.
- `_verified_fixed` scans all `RemediationAction` rows with status `FIX_VERIFIED` and keeps
  those whose finding's fingerprint appears in the current scan. Something Velora
  previously verified as fixed is present again.

The `detail["reason"]` records which of the two fired: `"previously remediated and
verified"` or `"seen in an earlier scan, absent in the previous scan"`.

Requiring one of these is the evidence-first rule applied to the alarm. `REINTRODUCED` is
the only classification the engine treats as an actual regression (`has_regression`, the
`REGRESSION_DETECTED` security log line, the non-zero CLI failure message). Raising it on a
plain two-scan diff would mean every first-time detection reads as a regression, which
would make the alarm meaningless. Absence of a prior record is not evidence of
reintroduction either.

Note that `_verified_fixed` reads all remediations in the database, not just those for the
target under comparison.

### `FIXED_FINDING` carries a caveat in the data

Findings present in the previous scan and absent from the current one are classified
`FIXED_FINDING`, but the engine writes the qualification into the persisted row rather than
leaving the label to speak for itself:

```python
{"previous_finding_id": finding.id,
 "note": "no longer detected; absence of detection is not proof of a fix — "
         "verify with a targeted retest"}
```

`FIXED_FINDING` here means only "the check that fired last time did not fire this time".
The current scan may not have reached the endpoint, the route may have moved, or the check
may not have run. A scan-to-scan diff cannot distinguish those from a fix; only a retest
with a coverage check can, which is what `velora remediation retest` does. The CLI prints
this note under each fixed item, and the integration test
`test_removed_finding_reports_as_fixed_with_a_caveat` asserts it is present.

### Endpoints, technologies and controls

- Endpoints are compared as sets of normalized URLs from `repo.list_endpoints`.
- Technologies are compared as `f"{name}:{version or '?'}"` strings. The engine uses a
  symmetric difference, so additions and removals both emit `CHANGED_TECHNOLOGY`;
  `detail["added"]` distinguishes them.
- Security controls are inferred from findings, not measured directly. `_control_changes`
  takes finding titles in the categories `configuration`, `session` and `tls` — "header
  presence is the observable control surface" — and reports a title that disappeared as
  `"control now present / issue gone"` and a title that appeared as `"control weakened /
  issue appeared"`, in `detail["direction"]`. This is an inference from detection state,
  not an observation of the control itself.

## `RegressionSummary`

Returned by `RegressionEngine.compare`:

| Member | Returns |
| --- | --- |
| `by_change(change)` | Results of one classification |
| `counts()` | `{change value: count}` |
| `severity_breakdown(change)` | `{severity: count}` for one classification |
| `has_regression` | True iff any `REINTRODUCED_FINDING` exists |
| `new_findings` | Shorthand for `by_change(NEW_FINDING)` |
| `to_dict()` | Counts, fixed/new/persisting severity breakdowns, `regression_detected`, and every change |

With `persist=True` (the default) every result row is written via `repo.add_regression`, and
an audit record is added with action `regression_detected` or `regression_compared`.

`severity_delta(previous, current)` returns per-severity counts for both scans, for the
report header. It counts every finding regardless of `FindingStatus`.

## CLI reference

Verified against `velora --help` output.

### `velora regression compare`

| Option | Notes |
| --- | --- |
| `--previous TEXT` | Previous scan id (required) |
| `--current TEXT` | Current scan id (required) |
| `--no-persist` | Compute without storing the results |
| `--json` | Emit JSON, including `severity_delta` |

If the two scans have different `target_id`s the command warns that the comparison may be
meaningless but still runs. Table output shows the per-severity delta, the change counts,
and then up to 15 items each for `REINTRODUCED_FINDING`, `NEW_FINDING` and
`FIXED_FINDING`, each with its `note` or `reason`. It closes with either
`REGRESSION DETECTED: N previously-absent finding(s) reappeared` or `no reintroduced
findings`.

### `velora regression report`

| Option | Notes |
| --- | --- |
| `--current TEXT` | Scan id whose stored results to show (required) |
| `--json` | Emit JSON |

Reads previously persisted rows only. If none exist it says so and points at
`velora regression compare`; it does not silently compute an empty comparison.

## Limits

- The comparison is only meaningful between scans of the same target run with comparable
  profiles. A `safe`-profile scan does not run the same checks as a `standard` scan, so
  findings from the checks that did not run will appear as `FIXED_FINDING`.
- `has_regression` is driven solely by `REINTRODUCED_FINDING`. A scan full of new
  high-severity findings reports "no reintroduced findings"; that phrase is not a pass.
- The engine records `RegressionChange.REINTRODUCED_FINDING` rows but does not write
  `RemediationStatus.REGRESSION_DETECTED` back onto the affected `RemediationAction`. That
  enum member is unused by any code path.
