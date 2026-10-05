# Remediation and retest verification

Velora tracks the lifecycle of a fix separately from the finding's own validation status,
and it verifies fixes by re-examining the target rather than by trusting a status change.
The pipeline is:

    Finding -> Remediation -> Retest -> Comparison -> Verification

The module is `velora/remediation/service.py` (`RemediationService`, `VerificationResult`).
The CLI surface is `velora/cli/commands/remediation.py`.

## The core rule: no coverage, no verification

A retest that did not reach the affected endpoint cannot verify a fix, and Velora does not
report it as one.

This is the "security evidence first" principle applied to the one place where teams are
most tempted to accept absence as proof. When a scanner does not re-detect an issue there
are two possible explanations, and they are not distinguishable from the detection result
alone:

1. The issue was fixed.
2. The check never ran against that endpoint — the crawl missed it, the route was moved,
   the host was down, the scope policy excluded it, the profile did not include the check.

Case 2 produces exactly the same output as case 1: nothing. Treating "nothing" as "fixed"
would close real vulnerabilities on the strength of a scan that never looked. So the code
requires a positive coverage signal before it will emit `FIX_VERIFIED`.

### How the code enforces it

In `RemediationService.verify_against_scan`:

```python
target_endpoint = fp.normalize_endpoint(finding.endpoint)
covered_endpoints = {fp.normalize_endpoint(e.url)
                     for e in self.repo.list_endpoints(retest_scan.id)}
covered_endpoints |= {fp.normalize_endpoint(f.endpoint) for f in retest_findings}
covered = target_endpoint in covered_endpoints or still_present
```

The coverage set is built from two independent sources for the retest scan:

- every `Endpoint` record the retest scan discovered and stored, and
- the endpoint of every finding the retest scan produced.

Both sides are passed through `fingerprint.normalize_endpoint`, so coverage is matched on
endpoint *shape* (host plus path, port dropped, numeric/UUID/long-hex path segments
collapsed to `{id}`) rather than on exact URL string equality. A retest that examined
`/api/orders/5` therefore counts as covering a finding recorded against `/api/orders/9`.

The verdict is then chosen in this order:

| Condition | Verdict | Meaning |
| --- | --- | --- |
| Fingerprint found in the retest scan | `FIX_FAILED` | The issue was detected again |
| Not found **and** endpoint not covered | `READY_FOR_RETEST` | Inconclusive — the retest proves nothing |
| Not found **and** endpoint covered | `FIX_VERIFIED` | Re-examined, no longer detected |

The inconclusive branch is not a separate terminal state. The remediation is left at
`READY_FOR_RETEST`, which is exactly where it was before the retest ran: no progress was
made, because no evidence was obtained. The recorded detail reads:

> scan `<id>` did not cover `<endpoint>`; the retest is inconclusive. Absence of detection
> is not evidence of a fix.

`covered` is forced to `True` whenever `still_present` is true. That is not a loophole —
re-detecting the issue is itself proof that the retest reached it, and the verdict in that
branch is `FIX_FAILED` regardless.

The integration test `tests/integration/test_lifecycle.py::
test_uncovered_endpoint_is_inconclusive_not_verified` pins this behaviour: it attaches a
synthetic finding to an endpoint no scan will ever reach, runs a clean retest, and asserts
the verdict is `READY_FOR_RETEST` with `covered is False`.

The same statement appears in generated reports. `velora/reporting/assembler.py` emits the
limitation "A retest that did not cover the affected endpoint cannot verify a fix, and is
not reported as one."

## Lifecycle states

`RemediationStatus` is defined in `velora/models/enums.py`.

| Status | Set by | Meaning |
| --- | --- | --- |
| `OPEN` | Operator, or implicitly on first tracking | Tracked, work not started |
| `REMEDIATION_IN_PROGRESS` | Operator (`remediation start`) | A fix is being worked on |
| `READY_FOR_RETEST` | Operator (`remediation ready`), or an inconclusive retest | Awaiting evidence |
| `FIX_VERIFIED` | Retest only | Endpoint re-examined, issue no longer detected |
| `FIX_FAILED` | Retest only | Issue detected again |
| `REGRESSION_DETECTED` | Nothing — see below | Declared but unused |

Only the first three are operator-drivable. `RemediationService.set_status` rejects the
rest:

```python
if status not in _OPERATOR_TRANSITIONS:
    raise ValueError(
        f"{status.value} is set by a retest, not directly; use `remediation retest`")
```

This means a verdict cannot be typed in by hand through the service API. It has to be
produced by comparing a finding against a real scan. (The CLI exposes only `start` and
`ready`, so this guard is a library-level invariant rather than a path a CLI user can
reach.)

`REGRESSION_DETECTED` is present in the enum and has a colour mapping in the CLI, but no
code path assigns it. The regression engine logs a `REGRESSION_DETECTED` security event and
records `RegressionChange.REINTRODUCED_FINDING` rows; it does not write this status back
onto the `RemediationAction`. Treat it as unimplemented.

## Effects of a verdict

`_sync_finding` runs after every status change and every retest:

- writes `remediation_status` onto the `Finding`,
- calls `fingerprint.ensure(finding)` so the stable fingerprint is persisted, and
- sets `finding.status = FindingStatus.REMEDIATED` when, and only when, the verdict is
  `FIX_VERIFIED`.

On a retest the service additionally sets `action.last_retest_id`, stamps `verified_at` on
`FIX_VERIFIED`, persists a `RetestRun`, and writes an audit record
(`action="retest_completed"`) carrying the verdict, retest scan id, `still_present` and
`covered`.

Note that `FindingStatus.REMEDIATED` is reachable only through a verified retest. The
posture engine excludes `Rejected` and `Remediated` findings from scoring, so the only way
a finding stops depressing the posture score by being fixed is for a retest to have
covered it.

## Data model

`RemediationAction` (`velora/models/domain.py`) — one per finding, the durable record of
the fix:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | str | `REM-...` |
| `finding_id` | str | The finding being fixed |
| `engagement_id` | str \| None | Copied from the finding |
| `status` | `RemediationStatus` | Defaults to `OPEN` |
| `owner` | str | Free text |
| `note` | str | Free text |
| `opened_at` / `updated_at` | datetime | |
| `verified_at` | datetime \| None | Set only on `FIX_VERIFIED` |
| `last_retest_id` | str \| None | Most recent `RetestRun` |

`RetestRun` — one per retest, immutable evidence of what the comparison found:

| Field | Type | Notes |
| --- | --- | --- |
| `id` | str | `RETEST-...` |
| `finding_id` | str | |
| `remediation_id` | str \| None | |
| `original_scan_id` | str | Taken from `finding.scan_id` |
| `retest_scan_id` | str \| None | |
| `still_present` | bool \| None | |
| `verdict` | `RemediationStatus` | Defaults to `READY_FOR_RETEST` |
| `detail` | str | Human-readable reason for the verdict |
| `evidence_ids` | list[str] | Populated only when `still_present` |

`evidence_ids` are taken from the *retest* finding, not the original. They are the evidence
that the issue is still there. A verified fix carries no evidence ids, because a fix
produces no observation — another reason the coverage check matters.

`VerificationResult` is the in-memory return value of `verify_against_scan`, carrying
`finding_id`, `verdict`, `still_present`, `covered`, `detail`, the `RetestRun` and
`evidence_ids`. Its `to_dict()` exposes `covered` under the clearer key
`endpoint_covered_by_retest`.

## Matching: how "the same issue" is decided

`still_present` is determined by fingerprint, not by finding id:

```python
index = fp.index_by_fingerprint(retest_findings)
still_present = signature in index
```

Finding ids are per-scan and cannot be compared across runs. The fingerprint is the stable
identity. See `docs/REGRESSION.md` for what goes into it. One consequence that matters
here: severity is deliberately excluded from the fingerprint, so a finding that was
re-rated between scans is still recognised as the same issue and correctly reports
`FIX_FAILED` rather than looking fixed.

## CLI reference

Verified against `velora --help` output.

### `velora remediation list`

Lists tracked remediations and their verification state.

| Option | Notes |
| --- | --- |
| `--status` | One of `OPEN`, `REMEDIATION_IN_PROGRESS`, `READY_FOR_RETEST`, `FIX_VERIFIED`, `FIX_FAILED`, `REGRESSION_DETECTED` |
| `--json` | Emit JSON instead of a table |

### `velora remediation start FINDING_ID`

Moves the finding to `REMEDIATION_IN_PROGRESS`.

| Option | Notes |
| --- | --- |
| `--owner TEXT` | Who is doing the work |
| `--note TEXT` | Free text |

### `velora remediation ready FINDING_ID`

Moves the finding to `READY_FOR_RETEST`. Same `--owner` and `--note` options.

### `velora remediation retest FINDING_ID`

Retests one finding and records the verdict.

| Option | Notes |
| --- | --- |
| `--scan TEXT` | Use an existing scan as the retest (otherwise a new scan is run) |
| `--profile [safe\|standard\|lab]` | Profile for the new scan; defaults to `safe` |
| `--operator TEXT` | Recorded in the audit log |
| `--i-am-authorized` | Required only when a new scan is run |

Two modes:

- With `--scan`, an already-stored scan is used as the retest. No requests are sent, so no
  authorization flag is required. Note that the existing scan's `is_retest` and
  `baseline_scan_id` fields are **not** modified in this path.
- Without `--scan`, `--i-am-authorized` is required, the original scan and target are
  resolved from the finding, a fresh scan is run through `ScanOrchestrator`, and the new
  scan is marked `is_retest = True` with `baseline_scan_id` set to the finding's original
  scan.

Output prints the verdict, `still present`, `endpoint covered`, the retest scan id and the
detail string. On an inconclusive result it additionally warns: "retest was inconclusive —
absence of detection is not proof of a fix".

### `velora remediation verify`

Verifies every finding of an original scan against a retest scan.

| Option | Notes |
| --- | --- |
| `--scan TEXT` | Original scan to verify (required) |
| `--retest-scan TEXT` | Retest scan (required) |
| `--operator TEXT` | Recorded in the audit log |

Prints one row per finding with a `COVERED` column rendered as `yes` / `NO`, then a summary
line `verified=N failed=N inconclusive=N`. Inconclusive is computed as the remainder, so it
is the count of findings whose endpoint the retest did not reach.

## Reading the numbers honestly

`verified=0 failed=0 inconclusive=12` is not a clean bill of health. It means the retest
scan did not examine the endpoints in question at all. The correct response is to widen the
retest — check the scope policy, the profile, and whether the crawler reached the routes —
not to record the findings as fixed.

`verified=12 failed=0` means twelve endpoints were re-examined and the specific checks that
originally fired no longer fire. It does not mean those endpoints are secure. It means the
checks that ran did not detect anything, within the scope and budget of that scan.
