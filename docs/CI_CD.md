# CI/CD integration

Velora's CI/CD surface is one command with a defined exit-code contract:

```bash
velora gate evaluate --scan <scan-id> --policy .velora/gate.yaml
```

Code: `velora/gate/policy.py` (policy and evaluation), `velora/cli/commands/gate.py`
(CLI). Configuration: `.velora/gate.yaml`. Pipelines:
`.github/workflows/velora-security.yml`, `examples/ci/gitlab-ci.yml`,
`examples/ci/Jenkinsfile`. Tests: `tests/unit/test_gate_sarif.py`.

## What a passing gate means

A `PASS` means no rule in the policy you configured was violated by what Velora's checks
observed on that scan. It is not a statement that the application is secure. Both the
GitHub step summary and the Jenkinsfile's post block carry that sentence, and
`.velora/gate.yaml` opens with it:

> The gate answers one question: did this scan violate a rule you configured? A PASS is
> not a statement that the application is secure — it means no rule below was violated by
> what Velora's checks actually observed.

This is the "absence of a detection is never evidence of security" principle applied to
the one place where a green check mark is most likely to be read as a clean bill of
health.

## The exit-code contract

`GateDecision` in `velora/models/enums.py` maps each decision to a process exit code:

```python
@property
def exit_code(self) -> int:
    return {"PASS": 0, "FAIL": 1, "ERROR": 2}[self.value]
```

| Decision | Exit | Meaning |
| --- | --- | --- |
| `PASS` | `0` | No policy violation. |
| `FAIL` | `1` | At least one policy violation. |
| `ERROR` | `2` | The gate could not be evaluated. |

`gate_evaluate` calls `sys.exit(evaluation.exit_code)` as its last statement, so the
process status is the decision. A configuration error raised before evaluation exits with
`GateDecision.ERROR.exit_code` too, so a bad policy file and an unevaluable scan produce
the same `2`.

`test_exit_codes_are_the_documented_contract` asserts the three values directly.

### ERROR never silently passes

The module docstring states the design rule: "A gate that silently passes when it cannot
evaluate is worse than no gate. Any configuration or data problem is `ERROR` (exit 2),
never `PASS`."

`SecurityGate.evaluate()` returns `ERROR` in four situations:

| Condition | Summary |
| --- | --- |
| The scan id does not exist | `scan not found: <id>` |
| The scan's status is not `completed` | `scan <id> is '<status>', not 'completed'; refusing to pass a gate on an incomplete scan` |
| A baseline rule names a baseline scan that does not exist | `baseline scan not found: <id>` |
| `max_new_findings` is set but no baseline is available | `max_new_findings requires a baseline scan; pass --baseline or record one on the scan` |

Plus `ERROR` from the CLI when `GatePolicy.from_file()` or `from_dict()` raises
`ConfigError`.

A gate that passed on a scan that crashed halfway would be worse than no gate at all: the
pipeline would report green precisely when the scan produced the least information. The
same logic applies to a missing baseline — a `max_new_findings: 0` rule with nothing to
compare against has no meaning, so it errors rather than vacuously passing.

`ERROR` results are also not persisted or audited: the early-return paths in `evaluate()`
return before the `persist` block, so an unevaluable gate leaves no gate-result row
claiming an outcome.

Two tests pin the behaviour: `test_missing_scan_is_error_not_pass` and
`test_incomplete_scan_is_error_not_pass`.

## Policy rules

`GatePolicy` is a dataclass loaded from the `gate:` mapping of a YAML file (or from the
inline CLI options). A policy that defines no rules is rejected with `ConfigError`:
"gate policy defines no rules; set at least one of fail_on, max_cvss, max_priority_score,
max_new_findings, or fail_on_regression."

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `fail_on` | list of severity names | `[]` | Each finding whose severity is in the list is a violation. |
| `max_cvss` | number | unset | Each finding with a CVSS base score **greater than** the value is a violation. |
| `max_priority_score` | number | unset | Each finding whose Velora Priority Score exceeds the value is a violation. |
| `max_new_findings` | integer ≥ 0 | unset | Violation when the count of `NEW_FINDING` regressions exceeds the value. Requires a baseline. |
| `fail_on_regression` | bool | `true` | Each `REINTRODUCED_FINDING` regression is a violation. |
| `ignore_unvalidated` | bool | `false` | When true, only `Confirmed` findings are considered. |

Validation on load:

- An unrecognised severity name raises `ConfigError` naming the valid values, rather than
  being silently ignored — a typo in `fail_on` would otherwise turn a rule off.
- `max_cvss` and `max_priority_score` must parse as numbers.
- `max_new_findings` must parse as an integer and be `>= 0`.

`test_unknown_severity_is_rejected`, `test_policy_with_no_rules_is_rejected`,
`test_non_numeric_threshold_is_rejected` and `test_negative_new_finding_limit_rejected`
cover these.

### Which findings are considered

`SecurityGate._considered()`:

1. Findings whose status is `Rejected` or `Remediated` are always excluded.
2. When `ignore_unvalidated` is true, only findings whose status is `Confirmed` remain.

`Rejected` is excluded because a human already dismissed it; re-failing the build on it
would make triage meaningless. `Remediated` is excluded for the same reason from the other
direction.

Unvalidated `Potential` findings **do** count by default. The docstring gives the
reasoning: "a CI gate exists to stop regressions before a human has triaged them."
Requiring validation first would mean the gate can only catch what someone already looked
at, which is the opposite of what a pipeline gate is for. `ignore_unvalidated` exists so
that choosing the other behaviour is explicit and visible in the policy file rather than a
hidden default.

`test_unvalidated_findings_count_by_default` and
`test_ignore_unvalidated_counts_only_confirmed` pin both halves, and
`test_rejected_findings_are_excluded` pins the first rule.

### CVSS is only applied where it exists

```python
if finding.cvss_base_score is not None and finding.cvss_base_score > policy.max_cvss:
```

An unscored finding is never treated as if it scored zero, and never treated as if it
scored high either. `.velora/gate.yaml` says the same in its comment: "findings scored
'Not Assessed' are never treated as if they scored zero."
`test_max_cvss_only_applies_to_scored_findings` adds an unscored `Low` finding (passes),
then a `9.1`-scored one (fails), against the same `max_cvss: 5.0` policy.

### Baseline rules

`max_new_findings` and `fail_on_regression` both need scan-to-scan comparison. The gate
takes regressions already stored for the scan; failing that, it resolves a baseline from
`--baseline` or `scan.baseline_scan_id`, and runs `RegressionEngine.compare(...,
persist=False)` to compute them in memory. The gate does not write regression rows as a
side effect of evaluating.

Regression changes are matched by finding fingerprint, and `REINTRODUCED_FINDING` requires
actual history — present earlier, absent in the previous scan, present again now, or a
previously verified remediation. A finding without that history is `NEW_FINDING`, so
`fail_on_regression` does not fire on a first-ever detection.

### Violations and persistence

Each violation records its `rule`, a human-readable `detail`, and where applicable the
`finding_id` and `severity`. A `FAIL` logs `SECURITY_GATE_FAILED` at the custom `SECURITY`
level; a `PASS` logs `SECURITY_GATE_PASSED` at info.

With `persist=True` (the default), the evaluation writes a `SecurityGateResult` row
carrying the decision, the full policy as evaluated, the violations and the summary, and
an audit entry of `security_gate_failed` or `security_gate_passed`. The stored policy
means a past decision can be re-read against the rules that were actually in force.
`velora gate history` lists stored evaluations.

## CLI

```
velora gate init     [-o PATH]
velora gate evaluate --scan TEXT [--policy PATH] [--fail-on SEVERITY]... [--max-cvss FLOAT]
                     [--max-priority-score FLOAT] [--max-new-findings INT] [--baseline TEXT]
                     [--no-fail-on-regression] [--ignore-unvalidated] [--json] [--output PATH]
velora gate history  [--scan TEXT]
```

| Command | Flag | Type | Notes |
| --- | --- | --- | --- |
| `init` | `-o`, `--output` | path | Defaults to `velora-gate.yaml`. Refuses to overwrite an existing file. |
| `evaluate` | `--scan` | text | Required. |
| | `--policy` | path | Gate policy YAML. When given, the inline options below are ignored. |
| | `--fail-on` | choice, repeatable | `informational`, `low`, `medium`, `high`, `critical`. |
| | `--max-cvss` | float | |
| | `--max-priority-score` | float | |
| | `--max-new-findings` | integer | |
| | `--baseline` | text | Baseline scan for the new-finding and regression rules. |
| | `--no-fail-on-regression` | flag | Sets `fail_on_regression: false`. |
| | `--ignore-unvalidated` | flag | Count only human-validated findings. |
| | `--json` | flag | Print the evaluation as JSON. |
| | `--output` | path | Write the JSON evaluation to a file. |
| `history` | `--scan` | text | Filter to one scan. |

Without `--policy`, the inline options build a policy whose `fail_on` defaults to
`["critical", "high"]`. `--output` is written before the exit code is raised, so the JSON
file exists even on a failing build.

`velora gate init` writes `DEFAULT_POLICY_YAML` from `velora/gate/policy.py`.

## The bundled policy

`.velora/gate.yaml` is the policy the three example pipelines reference:

```yaml
gate:
  fail_on: [critical, high]
  # max_cvss: 7.0
  # max_priority_score: 70
  # max_new_findings: 0
  fail_on_regression: true
  ignore_unvalidated: false
```

## The three pipelines

All three follow the same shape, in this order:

1. Install Velora.
2. Start the application under test, on loopback.
3. Wait for it to become reachable.
4. `velora scan --scan-id-file <path>` and read the scan id back.
5. `velora report --format sarif --format json --format html`.
6. `velora gate evaluate --policy .velora/gate.yaml --output .../gate.json`.

The gate is deliberately the **last** step, so the reports are produced even when the
build is about to fail. Reports on a failing build are the ones a reviewer needs.

### They deliberately fail until you configure a start step

Every pipeline's "start the application" step is a hard failure:

- GitHub: `echo "::error::configure a start step for your application" && exit 1`
- GitLab: `- echo "configure a start step for your application" && exit 1`
- Jenkins: `error('configure a start step for your application')`

This is intentional, not a stub someone forgot to remove. The alternative — a pipeline
that runs end to end out of the box — would scan nothing, find nothing, and report a
green gate. A user who copied it would have a passing security check in their pipeline
that had never assessed an application. A loud failure on the one line that must be
customised is the only version that cannot be mistaken for a working gate.

The commented-out alternatives (`docker compose up -d app`, `./scripts/serve.sh &`) show
what to replace it with.

### Authorization is the user's assertion

Each pipeline's header carries the same scope note. The GitHub workflow states it most
fully:

> This workflow scans an application that the pipeline itself brings up, inside the
> runner, on loopback. That is the only target it is safe to point at by default: the
> runner owns it, it exists for the length of the job, and nothing outside the job can
> reach it.
>
> If you change `VELORA_TARGET` to a deployed environment, you are asserting that your
> organisation has written authorization to test that host. Velora enforces scope on every
> request, but it cannot know whether you are allowed to test a given system — only you
> can. Never point this workflow at a third party, a shared staging environment you do not
> own, or production without a signed authorization.

The scan invocation carries `--scope 127.0.0.1 --allow-private --i-am-authorized`, which
is the acknowledgement Velora requires before any request is sent.

### GitHub Actions — `.github/workflows/velora-security.yml`

Triggers on `pull_request`, `workflow_dispatch` and a Monday 03:00 UTC schedule.
Permissions are `contents: read` and `security-events: write`, the latter needed only for
the SARIF upload.

| Environment variable | Default |
| --- | --- |
| `VELORA_TARGET` | `http://127.0.0.1:8080/` |
| `VELORA_PROFILE` | `safe` |
| `VELORA_DATA_DIR` | `${{ github.workspace }}/.velora` |

The scan writes its id with `--scan-id-file "$RUNNER_TEMP/velora-scan-id"` and exports it
into `$GITHUB_ENV`. Reports upload as an artifact with `if: always()`, and SARIF uploads
to code scanning via `github/codeql-action/upload-sarif@v3` with
`continue-on-error: true` and a comment explaining why: "a code-scanning outage must not
mask the gate below." The gate is the authority; the upload is a convenience.

A final `if: always()` step renders `gate.json` into `$GITHUB_STEP_SUMMARY` as a decision
line and a violations table, closing with the reminder that a passing gate does not mean
the application is secure.

### GitLab CI — `examples/ci/gitlab-ci.yml`

A single `velora-security-gate` job in a `security` stage, on `python:3.11-slim`, 20-minute
timeout, with a pip cache. Rules run it on merge requests, scheduled pipelines and the
default branch.

Artifacts are `when: always` with a 30-day expiry, and `reports.sast` points GitLab's SAST
widget at the SARIF output.

The `sast` glob is `velora-reports/velora-*.sarif`, but `ReportGenerator` names the file
`<scan_id>.sarif`, and scan ids are of the form `SCAN-XXXXXX`. The glob does not match the
file Velora writes; the report artifact is still uploaded under `paths`, but the SAST
widget will not be populated by it. The file's own comment says "the file name must match
the report Velora actually wrote", which is the fix: use `velora-reports/SCAN-*.sarif` or
`velora-reports/*.sarif`.

### Jenkins — `examples/ci/Jenkinsfile`

Declarative pipeline, `agent any`, 20-minute timeout, `disableConcurrentBuilds()`. Velora
installs into a workspace virtualenv at `${WORKSPACE}/.venv`.

The gate stage is the one that shows the exit-code contract in full, because it captures
the status rather than letting a non-zero exit fail the stage generically:

```groovy
def status = sh(returnStatus: true, script: '''... velora gate evaluate ...''')
if (status == 1) {
  error("Velora security gate FAILED: the scan violated the gate policy. ...")
} else if (status != 0) {
  error("Velora security gate ERROR (exit ${status}): the scan was missing or " +
        "incomplete, or the policy is invalid. This is not a pass.")
}
```

Both branches fail the build. The distinction exists so the message tells the reader which
happened: a violated policy is a finding to triage, an `ERROR` is a broken pipeline to
fix. Collapsing them would hide a scan that never ran behind a message about security
findings. The `post { always { ... } }` block archives `velora-reports/**` with
`allowEmptyArchive: true`.

## Dashboard

The read-only dashboard has a `/ci-cd` page listing stored gate results.
`tests/integration/test_dashboard.py::test_ci_cd_page_documents_the_exit_code_contract`
asserts that page states the contract and contains the phrase "never silently passes".
