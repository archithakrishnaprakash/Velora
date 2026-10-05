# Workflow engine

Single-request checks cannot find a business-logic flaw. Whether checkout can happen
without payment, or a document can be published without review, is a property of an
ordered sequence, and the only way to test it is to run the sequence and then run it
again with a step removed.

Velora models that sequence as an explicit state machine that an operator writes down.
The module docstring in `velora/workflow/spec.py` states the boundary plainly: Velora
"will only execute a workflow that an operator has written down and authorized — it never
discovers and drives business operations on its own."

Code: `velora/workflow/spec.py` (parsing and validation), `velora/workflow/engine.py`
(execution, probes, findings), `velora/cli/commands/workflow.py` (CLI).
Example: `examples/labs/workflow-checkout.yaml`. Tests:
`tests/unit/test_workflow_planning.py`.

## The state-machine model

A workflow is an initial state plus an ordered list of steps. Each step is one HTTP
request that moves the machine from `from_state` to `to_state` and carries a security
assertion about what should be true when it does.

```
initial_state ──step 1──> to_state ──step 2──> to_state ──step 3──> terminal_state
                 │                    │                    │
            assertion            assertion            assertion
```

`WorkflowSpec.terminal_state` is the `to_state` of the last step, or `initial_state` if
there are no steps. `WorkflowSpec.required_steps` is every step with `required: true`.

At run time the machine tracks one `state` variable, starting at `initial_state`.
`WorkflowEngine.run_sequence()` executes steps in order, and on a passing step sets
`state = result.observed_state`, which is the step's `to_state` (or the current state if
the step declares none). **A failed step stops the machine** — the code comment says why:
"later steps are meaningless." A sequence whose second step failed tells you nothing about
the third.

### Step outcomes

`WorkflowStepOutcome` in `velora/models/enums.py`:

| Outcome | When `WorkflowEngine._evaluate()` returns it |
| --- | --- |
| `PENDING` | Default on a stored `WorkflowStep` that has not been evaluated. |
| `PASSED` | Every declared assertion held. |
| `ASSERTION_FAILED` | Status, body-contains or body-absent assertion failed. |
| `UNEXPECTED_STATE` | The step declares a `from_state` that is not the machine's current state. |
| `BLOCKED_BY_SCOPE` | The request was refused by scope policy, or the request budget was exhausted. |
| `ERROR` | Transport error on the response. |

`BLOCKED_BY_SCOPE` covers two distinct causes because `_execute()` returns `None` for
both a `ScopeViolation` and a `RateLimitExceeded`. The `ScopeViolation` case additionally
emits a `WORKFLOW_STEP_BLOCKED` record at the custom `SECURITY` log level. The step's
`detail` says "request blocked by scope policy or request budget".

Only `PASSED` counts as success: `StepResult.succeeded` is `outcome == PASSED`, and
`WorkflowRunResult.completed` is `all(s.succeeded for s in self.steps)`.

## YAML specification

Top-level keys read by `load_workflow()`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | — | Required. The file must be a mapping containing it. |
| `description` | string | `""` | Free text. |
| `identity` | string | `""` | An identity name from the authz plan. Informational in the spec. |
| `authorized` | bool | `false` | Must be `true` before the engine will execute the workflow. |
| `initial_state` | string | `"start"` | The machine's starting state. |
| `steps` | list | — | Required in practice: a file with no steps raises `ConfigError`. |

Per-step keys:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | — | Required. Must be unique within the workflow. |
| `url` | string | — | Required. Must start with `http://` or `https://`. |
| `method` | string | `"GET"` | Upper-cased on load. Checked against the verb lists below. |
| `from_state` | string | `""` | State the machine must be in. Empty means "do not check". |
| `to_state` | string | `""` | State after a passing step. Must be non-empty to validate. |
| `required` | bool | `false` | Marks the step for the skip probe. |
| `assertion` | string | `""` | Human-readable security assertion. Must be non-empty to validate. |
| `assert_status_in` | list of int | `[]` | Response status must be in this list. |
| `assert_body_contains` | string | `""` | Substring that must be present in the body. |
| `assert_body_absent` | string | `""` | Substring that must not be present in the body. |
| `headers` | map | `{}` | Request headers for this step. |
| `body` | string | `""` | Parsed into `StepSpec.body`. |

`StepSpec.body` is parsed and stored but `WorkflowEngine._execute()` calls
`client.request(step.method, step.url, headers=step.headers or None)` — it does not pass a
body. A `body:` in a workflow file is currently inert.

`velora workflow create` writes a starter file from `spec.TEMPLATE`, which ships with
`authorized: false` and a comment stating that Velora executes only what is written in the
file and only when `authorized: true`.

## Validation rules

`WorkflowSpec.validate()` returns a list of problems; empty means valid. It sends no
requests. Per step, walking the state machine forward:

1. **Duplicate step name** — `duplicate step name '<name>'`.
2. **Refused verb** — the method is in `REFUSED_METHODS`: `step '<name>' uses <M>, which
   Velora refuses to execute in a workflow (destructive or diagnostic verb)`.
3. **Unsupported verb** — the method is in neither list:
   `step '<name>' uses unsupported method <M>`.
4. **Non-http(s) URL** — `step '<name>' has a non-http(s) url`.
5. **Broken state chain** — a non-empty `from_state` that does not match the state the
   machine is in after the previous steps: `step N '<name>' expects from_state '<X>' but
   the machine is in '<Y>'`.
6. **Missing `to_state`** — `step '<name>' has no to_state`.
7. **Missing assertion** — `step '<name>' has no security assertion`.

A workflow with no steps returns a single problem, `workflow defines no steps`, and stops.

Rule 5 walks the declared chain statically: a step with an empty `from_state` is not
checked and does not break the chain, and the tracked state advances to `to_state or
state`. Rule 7 exists because a step without an assertion tests nothing — it would issue a
request and then have no criterion by which to judge the response.

`tests/unit/test_workflow_planning.py::TestWorkflowSpec` covers a valid spec, the refused
verb, the broken chain, the missing assertion, the duplicate name, the non-http URL, and
`required_steps` / `terminal_state`.

## Refused HTTP verbs

```python
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"})
REFUSED_METHODS = frozenset({"DELETE", "CONNECT", "TRACE"})
```

The comment above them gives the reason: "Destructive verbs are refused outright: Velora
models business processes, it does not delete data on a target."

- `DELETE` removes data. A framework that will not exploit will not destroy either, and a
  workflow test that deletes a record cannot be re-run to check itself.
- `CONNECT` builds a tunnel. That is proxying, not exercising a business process, and it
  would carry traffic past the scope check that authorized the original request.
- `TRACE` is a diagnostic verb with no place in a business flow.

The refusal happens at validation time, and `WorkflowEngine.assess()` runs
`spec.validate()` before any request is sent and raises rather than execute a spec with
problems. A refused verb therefore never reaches the network — it is rejected before the
first request, not skipped during the run.

Anything outside both sets is an unsupported method rather than a refused one, so a typo
produces a clear message instead of a silent fallback to `GET`.

## Explicit authorization

Executing a workflow means driving an application's real business process. There are two
independent gates, both in `WorkflowEngine.assess()`, and both raise `AuthorizationError`:

1. **The definition must be marked authorized.** `spec.authorized` must be `true`, or:
   `workflow '<name>' is not marked authorized; set 'authorized: true' in its definition
   before running it`.
2. **The caller must acknowledge.** `authorization_ack` must be `True`, or:
   `authorization acknowledgement required to execute a workflow`.

The CLI supplies the second through `require_authorization(authorized)` on
`--i-am-authorized`, then passes `authorization_ack=True` into `assess()`.

The two gates are not redundant. The first lives in the file, is reviewable, and travels
with the workflow through version control. The second is the person at the terminal
asserting, at this moment, that they are permitted to run it. A committed file cannot
consent on a future operator's behalf, and a flag on a command line leaves no reviewable
record of which flows were sanctioned.

A third gate is structural: every request goes through the scan's scope-gated
`SafeHTTPClient`, so a step pointing outside the authorized scope is blocked and recorded
as `BLOCKED_BY_SCOPE` regardless of what the file says.

`velora workflow validate` performs no authorization check because it sends no requests.
It does warn when `authorized: false`: "authorized: false — Velora will refuse to execute
this workflow."

## The step-skip probe

This is the part that finds business-logic flaws.

After a baseline run, for each step marked `required` (excluding the terminal step itself),
`_probe_skips()` re-runs the sequence with that step omitted. If the terminal step still
succeeds, the application did not enforce its own ordering server-side.

```
baseline :  login ──> add-item ──> checkout      all PASSED
probe    :  login ────────────────> checkout      terminal still PASSED  ->  BYPASSED
```

Mechanics:

- The probe runs only when `probe_skips` is true **and** `result.completed` is true. A
  baseline that did not complete gives no reference point for what "still succeeded"
  means.
- The terminal step is `spec.steps[-1]`. A required step that *is* the terminal step is
  skipped by the probe, since omitting it would leave nothing to observe.
- Each probe rebuilds its steps with `from_state` cleared:
  `StepSpec(**{**s.__dict__, "from_state": ""})`. The comment says why — "we are
  deliberately breaking it." Leaving the declared chain in place would make every probe
  fail with `UNEXPECTED_STATE` at the step after the omitted one, and the probe would
  report `blocked` for a reason that has nothing to do with the server.
- Each probe records `omitted_step`, `terminal_step`, `terminal_reached`,
  `terminal_status` and a `detail` string.

### The finding it produces

A probe where `terminal_reached` is true produces one finding through
`WorkflowEngine._finding()`:

| Field | Value |
| --- | --- |
| `title` | `Required workflow step '<omitted>' can be skipped before '<terminal>'` |
| `severity` | `Severity.HIGH` |
| `confidence` | `Confidence.FIRM` |
| `status` | `FindingStatus.POTENTIAL` |
| `category` | `business_logic` |
| `cwe_id` | `CWE-841` |
| `owasp_category` | `A04:2021-Insecure Design` |
| `scanner` | `workflow.engine` |
| `validation_state` | `ValidationState.OBSERVED` |
| `endpoint` | The terminal step's URL |

A step that ended `UNEXPECTED_STATE` in the baseline produces a second kind of finding,
`Unexpected workflow state at step '<name>'`, at `Severity.MEDIUM` with the same CWE and
category.

The description of the skip finding contains the reasoning that matters:

> This indicates the business process does not enforce its own ordering server-side. It is
> an INDICATOR: the operator's model of the workflow may be incomplete, so a human must
> validate it.

That caveat is not boilerplate. The probe compares the application against the operator's
*model* of it, and the model can be wrong. A step the operator marked `required` may be
optional by design, in which case skipping it is correct behaviour and the finding is a
false positive of the model, not of the application. The example workflow makes the same
point from the other side: `examples/labs/workflow-checkout.yaml` deliberately leaves
`login` as `required: false`, with a comment explaining that the fixture carries identity
in a static bearer header, so omitting the login *request* does not remove authentication
— marking it required "would make the skip probe report a bypass that is an artifact of
the fixture rather than a real ordering flaw."

So the finding is `Potential`, requires human validation like every other finding, and
`Confidence.FIRM` describes how reliably the *observation* was made, not how certain the
conclusion is.

`_finding()` hardcodes `method="POST"` on the finding regardless of the terminal step's
declared method.

## Evidence and persistence

When `assess()` is given a `Scan`, each baseline step is persisted as an `EvidenceItem`
with `test_name="workflow.step"`, the request method and URL, the observed status, an
excerpt of the form `step '<name>' -> <OUTCOME>: <detail>`, and
`confidence=Confidence.FIRM.score`. The resulting evidence id is attached to the step
result, and the skip finding carries the first three of them.

`WorkflowEngine.persist()` writes a `Workflow` row and one `WorkflowStep` row per baseline
step, recording the declared transition and assertions alongside the observed outcome,
status and state. `assess()` also writes a `workflow_executed` audit entry with the
completion flag, the final state and the probe count.

## CLI

```
velora workflow create   [-o PATH]
velora workflow validate --config PATH [--json]
velora workflow run      --config PATH [--target TEXT] [--scope TEXT] [--allow-private]
                         [--operator TEXT] [--engagement TEXT] [--no-skip-probe]
                         --i-am-authorized
velora workflow report   [--workflow TEXT] [--json]
```

| Command | Flag | Type | Notes |
| --- | --- | --- | --- |
| `create` | `-o`, `--output` | path | Defaults to `workflow.yaml`. Refuses to overwrite an existing file. |
| `validate` | `--config` | path | Required; must exist. |
| | `--json` | flag | Emits the spec, the problem list, `valid` and `authorized`. |
| `run` | `--config` | path | Required; must exist. |
| | `--target` | text | Stored target id or name, used to anchor evidence to a scan. |
| | `--scope` | text | Repeatable allowed domain for the ad-hoc scope policy. |
| | `--allow-private` | flag | Permit private/loopback targets. |
| | `--operator` | text | Recorded on the scan. |
| | `--engagement` | text | Engagement id to attach the workflow to. |
| | `--no-skip-probe` | flag | Runs the baseline only; passes `probe_skips=False`. |
| | `--i-am-authorized` | flag | Required. |
| `report` | `--workflow` | text | Filter by workflow name. |
| | `--json` | flag | Emits each workflow with its stored steps. |

`velora workflow validate` exits `1` when the definition has problems, so it is usable as
a lint step in a pipeline.

`velora workflow run` creates a `Scan` only when `--target` resolves to a stored target;
without one the workflow runs and reports but no evidence, findings or scan row are
written (`assess()` skips evidence and findings when `scan is None`). The ad-hoc scope
policy for the run gets a request budget of `max(60, len(spec.steps) * 6)`, sized for the
baseline plus the probes. The output prints the step table, the final state and
completion flag, the step-skip probe table (marking each `BYPASSED` or `blocked`), and
then every finding prefixed with a warning that all of them require validation.
