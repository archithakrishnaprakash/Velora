# Velora CLI reference

Every command below was run against the code in this repository. Flags, defaults and
output shapes are taken from `velora <command> --help` and from real executions against
the bundled local lab app.

> **Authorized use only.** Velora is for systems you own or have explicit written
> authorization to test. Every command that sends a request requires `--i-am-authorized`.
> Every example in this file targets `127.0.0.1` — the bundled lab app. Never point these
> commands at a public site.

## Invocation

The console script is `velora`. From a source checkout without installing, the module
entrypoint is equivalent:

```bash
velora --help
python -m velora.cli.main --help
```

Root options:

| Option | Meaning |
| --- | --- |
| `--config TEXT` | Path to a `config.yaml` to use instead of the default location |
| `--version` | Print the version and exit |
| `-h`, `--help` | Help. Available on every command and group |

Two environment variables control where state lives:

| Variable | Effect |
| --- | --- |
| `VELORA_DATA_DIR` | Database, reports and other state (default `~/.local/share/velora`) |
| `VELORA_CONFIG_DIR` | `config.yaml` location (default `~/.config/velora`) |

## Typical session

This is a complete run against the bundled lab app, in order. Start the lab app in one
terminal:

```bash
python scripts/run_labapp.py 8099
```

Then, in another terminal:

```bash
# 1. One-time setup
velora init
velora doctor

# 2. Register the target and its scope boundary
velora target add --name labshop --url http://127.0.0.1:8099/ \
  --owner you --authorization LAB_ONLY --allow-private

# 3. Confirm the boundary does what you think it does
velora scope validate --target labshop --url http://127.0.0.1:8099/admin
velora scope validate --target labshop --url http://external.example.net/

# 4. Look before you scan
velora recon --target http://127.0.0.1:8099/ --allow-private --i-am-authorized

# 5. Full assessment
velora scan --target labshop --profile lab --operator you \
  --allow-private --i-am-authorized --scan-id-file /tmp/scan.id
SCAN=$(cat /tmp/scan.id)

# 6. Triage
velora findings --scan "$SCAN" --severity High
velora finding show WEB-5NEP4G
velora analyze --finding WEB-5NEP4G
velora finding validate WEB-5NEP4G --operator you --note "confirmed by hand"

# 7. Context
velora attack-map --scan "$SCAN"
velora attack-map paths --scan "$SCAN" --evidenced-only
velora posture show --scan "$SCAN" --save

# 8. Deliverables
velora report --scan "$SCAN" --format html --format json --format sarif
velora gate evaluate --scan "$SCAN" --fail-on critical --fail-on high

# 9. Read it back in a browser
velora dashboard
```

A real run of step 5 against the lab app produced 14 findings across 11 checks with 35
requests and 0 blocked requests.

---

## Stage 0 — Setup and environment

### `velora init`

Creates `config.yaml` if it does not exist and initializes the database. Takes no options.

```bash
velora init
```

Output names both paths, for example `wrote config: ~/.config/velora/config.yaml` and
`database ready: sqlite:////home/you/.local/share/velora/velora.db`. If the config file
already exists it warns and leaves it alone; the database is still initialized.

### `velora doctor`

Environment and installation health checks. Takes no options. Exits `1` if any check
FAILs, `0` otherwise (warnings do not fail it).

```bash
velora doctor
```

It checks Python ≥ 3.11, the OS, the nine import names `httpx`, `bs4`, `pydantic`,
`jinja2`, `yaml`, `cryptography`, `click`, `starlette`, `uvicorn`, the config file, data
directory writability, database schema and pending migrations, free disk space, the four
external tools `nmap`, `zap.sh`, `nuclei`, `docker`, and the configured AI provider.
Missing external tools are warnings, not failures.

### `velora config`

Prints the effective configuration as JSON, with secrets omitted. Takes no options.

```bash
velora config
```

### `velora version`

Prints `Velora v0.1.0`. Takes no options. (`velora --version` prints the same thing.)

---

## Stage 1 — Targets and scope

### `velora target add`

Creates a target and its scope policy in one step.

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--name` | text | required | |
| `--url` | text | required | |
| `--owner` | text | `""` | |
| `--authorization` | `UNAUTHORIZED`/`LAB_ONLY`/`AUTHORIZED` | `LAB_ONLY` | |
| `--note` | text | `""` | Free-text authorization note |
| `--scope` | text, repeatable | derived from the URL host | Allowed domain |
| `--allow-private` | flag | off | Permit private/loopback targets |

```bash
velora target add --name labshop --url http://127.0.0.1:8099/ \
  --owner you --authorization LAB_ONLY --allow-private
```

The created scope policy always includes ports 80, 443, 8080 and 3000 plus the port in
the URL. A hostname goes into `allowed_domains`; a literal IP goes into `allowed_ips`.

### `velora target list`

Lists targets as `ID | NAME | URL | AUTHORIZATION`. Takes no options.

### `velora target show TARGET_ID`

Prints one target as JSON. The argument accepts either the target id or its name.

```bash
velora target show labshop
```

### `velora scope validate`

Checks one URL against a target's stored scope policy. Sends no request.

| Option | Type | Notes |
| --- | --- | --- |
| `ACTION` | positional, only `validate` is accepted | |
| `--target` | text, required | Target id or name |
| `--url` | text, required | The URL to test |

```bash
velora scope validate --target labshop --url http://127.0.0.1:8099/admin
velora scope validate --target labshop --url http://external.example.net/
```

Output is `IN SCOPE: <url>  (in-scope-ip)` or
`OUT OF SCOPE: <url>  (domain-not-in-scope:external.example.net)`. The reason string is
the scope engine's own verdict, not a summary.

---

## Stage 2 — Reconnaissance

These three commands are ad-hoc: they take a URL, build a scope policy on the fly, send
requests, print a table and store nothing. They do not create a scan.

### `velora recon`

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--target` | text | required | URL |
| `--scope` | text, repeatable | host of the URL | Extra in-scope domain |
| `--allow-private` | flag | off | |
| `--i-am-authorized` | flag | required | |

```bash
velora recon --target http://127.0.0.1:8099/ --allow-private --i-am-authorized
```

Reports base status, `Server`, allowed methods, whether `robots.txt` and `security.txt`
exist, DNS A records, and a technology table when anything is detected. Its internal
request budget is 200.

### `velora crawl`

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--target` | text | required | URL |
| `--scope` | text, repeatable | host of the URL | |
| `--allow-private` | flag | off | |
| `--depth` | integer | `3` | |
| `--max-pages` | integer | `100` | |
| `--i-am-authorized` | flag | required | |

```bash
velora crawl --target http://127.0.0.1:8099/ --depth 2 --max-pages 50 \
  --allow-private --i-am-authorized
```

Prints an endpoint table (`METHOD`, `URL`, `STATUS`, `api` marker) and a summary line
with `pages`, `blocked_out_of_scope`, `off_origin` and `forms`. The request budget is
`max_pages * 3`.

### `velora fingerprint`

| Option | Type | Notes |
| --- | --- | --- |
| `--target` | text, required | URL |
| `--scope` | text, repeatable | |
| `--allow-private` | flag | |
| `--i-am-authorized` | flag, required | |

```bash
velora fingerprint --target http://127.0.0.1:8099/ --allow-private --i-am-authorized
```

Fetches the base URL once (budget 20, no request delay) and prints
`TECH | VERSION | CONF | CATEGORIES`.

---

## Stage 3 — Scanning

### `velora scan`

The full pipeline: recon, crawl, checks, findings, correlation, knowledge graph.

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--target` | text | required | Stored target id/name, **or** a full `http(s)` URL |
| `--profile` | `safe`/`standard`/`lab` | `safe` | |
| `--scope` | text, repeatable | — | Allowed domain, for URL targets |
| `--operator` | text | `""` | Recorded on the scan and in the audit log |
| `--allow-private` | flag | off | |
| `--i-am-authorized` | flag | required | |
| `--scan-id-file` | path | — | Writes the bare scan id plus a newline, for pipelines |

```bash
velora scan --target labshop --profile lab --operator you \
  --allow-private --i-am-authorized --scan-id-file /tmp/scan.id
```

If `--target` is a URL that matches no stored target, Velora creates a target and scope
policy for it on the spot. `--allow-private` makes the new target `LAB_ONLY`; without it
the target is created as `AUTHORIZED`.

Profiles change which checks run. Against the lab app, `safe` ran 10 checks and `lab` ran
11 — `input.reflection` is the active check that `safe` excludes.

| Profile | Meaning |
| --- | --- |
| `safe` | Passive and low-touch checks only. The default. |
| `standard` | Safe checks plus light active probes. Authorized targets only. |
| `lab` | More intensive. Explicitly-authorized lab targets only. |

The command prints a `stats` JSON line (`requests`, `blocked_requests`, `endpoints`,
`technologies`, `findings`, `correlations`, `knowledge_entities`, `findings_enriched`,
`checks_run`, `checks_failed`) and a findings table sorted by priority score.

### `velora scans`

Lists all scans as `SCAN | TARGET | PROFILE | STATUS | FINDINGS`. Takes no options.

### `velora scan-show SCAN_ID`

Prints one scan's status, profile, operator, stats and its findings table. No options.

```bash
velora scan-show SCAN-W6XCXA
```

---

## Stage 4 — Findings and evidence

### `velora findings`

| Option | Type | Notes |
| --- | --- | --- |
| `--scan` | text | Restrict to one scan. Omit for all scans. |
| `--severity` | text | Case-insensitive exact match on the severity name |

```bash
velora findings --scan SCAN-W6XCXA --severity High
```

Columns are `ID | PRIO | SEVERITY | TITLE | STATUS`, sorted by priority score descending.

### `velora finding show FINDING_ID`

Prints title, severity, id, status, confidence, priority, endpoint, category, detecting
check, description, impact, remediation, any stored AI analysis, and every evidence
record. No options.

### `velora finding validate FINDING_ID`

Marks a finding `Confirmed`. This is the only path to `Confirmed` — no scanner and no AI
provider can set it.

| Option | Type | Notes |
| --- | --- | --- |
| `--operator` | text, required | Recorded as `validated_by` |
| `--note` | text | |

```bash
velora finding validate WEB-5NEP4G --operator you --note "confirmed by hand"
```

### `velora finding reject FINDING_ID`

Marks a finding a false positive. Same `--operator` (required) and `--note` options.

### `velora finding remediated FINDING_ID`

Marks a finding remediated. Same `--operator` (required) and `--note` options.

### `velora evidence`

Lists evidence rows for a scan as `ID | FINDING | TEST | STATUS | EXCERPT`.

| Option | Type | Notes |
| --- | --- | --- |
| `--scan` | text, required | |

```bash
velora evidence --scan SCAN-W6XCXA
```

Excerpts are already redacted at capture time — secret values are never persisted.

### `velora reproduce`

Builds a reproducibility package for a finding: Velora version, detecting check, scan and
profile, a SHA-256 hash of the scope policy in force, validation state, evidence ids,
finding fingerprint, the scope summary, and numbered steps ending in a comparison against
the recorded evidence excerpts. No credentials or secrets are included.

The group itself runs when given `--finding`, and there is one subcommand.

| Form | Options |
| --- | --- |
| `velora reproduce --finding ID` | `--finding`, `--json`, `--output PATH` |
| `velora reproduce show FINDING_ID` | `--json`, `--output PATH` |

```bash
velora reproduce --finding WEB-5NEP4G
velora reproduce show WEB-5NEP4G --json --output /tmp/repro.json
```

`--output` writes the JSON package to a file; `--json` prints it instead of the table.
Both can be combined.

---

## Stage 5 — Correlation and AI

### `velora attack-map`

With no subcommand it prints the graph summary for a scan and requires `--scan`.

```bash
velora attack-map --scan SCAN-W6XCXA
```

It reports nodes by kind, edges by relation, edges by validation status, and warns when
hypothesis edges are present.

#### `velora attack-map paths`

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--scan` | text | required | |
| `--max-depth` | integer | `6` | |
| `--max-paths` | integer | `25` | |
| `--evidenced-only` | flag | off | Hide hypothesis paths |
| `--json` | flag | off | |

```bash
velora attack-map paths --scan SCAN-W6XCXA --evidenced-only --max-paths 10
```

Each path is labelled `[EVIDENCED]` or `[HYPOTHESIS]` and scored by its weakest link. The
footer states how many of the listed paths are hypotheses.

#### `velora attack-map explain`

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--scan` | text | required | |
| `--index` | integer | `1` | 1-based index into the path list |
| `--max-depth` | integer | `6` | |

```bash
velora attack-map explain --scan SCAN-W6XCXA --index 2
```

Each step is prefixed `[OBSERVED ]`, `[INFERRED]` or `[HYPOTHESIS]` with its confidence,
validation state, source and evidence ids.

### `velora analyze`

Runs AI-assisted analysis on one finding. Advisory only.

| Option | Type | Notes |
| --- | --- | --- |
| `--finding` | text, required | |

```bash
velora analyze --finding WEB-5NEP4G
```

Prints provider, model, classification, confidence, `human_validation_required` and a
reasoning summary. The default provider is `heuristic`, which is offline and needs no key.
There is **no** `velora ai` group — this single command is the AI entrypoint.

---

## Stage 6 — Deeper testing

### `velora diff`

Differential request analysis: fetch two controlled exchanges and classify what differs.
Both requests pass through the scope engine.

`velora diff compare` and `velora diff create` are registered as the same operation —
running a comparison is what creates the stored observation. Note that only `compare`
carries the option decorators: `velora diff create --help` lists no options at all, and
passing any of them to `create` fails. Use `compare`.

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--baseline` | text | required | Baseline URL |
| `--candidate` | text | required | Candidate URL |
| `--method` | text | `GET` | Applied to both exchanges |
| `--baseline-header` | text, repeatable | — | `'Name: value'` |
| `--candidate-header` | text, repeatable | — | `'Name: value'` |
| `--label` | text | `""` | Stored with the observation |
| `--scan` | text | — | Attach to an existing scan id |
| `--scope` | text, repeatable | — | |
| `--allow-private` | flag | off | |
| `--ignore-timing` | flag | off | Ignore response-timing differences |
| `--json` | flag | off | |
| `--i-am-authorized` | flag | required | |

```bash
velora diff compare \
  --baseline "http://127.0.0.1:8099/api/orders/1" \
  --candidate "http://127.0.0.1:8099/api/orders/2" \
  --baseline-header "Authorization: Bearer alice-token" \
  --candidate-header "Authorization: Bearer bob-token" \
  --label "owner vs other user" --allow-private --i-am-authorized
```

Every result is stored with `validation_required=true`. A difference is an observation,
not a vulnerability.

| Subcommand | Options |
| --- | --- |
| `velora diff list` | `--scan` |
| `velora diff show DIFFERENTIAL_ID` | `--json` |

### `velora authz`

Multi-identity authorization testing. Credentials are never stored in the plan file —
`secret_ref` names an environment variable that is read at run time.

| Subcommand | Options |
| --- | --- |
| `authz init` | `-o`, `--output PATH` |
| `authz plan` | `--config PATH` (required), `--json` |
| `authz run` | see below |
| `authz compare` | `--scan`, `--json` |
| `authz report` | `--scan`, `--json` |

`authz run` options:

| Option | Type | Notes |
| --- | --- | --- |
| `--config` | path, required | The plan YAML |
| `--target` | text | Stored target id/name to attach the scan to |
| `--scope` | text, repeatable | Additional in-scope domain |
| `--allow-private` | flag | |
| `--operator` | text | |
| `--engagement` | text | |
| `--strict` | flag | Fail if any identity's credential is missing (recommended) |
| `--no-findings` | flag | Record tests but create no findings |
| `--i-am-authorized` | flag, required | |

```bash
velora authz init -o authz.yaml
# edit authz.yaml, then export the referenced variables
export VELORA_IDENTITY_ALICE=alice-token
export VELORA_IDENTITY_BOB=bob-token
export VELORA_IDENTITY_ADMIN=admin-token

velora authz plan --config authz.yaml     # builds the matrix, sends nothing
velora authz run --config authz.yaml --target labshop \
  --allow-private --operator you --strict --i-am-authorized
velora authz report
```

`authz plan` prints the identity table (including which credentials are missing) and the
identity × resource matrix with the expectation and the reason it was derived. It sends no
requests. `authz run` executes the matrix, prints expected vs observed per case, and
creates `Potential` findings for weaknesses. Outcomes seen in a real lab run:
`AS_EXPECTED`, `INCONCLUSIVE`, `HORIZONTAL_AUTHORIZATION_WEAKNESS`,
`VERTICAL_AUTHORIZATION_WEAKNESS`, `UNAUTHENTICATED_ACCESS`.

### `velora workflow`

Model a business process as a state machine and test that the application enforces its own
order.

| Subcommand | Options |
| --- | --- |
| `workflow create` | `-o`, `--output PATH` |
| `workflow validate` | `--config PATH` (required), `--json` |
| `workflow run` | see below |
| `workflow report` | `--workflow`, `--json` |

`workflow run` options:

| Option | Type | Notes |
| --- | --- | --- |
| `--config` | path, required | |
| `--target` | text | Stored target to anchor evidence |
| `--scope` | text, repeatable | |
| `--allow-private` | flag | |
| `--operator` | text | |
| `--engagement` | text | |
| `--no-skip-probe` | flag | Do not probe whether required steps can be skipped |
| `--i-am-authorized` | flag, required | |

```bash
velora workflow validate --config examples/labs/workflow-checkout.yaml
velora workflow run --config examples/labs/workflow-checkout.yaml \
  --target labshop --allow-private --operator you --i-am-authorized
velora workflow report
```

A definition must set `authorized: true` before it will execute. `workflow validate` sends
no requests. In a real run against the lab app, the step-skip probe found that the required
`add-item` step could be omitted before `checkout`, and recorded it as a `Potential` High
finding.

### `velora benchmark`

Measure detection against ground truth. The `labshop` suite is built into the code, with
ground truth derived from `tests/fixtures/labapp.py`. `--suite-dir` loads additional suites
from YAML.

| Subcommand | Options |
| --- | --- |
| `benchmark list` | `--suite-dir` (default `examples/labs`), `--json` |
| `benchmark run` | see below |
| `benchmark report` | `--run` (default: latest), `--json` |

`benchmark run` options:

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--suite` | text | `labshop` | |
| `--suite-dir` | text | `examples/labs` | |
| `--target` | text | required | Benchmark target URL or stored id |
| `--profile` | `safe`/`standard`/`lab` | scanner default | |
| `--scan` | text | — | Score an existing scan instead of running a new one |
| `--allow-private` | flag | off | |
| `--operator` | text | — | |
| `--output` | path | — | Write the JSON report here |
| `--i-am-authorized` | flag | required | |

```bash
velora benchmark list
velora benchmark run --suite labshop --target http://127.0.0.1:8099/ \
  --profile lab --allow-private --operator you --i-am-authorized \
  --output /tmp/bench.json
```

Metrics reported are true/false positives and negatives, precision, recall, F1, FPR, FNR,
detection coverage and evidence completeness. A real run scored 7 TP / 2 TN / 0 FP / 0 FN
on the 9-case `labshop` suite.

---

## Stage 7 — Lifecycle

### `velora remediation`

| Subcommand | Options |
| --- | --- |
| `remediation start FINDING_ID` | `--owner`, `--note` |
| `remediation ready FINDING_ID` | `--owner`, `--note` |
| `remediation retest FINDING_ID` | `--scan`, `--profile`, `--operator`, `--i-am-authorized` |
| `remediation verify` | `--scan` (required), `--retest-scan` (required), `--operator` |
| `remediation list` | `--status`, `--json` |

`--status` accepts `OPEN`, `REMEDIATION_IN_PROGRESS`, `READY_FOR_RETEST`, `FIX_VERIFIED`,
`FIX_FAILED`, `REGRESSION_DETECTED`.

```bash
velora remediation start WEB-DZ5R7S --owner platform --note "patching the login form"
velora remediation ready WEB-DZ5R7S --owner platform
velora remediation retest WEB-DZ5R7S --scan SCAN-HCK5TX --operator you
velora remediation list
```

`remediation retest` runs a fresh scan unless `--scan` names an existing one to use
instead; a fresh scan requires `--i-am-authorized`. The verdict reports whether the issue
is still present, whether the affected endpoint was actually covered by the retest, and
the finding fingerprint it matched on.

`remediation verify` scores every finding of one scan against a retest scan in one pass.

### `velora regression`

| Subcommand | Options |
| --- | --- |
| `regression compare` | `--previous` (required), `--current` (required), `--no-persist`, `--json` |
| `regression report` | `--current` (required), `--json` |

```bash
velora regression compare --previous SCAN-W6XCXA --current SCAN-HCK5TX
velora regression report --current SCAN-HCK5TX
```

`compare` prints a per-severity previous/current/delta table and a change-classification
count (`NEW_FINDING`, `PERSISTING_FINDING`, `FIXED_FINDING`, and reintroduction). It warns
when the two scans belong to different targets.

### `velora posture`

The Velora Security Posture Score: a 0–100 aggregate trend indicator. It is not CVSS.

| Subcommand | Options |
| --- | --- |
| `posture show` | `--scan` (required), `--save`, `--json` |
| `posture trend` | `--target` (required), `--json` |
| `posture methodology` | none |

```bash
velora posture show --scan SCAN-W6XCXA --save
velora posture trend --target TGT-RE4HJD
velora posture methodology
```

`posture trend --target` takes a target **id**, not a name — unlike most other `--target`
options. `posture methodology` prints the severity penalties, the confidence weighting
(`0.55 + 0.45 × scanner_confidence`), the seven category weights and the bounded
remediation/regression adjustments. A category with no coverage is reported as
"not assessed", never as 100.

---

## Stage 8 — Delivery

### `velora report`

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `--scan` | text | required | |
| `--format` | `html`/`json`/`pdf`/`sarif`, repeatable | `html` and `json` | |
| `--output-dir` | text | `reports.output_dir` from config | |

```bash
velora report --scan SCAN-W6XCXA --format html --format json --format sarif \
  --output-dir ./reports
```

Files are named `<SCAN_ID>.<ext>`. `--format pdf` requires WeasyPrint; when it is not
installed Velora logs a warning and writes HTML instead — the command still succeeds, and
the output line says `html`, not `pdf`.

### `velora gate`

CI/CD security gate. Exit codes: `0` PASS, `1` SECURITY GATE FAILURE, `2`
CONFIGURATION/EXECUTION ERROR. All three were verified.

| Subcommand | Options |
| --- | --- |
| `gate init` | `-o`, `--output PATH` |
| `gate evaluate` | see below |
| `gate history` | `--scan` |

`gate evaluate` options:

| Option | Type | Notes |
| --- | --- | --- |
| `--scan` | text, required | |
| `--policy` | path | Gate policy YAML. Without it, the inline options below apply. |
| `--fail-on` | `informational`/`low`/`medium`/`high`/`critical`, repeatable | Severity that fails the build |
| `--max-cvss` | float | |
| `--max-priority-score` | float | |
| `--max-new-findings` | integer | Relative to `--baseline` |
| `--baseline` | text | Baseline scan for new-finding and regression rules |
| `--no-fail-on-regression` | flag | |
| `--ignore-unvalidated` | flag | Count only human-validated findings |
| `--json` | flag | |
| `--output` | path | Write the JSON result here |

```bash
velora gate init -o gate.yaml
velora gate evaluate --scan SCAN-W6XCXA --policy gate.yaml --output gate.json
echo "exit=$?"
velora gate history --scan SCAN-W6XCXA
```

Every evaluation is persisted, so `gate history` shows PASS and FAIL runs for the same
scan in order.

### `velora engagement`

Groups targets, identities, scans, findings and reports.

| Subcommand | Options |
| --- | --- |
| `engagement create` | `--name` (required), `--client`, `--description`, `--operator`, `--authorization-reference`, `--granted-by` |
| `engagement attach ENGAGEMENT_ID` | `--target` (required) |
| `engagement list` | `--json` |
| `engagement show ENGAGEMENT_ID` | `--json` |
| `engagement scope ENGAGEMENT_ID` | none |
| `engagement status ENGAGEMENT_ID` | `--set` (required): `PLANNED`/`ACTIVE`/`COMPLETED`/`CLOSED` |
| `engagement report ENGAGEMENT_ID` | `--format`, `--output-dir` |

```bash
velora engagement create --name "Q4 LabShop" --client LabShop --operator you \
  --authorization-reference SEC-1042 --granted-by CISO
velora engagement attach ENG-889PPQ --target labshop
velora engagement status ENG-889PPQ --set ACTIVE
velora engagement scope ENG-889PPQ
velora engagement report ENG-889PPQ --format html --output-dir ./reports
```

`--authorization-reference` is a ticket or contract reference. It is never a secret.

`engagement scope` prints one row per target with its domains, ports and whether private
addresses are permitted — useful as the boundary statement in an authorization record.

### `velora plan`

Generate, review, approve and execute assessment plans. A plan may only reference
capabilities from a fixed catalog; a planner cannot invent an action, and no step runs
without human approval and a scope re-check immediately before execution.

| Subcommand | Options |
| --- | --- |
| `plan capabilities` | `--json` |
| `plan generate` | `--target` (required), `--planner` (`heuristic`/`ai`, default `heuristic`), `--scan`, `--engagement`, `--scope`, `--allow-private` |
| `plan list` | none |
| `plan review PLAN_ID` | `--json` |
| `plan approve PLAN_ID` | `--operator` (required), `--step` (repeatable) |
| `plan execute PLAN_ID` | `--operator`, `--scope`, `--allow-private`, `--dry-run`, `--i-am-authorized` |

```bash
velora plan capabilities
velora plan generate --target labshop --planner heuristic --allow-private
velora plan review PLAN-4C8SPQ
velora plan approve PLAN-4C8SPQ --operator you
velora plan execute PLAN-4C8SPQ --operator you --allow-private --dry-run --i-am-authorized
```

The catalog has eight entries: `recon`, `crawl`, `scan.safe`, `scan.standard`,
`authz.matrix`, `differential.compare`, `workflow.assess`, `benchmark`. Each carries a risk
level, a safe/active mode and whether explicit review is always required.

`plan generate` sends no requests. `plan approve` cannot approve an out-of-scope step.
`--step` approves only the named step ids; without it every step is approved.
`plan execute --dry-run` prints the exact CLI command each step maps to and runs nothing.

### `velora plugins`

| Subcommand | Options |
| --- | --- |
| `plugins list` | `--sdk-only` |
| `plugins load` | `--dir PATH` (required) |
| `plugins enable PLUGIN_ID` | none |
| `plugins disable PLUGIN_ID` | none |
| `plugins show PLUGIN_ID` | none |

```bash
velora plugins list
velora plugins show headers.security_headers
velora plugins disable tls.configuration
velora plugins enable tls.configuration
```

The eleven built-in checks are:

| ID | Category | Type |
| --- | --- | --- |
| `auth.indicators` | authentication | safe |
| `authz.consistency` | authorization | safe |
| `config.directory_exposure` | configuration | safe |
| `config.http_methods` | configuration | safe |
| `config.security_txt` | configuration | safe |
| `cookies.attributes` | session | safe |
| `headers.security_headers` | configuration | safe |
| `headers.server_version` | information_disclosure | safe |
| `infodisc.indicators` | information_disclosure | safe |
| `input.reflection` | input_validation | active |
| `tls.configuration` | tls | safe |

All eleven declare SDK `1.x`, so `plugins list --sdk-only` lists nothing until external
SDK 2.0 plugins are loaded.

`plugins load` executes the Python in each module in the current process. It validates each
SDK plugin's declared contract and refuses symlinks that escape the directory, but it
cannot make untrusted code safe — read a plugin before loading it.

```bash
velora plugins load --dir examples/plugins
```

The two bundled example plugins, `example.cache_control` (passive) and
`example.wellknown_paths` (active_safe), both register as SDK 2.0.

The plugin registry is **process-local**. A later `velora plugins list` is a new process
and will not show them: run against the bundled examples, `plugins load` reported both as
loaded and the next `plugins list --sdk-only` printed `(none)`. External plugins take
effect only within the process that loaded them.

### `velora dashboard`

Starts the read-only web dashboard and JSON API via uvicorn.

| Option | Type | Default |
| --- | --- | --- |
| `--host` | text | `api.host` from config (`127.0.0.1`) |
| `--port` | integer | `api.port` from config (`8787`) |

```bash
velora dashboard
velora dashboard --host 127.0.0.1 --port 8811
```

The default bind is loopback. See `docs/API.md` for the routes. Do not run the dashboard
as root.

---

## Command index

| Command | Stage |
| --- | --- |
| `init`, `doctor`, `config`, `version` | Setup |
| `target add`, `target list`, `target show`, `scope validate` | Targets and scope |
| `recon`, `crawl`, `fingerprint` | Reconnaissance |
| `scan`, `scans`, `scan-show` | Scanning |
| `findings`, `finding show/validate/reject/remediated`, `evidence`, `reproduce` | Findings |
| `attack-map`, `attack-map paths`, `attack-map explain`, `analyze` | Correlation and AI |
| `diff`, `authz`, `workflow`, `benchmark` | Deeper testing |
| `remediation`, `regression`, `posture` | Lifecycle |
| `report`, `gate`, `engagement`, `plan`, `plugins`, `dashboard` | Delivery |
