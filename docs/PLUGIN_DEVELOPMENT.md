# Plugin development (Plugin SDK 2.0)

A Velora plugin is a **deterministic detector**. It observes a target within scope,
produces evidence, and reports what it saw. It does not decide that a vulnerability
exists — a human does that, after reading the evidence.

That framing is the whole design. Everything below follows from it.

---

## The contract

Every SDK 2.0 plugin declares a `PluginMetadata` contract that Velora validates
**before the plugin is registered**. An invalid contract means the plugin never becomes
loadable, so a mistake surfaces at load time rather than halfway through a scan.

```python
from velora.models.enums import Confidence, Severity
from velora.plugins import PluginMetadata, ScannerType, VeloraPlugin, register_plugin
from velora.scanners.base import CheckOutput, EvidenceItem, ScanContext


@register_plugin
class MyCheck(VeloraPlugin):
    metadata = PluginMetadata(
        id="myorg.my_check",                    # lowercase, dotted, unique
        name="My check",
        version="1.0.0",
        description="Reports X observed on Y.",
        category="configuration",
        scanner_type=ScannerType.PASSIVE,
        severity=Severity.LOW,
        expected_evidence=("response headers",),
        remediation="Do Z.",
        cwe_id="CWE-693",                       # UNKNOWN if you cannot map it honestly
        owasp_category="A05:2021",
    )

    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        resp = await ctx.client.safe_get(ctx.target)
        if resp is None or resp.error:
            return []
        ...
        return []
```

Two complete, working examples ship in [`examples/plugins/`](../examples/plugins/):
`cache_control.py` (PASSIVE) and `wellknown_paths.py` (ACTIVE_SAFE, with a
configuration schema).

### Metadata fields

| Field | Meaning |
|---|---|
| `id` | Unique, lowercase, dotted. Namespace it (`myorg.`) so it cannot collide with a built-in. |
| `name`, `description` | Human-facing. Validated as untrusted text — see [Metadata is untrusted](#metadata-is-untrusted-text). |
| `version` | `MAJOR.MINOR[.PATCH]`. |
| `scanner_type` | What kind of interaction the plugin performs. Decides which profiles may run it. |
| `severity` | The plugin's default severity; an individual detection may differ. |
| `requires_scope` | Always `True`. The field documents the guarantee; setting it `False` is refused. |
| `required_permissions` | The authorization the operator must already hold. Surfaced in plans and reports. |
| `allowed_methods` | HTTP verbs the plugin may issue. Destructive verbs are refused outright. |
| `lab_only` | `True` for plugins that must only run against a system you control. |
| `expected_evidence` | Names of the evidence a detection must carry. Required for anything that detects. |
| `config_schema` | Declared options — see [Configuration](#configuration). |
| `cwe_id`, `owasp_category` | Map honestly or leave `UNKNOWN`. Velora never invents identifiers. |

### Scanner types

| Type | Sends requests? | Runs in `safe` profile | Use for |
|---|---|---|---|
| `PASSIVE` | Plain reads only | yes | Analysing what the scan already collected |
| `ACTIVE_SAFE` | Extra plain reads | yes | Probing additional paths or headers |
| `ACTIVE_INTRUSIVE` | Crafted input | **no** — requires `lab_only=True` and the `lab` profile | Payload-bearing checks |
| `MANUAL_ONLY` | No | yes | Producing guidance for a human tester |

`ACTIVE_INTRUSIVE` without `lab_only=True` is refused at validation. An intrusive check
is only ever appropriate against a system you control, and the contract has to say so.

---

## What a plugin cannot do

These are enforced, not advisory.

**Scope.** A plugin never gets its own HTTP client. It receives the scan's scope-gated
client via `ScanContext`, so `ScopePolicy` checks every request it makes — allowed
domains, IPs and CIDRs, ports, schemes, excluded paths, private-network policy, DNS
rebinding, redirect policy. A blocked request produces an `OUT_OF_SCOPE_REQUEST_BLOCKED`
audit event and `safe_get()` returns `None`. There is no supported way around this, and
`requires_scope=False` is rejected.

**Destructive verbs.** `PUT`, `PATCH`, `DELETE`, `CONNECT` and `TRACE` cannot appear in
`allowed_methods`. `check_method()` also refuses, at call time, any verb the plugin did
not declare.

**Request budget and pacing.** `max_requests`, `max_concurrency`, `request_delay` and
`timeout` come from the scan's scope policy and apply to the shared client. Exhausting
the budget raises `RateLimitExceeded`, which ends the scan cleanly.

**Secrets.** Response bodies are redacted by the client before a plugin ever sees them.
Do not defeat that: never write a raw credential, cookie value or token into a
`CheckOutput` or `EvidenceItem`. If your plugin needs a credential, take an
**environment variable name** in its config and read the value at run time — Velora
stores the reference, never the value.

**Confirmation.** A plugin returns `CheckOutput` objects. They become findings with
status `Potential`. Nothing a plugin can set makes a finding `Confirmed`; only a human
reviewer, through `velora finding validate`, does that.

**Impact claims.** Say what you observed. If you did not demonstrate exploitability, do
not assert it — write the limit into the detection's description, as the shipped
examples do.

---

## Lifecycle

```
configure(config)  →  run(ctx)  →  cleanup()
```

`configure()` validates and applies configuration; override `on_configure()` to derive
state from `self.config`. `run()` does the work. `cleanup()` runs **whether or not
`run()` succeeded**, so anything acquired gets released. All three are optional except
`run()` — a 1.x `SecurityCheck` that defines none of them still runs unchanged.

A plugin that raises is isolated: the failure is recorded against that check id and the
scan continues with the rest.

---

## Configuration

Declare options; do not read a free-form dict. Unknown keys are **refused**, so a typo
is an error at load time instead of a check that silently ran on defaults.

```python
from velora.plugins import ConfigField

config_schema = {
    "max_paths": ConfigField(type="int", default=10, minimum=1, maximum=25,
                             description="Upper bound on requests issued."),
    "mode": ConfigField(type="str", default="fast", choices=("fast", "slow")),
    "token_ref": ConfigField(type="str", required=True,
                             description="Name of the env var holding the token."),
}
```

Supported types: `str`, `int`, `float`, `bool`, `list[str]`. A `required` field must not
carry a default. Values are type-, range- and choice-checked; `True` is not accepted for
an `int`.

Read resolved values from `self.config` inside `on_configure()` or `run()`.

---

## Metadata is untrusted text

Plugin metadata is rendered into logs, terminals, HTML and JSON reports, and — for the
AI layer — prompts. So it is validated like any other untrusted string:

* **Control and formatting characters** are refused, including NUL and terminal escape
  sequences (`\x1b[`), which could otherwise rewrite a terminal or a log line.
* **Prompt-injection markers** are refused: `ignore previous`, `system:`, `assistant:`,
  `<|`, `|>`, and fenced-code markers.
* **Length caps**: id 64, name 120, description 2000 characters.
* **References** must be `http(s)` URLs.

This is about keeping a careless plugin from corrupting output, not about containing a
hostile one. See below.

---

## Loading plugins

```bash
velora plugins load --dir ./my-plugins
velora plugins list --sdk-only
velora plugins show myorg.my_check
velora plugins disable myorg.my_check
```

The loader refuses a module that resolves outside the named directory (a symlink
escape), is not a regular file, or exceeds 512 KB. A module that raises, or whose
contract is rejected, is reported with its reason; the rest still load. A plugin may not
reuse an existing check's id, so it cannot silently shadow a built-in.

> **Loading a plugin executes its Python in the Velora process.** The checks above make
> loading a deliberate act and catch mistakes — they do **not** sandbox hostile code,
> and nothing short of a separate process with its own privileges would. Read a plugin
> before you load it, exactly as you would any other code you are about to run.

---

## Testing your plugin

Run it against a local lab application, never a public site. Velora's own suite uses a
stdlib HTTP fixture (`tests/fixtures/labapp.py`) that needs no network:

```python
from tests.fixtures.labapp import LabApp

with LabApp() as app:
    ...  # point a scan at app.base_url
```

Test at minimum:

1. the contract validates (`validate_metadata(MyCheck.metadata)`);
2. configuration rejects unknown keys and out-of-range values;
3. `run()` returns `[]` when the condition is absent — a detector that always fires is
   a false-positive generator;
4. every `CheckOutput` carries the evidence `expected_evidence` promised;
5. no credential or token appears in any output.

`tests/unit/test_plugin_sdk.py` covers the SDK itself and asserts that the shipped
examples satisfy their own contract.

---

## Checklist before shipping

- [ ] `id` is namespaced and unique
- [ ] `scanner_type` matches what the plugin actually does
- [ ] `allowed_methods` is the narrowest set that works
- [ ] `expected_evidence` names what a reviewer will need
- [ ] Every detection carries that evidence
- [ ] `cwe_id` / `owasp_category` are mapped honestly, or `UNKNOWN`
- [ ] The description states what was observed, not what it might mean
- [ ] No credential, token or cookie value reaches any output
- [ ] `cleanup()` releases anything `run()` acquired
- [ ] Tested against a local lab you control
