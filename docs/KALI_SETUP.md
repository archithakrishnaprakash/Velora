# Velora on Kali Linux

Kali is the primary development platform for Velora. This page covers the system packages,
the non-root user requirement, the external-tool adapters Velora can use when those tools
are installed, the lab material in this repository, and a first authorized scan.

---

## Authorization

**Velora is for systems you own or are explicitly authorized to test.**

Running a scanner against a host you do not own or have written permission to assess is
unlawful in most jurisdictions, regardless of intent and regardless of whether anything
breaks. Kali makes it trivially easy to point a tool at anything reachable; Velora will
not stop you from typing an address, and the scope engine only constrains what a scan does
*after* you have named the target.

Before any scan against anything other than your own lab:

- Have written authorization naming the hosts, the dates and the permitted activity.
- Record the reference with the engagement: `velora engagement create --name ... --authorization-reference TICKET-123 --granted-by "Name, Title"`.
- Confirm the boundary before you scan: `velora engagement scope <ENGAGEMENT_ID>` and `velora scope validate --target <target> --url <url>`.
- Pass `--i-am-authorized` only when that is true. It is an assertion you are making, recorded on the scan and in the audit log.

Velora does not perform exploitation, credential theft, persistence, evasion or
destructive actions. That is a property of the tool, not a substitute for authorization.

---

## System packages

Kali ships Python 3.11+ and pip. The only package commonly missing is `venv`:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

For PDF reports, WeasyPrint needs system libraries in addition to the Python package:

```bash
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```

PDF output is optional. Without WeasyPrint, `velora report --format pdf` logs a warning
and writes HTML instead; the command still succeeds.

Then install as in `docs/INSTALLATION.md`:

```bash
git clone https://github.com/architha/velora
cd velora
./install.sh
```

`install.sh` puts the virtualenv at `~/.local/share/velora/venv` and symlinks the CLI to
`~/.local/bin/velora`. On Kali that directory is normally already on `PATH` for a regular
user; the installer warns if it is not.

---

## Run as a non-root user

Kali's default shell is often root. Do not install or run Velora there.

```bash
sudo useradd -m -s /bin/bash pentest
sudo usermod -aG sudo pentest
su - pentest
cd ~ && git clone https://github.com/architha/velora && cd velora && ./install.sh
```

**The web dashboard must not run as root.** It is an HTTP server with no authentication of
its own, rendering assessment data — target lists, evidence excerpts, audit entries — that
is sensitive by nature. Running it as root means any flaw in the server, in Starlette, or
in a template becomes root on the box; it also gives the process write access to the whole
filesystem when the only thing it legitimately needs is read access to one SQLite file.
Nothing the dashboard does requires privilege: it binds `127.0.0.1:8787`, a high port, and
never sends a request to a target.

The packaging enforces this in both supported deployments:

- `docker/Dockerfile` creates a system user `velora` and ends with `USER velora`.
- `systemd/velora.service` runs as `User=velora` with `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `ProtectHome=true` and an empty `CapabilityBoundingSet`.

Keep the default bind address. `velora dashboard` defaults to `127.0.0.1`. If you need it
on another machine, tunnel it:

```bash
ssh -L 8787:127.0.0.1:8787 pentest@kali-box
```

Scanning also needs no root. Velora's HTTP client is an ordinary user-space client, and the
`nmap` adapter deliberately uses `-sT` (TCP connect) rather than a SYN scan precisely so it
does not need raw sockets.

---

## External tool adapters

`velora/integrations/` contains three adapters. They are used only when the tool is present;
`velora doctor` reports each as a warning when it is missing and the framework runs
normally without any of them.

| Adapter | Class | Executable it looks for | What it runs |
| --- | --- | --- | --- |
| nmap | `NmapAdapter` | `nmap` | `-sT -Pn -T3 --top-ports <n> -oX - <host>` |
| OWASP ZAP | `ZapAdapter` | `zap-baseline.py` | `-t <url> -I -s` (passive baseline scan) |
| nuclei | `NucleiAdapter` | `nuclei` | `-u <url> -jsonl -severity <list> -silent -rate-limit 20 -timeout 10` |

All three are installed by default in a full Kali image. Check with:

```bash
which nmap nuclei zap-baseline.py
velora doctor
```

Note that `velora doctor` checks for `zap.sh`, while `ZapAdapter` resolves
`zap-baseline.py`. On a machine with `zap-baseline.py` but no `zap.sh`, doctor will warn
about ZAP even though the adapter would work.

Safety rules enforced by `integrations/base.ToolAdapter` for every adapter:

- Commands are executed as argument **arrays**, never a shell string. No input is
  concatenated into a shell command.
- The executable path is resolved and validated before execution.
- The target is checked against the scan's `ScopeManager` first; an out-of-scope target is
  refused and logged as `EXTERNAL_TOOL_TARGET_OUT_OF_SCOPE`.
- Every run has a timeout, and the child process group is killed on timeout or
  cancellation.
- stdout and stderr are captured with a ~2 MB cap.

The adapter defaults are conservative on purpose: no OS detection, no NSE scripts, no
aggressive timing for nmap; ZAP's *baseline* (passive) scan rather than an active scan;
nuclei limited to a validated severity set from `{info, low, medium, high, critical}` with
a rate limit, and no arbitrary flag passthrough.

**These adapters are not wired into any CLI command or into the scan orchestrator.** They
are importable library code (`from velora.integrations import NmapAdapter, ZapAdapter,
NucleiAdapter`) exercised by `tests/security/test_command_injection.py`. There is no
`velora nmap` or `--with-nuclei` flag. Nothing in a normal `velora scan` invokes them, so
installing these tools does not change what a scan does today.

---

## Lab setup

### Bundled lab app — no internet required

The repository ships a self-contained lab application built on stdlib `http.server`. It
deliberately exhibits real configuration weaknesses (missing security headers, insecure
cookie flags, a verbose `Server` header, permissive HTTP methods, an exposed secret in the
page body, privileged paths reachable without authentication) so checks have genuine
evidence to find. It performs no attacks and stores nothing.

```bash
python scripts/run_labapp.py 8099
```

It binds `127.0.0.1` only. Its behaviour is defined in `tests/fixtures/labapp.py`, which is
also the ground truth for the built-in `labshop` benchmark suite — the benchmark numbers
are measured against a known-correct answer key, not estimated.

### `examples/labs/`

| File | Purpose |
| --- | --- |
| `examples/labs/workflow-checkout.yaml` | A business-logic workflow for the bundled lab app: login, add-item, checkout, with `add-item` marked required. The lab app does not verify the cart was filled before checkout, so the step-skip probe has a real ordering flaw to find. |

`examples/labs` is also the default `--suite-dir` for `velora benchmark`. The `labshop`
suite itself is built into the code, so `velora benchmark list` works with the directory as
shipped; drop additional suite YAML files there to extend it.

### Other lab material

| File | Purpose |
| --- | --- |
| `examples/dvwa.yaml` | Target and scope template for DVWA |
| `examples/juice-shop.yaml` | Target and scope template for OWASP Juice Shop |
| `examples/plugins/` | Two example SDK 2.0 plugins plus a README |
| `examples/ci/` | `Jenkinsfile` and `gitlab-ci.yml` gate examples |
| `docs/lab-guide.md` | Docker one-liners for Juice Shop, DVWA and WebGoat |

Those third-party applications need Docker and an image pull. They are intentionally
vulnerable and must stay on an isolated network — never expose them.

Keep lab targets on loopback or RFC1918 and pass `--allow-private`. Without that flag the
scope engine blocks private and loopback addresses, which is the correct default for real
engagements.

---

## First authorized scan

Against the bundled lab app, which you own by definition. Terminal one:

```bash
python scripts/run_labapp.py 8099
```

Terminal two:

```bash
# 1. Verify the install
velora doctor

# 2. Register the target with an explicit lab-only authorization status
velora target add --name labshop --url http://127.0.0.1:8099/ \
  --owner "$USER" --authorization LAB_ONLY --allow-private \
  --note "Bundled lab app on loopback"

# 3. Prove the boundary before sending anything
velora scope validate --target labshop --url http://127.0.0.1:8099/admin
velora scope validate --target labshop --url http://external.example.net/
```

The second call prints
`OUT OF SCOPE: http://external.example.net/  (domain-not-in-scope:external.example.net)`.
The lab app's index page links to that external host on purpose — this is the scope engine
refusing to follow it.

```bash
# 4. Look before you scan
velora recon --target http://127.0.0.1:8099/ --allow-private --i-am-authorized
```

That reports `Server: LabShop/1.4.2 Python/3.11-lab`, the advertised methods
`GET, HEAD, POST, OPTIONS, TRACE, PUT, DELETE`, and that `robots.txt` exists while
`security.txt` does not.

```bash
# 5. Full assessment
velora scan --target labshop --profile lab --operator "$USER" \
  --allow-private --i-am-authorized --scan-id-file /tmp/scan.id
SCAN=$(cat /tmp/scan.id)
```

A real run produced 14 findings from 11 checks over 35 requests with 0 blocked requests,
led by two High findings — credentials submitted over plaintext HTTP, and a secret
disclosed in a response body.

```bash
# 6. Triage. Every finding starts as Potential; only a human confirms one.
velora findings --scan "$SCAN" --severity High
velora finding show <FINDING_ID>
velora analyze --finding <FINDING_ID>
velora finding validate <FINDING_ID> --operator "$USER" --note "reproduced by hand"

# 7. Context
velora attack-map --scan "$SCAN"
velora attack-map paths --scan "$SCAN" --evidenced-only
velora posture show --scan "$SCAN" --save

# 8. Measure the scanner against ground truth
velora benchmark run --suite labshop --target http://127.0.0.1:8099/ \
  --profile lab --allow-private --operator "$USER" --i-am-authorized

# 9. Report and read
velora report --scan "$SCAN" --format html --format json --format sarif
velora dashboard
```

Then open `http://127.0.0.1:8787/` as your non-root user. The dashboard is read-only; go
back to the terminal to act. See `docs/CLI.md` for the full command reference and
`docs/API.md` for the routes.

### Going beyond a passive scan, in the lab

```bash
# Authorization matrix across identities
velora authz init -o /tmp/authz.yaml
# edit the resource URLs to point at 127.0.0.1:8099, then export the referenced variables
export VELORA_IDENTITY_ALICE=alice-token
export VELORA_IDENTITY_BOB=bob-token
export VELORA_IDENTITY_ADMIN=admin-token
velora authz plan --config /tmp/authz.yaml            # sends nothing
velora authz run --config /tmp/authz.yaml --target labshop \
  --allow-private --operator "$USER" --strict --i-am-authorized

# Business-logic workflow
velora workflow validate --config examples/labs/workflow-checkout.yaml
velora workflow run --config examples/labs/workflow-checkout.yaml \
  --target labshop --allow-private --operator "$USER" --i-am-authorized
```

`authz plan` and `workflow validate` send no requests — run them first and read the matrix
and the state machine before anything goes on the wire.

---

## Operational notes for Kali

- Keep lab targets on loopback. `--allow-private` is the only thing that lets Velora touch
  RFC1918 or loopback, and it should never be set for a real engagement.
- Velora needs no internet for core operation: SQLite storage, an offline `heuristic` AI
  provider, inline SVG charts with no CDN, and a bundled lab app. An air-gapped Kali VM can
  run the full pipeline.
- The default `User-Agent` is `Velora/0.1 (+authorized-security-assessment)`. Leave it
  identifiable. Blue teams and log reviewers should be able to see who you are.
- `scope.request_delay` defaults to 0.2s per worker and `max_concurrency` to 5. Those are
  politeness defaults, not performance settings.
- Set `logging.json_file` to keep a machine-readable audit trail, for example
  `/var/log/velora/audit.jsonl` with a directory the running user can write. Scope
  violations are logged at the `SECURITY` level.
- Treat `<data dir>/velora.db` as sensitive. It holds targets, evidence excerpts and the
  audit log. Evidence is redacted before persistence, but the file still describes a
  client's attack surface.
