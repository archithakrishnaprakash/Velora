# Installing Velora

Velora is a Python package with a CLI (`velora`) and an optional read-only web dashboard.
It runs on Linux, and is developed against Kali. See `docs/KALI_SETUP.md` for Kali
specifics.

> **Authorized use only.** Installing Velora does not authorize you to test anything. Use
> it against systems you own or have explicit written authorization to assess.

## Requirements

| Requirement | Value |
| --- | --- |
| Python | 3.11 or newer (`requires-python = ">=3.11"`) |
| venv | `python3 -m venv` must work (`python3-venv` on Debian/Kali) |
| Disk | The doctor warns below 0.5 GB free in the data directory |
| Network | None for core operation. The database is SQLite; the AI default is offline. |

External tools (`nmap`, OWASP ZAP, `nuclei`, `docker`) are optional. `velora doctor`
reports them as warnings when absent and the framework runs without them.

## The dependency situation — read this first

This repository was built and verified in an environment with **no outbound package
access** (PyPI and apt both return HTTP 403). The code was therefore written against the
libraries that were already present and importable, and every feature was actually
executed against them. `docs/V2_UPGRADE_AUDIT.md` section 13 records that decision.

What the code actually imports and uses at runtime:

| Library | Used for |
| --- | --- |
| `click` | The entire CLI, including all command groups |
| `httpx` | All HTTP, via the scope-gated `SafeHTTPClient` |
| `beautifulsoup4` (`bs4`) | HTML parsing in the crawler and checks |
| `pydantic` | Every domain model and the settings model |
| `jinja2` | Dashboard templates and HTML reports |
| `pyyaml` | `config.yaml`, gate policies, authz plans, workflow definitions, fingerprint signatures |
| `starlette` | The ASGI dashboard and JSON API |
| `uvicorn` | Serving that app (`velora dashboard`) |
| `cryptography` | Checked by `velora doctor` |
| stdlib `sqlite3` | The database, with plain SQL migrations |
| stdlib `unittest` | The test suite |

What Velora does **not** require, despite appearing in design documents:

| Library | Status |
| --- | --- |
| `typer` | Not used. The CLI is `click`. |
| `rich` | Not used. Console output is `velora/utils/console.py`. |
| `fastapi` | Not used. The API is `starlette` directly. |
| `sqlalchemy`, `alembic` | Not used. Storage is stdlib `sqlite3` with SQL migration files. |
| `pytest` | Not required. Tests are `unittest.TestCase` subclasses, which pytest discovers and runs natively if you have it. |
| `weasyprint` | Optional, for PDF reports only. Without it `--format pdf` writes HTML and logs a warning. |

`pyproject.toml` keeps a `reference-stack` extra —
`typer`, `rich`, `fastapi`, `sqlalchemy`, `alembic` — so those libraries can be installed
on a machine with working pip. Installing the extra changes nothing about how Velora runs;
nothing in `velora/` imports them. Treat the extra as a record of the design-document stack,
not as a requirement.

The `dependencies` list in `pyproject.toml` also names `pydantic-settings` and
`python-multipart`. Both were present in the build environment, but no module under
`velora/` imports either one: settings are a plain `pydantic.BaseModel` with the YAML and
environment layering implemented in `velora/config/settings.py`, and the dashboard has no
form handling.

The practical consequence: on a machine with working pip, `pip install .` installs the
declared dependency set and everything works. In an environment without package access,
Velora still runs as long as `click`, `httpx`, `bs4`, `pydantic`, `jinja2`, `yaml`,
`cryptography`, `starlette` and `uvicorn` are importable — which is exactly the set
`velora doctor` checks.

## Install from source

```bash
git clone https://github.com/architha/velora
cd velora
./install.sh
```

`install.sh` is a Bash script for Debian-based systems. It:

1. Verifies Python ≥ 3.11 and that the `venv` module is importable.
2. Creates a virtualenv at `$VELORA_VENV`, default `~/.local/share/velora/venv`.
3. Upgrades `pip` and `wheel`, then runs `pip install <repo dir>`.
4. Runs `velora init` to write the config file and initialize the database.
5. Symlinks the CLI to `$VELORA_BIN`, default `~/.local/bin/velora`, and warns if that
   directory is not on `PATH`.
6. Optionally writes a desktop entry when `VELORA_DESKTOP=1` and
   `~/.local/share/applications` exists.
7. Runs `velora doctor`.

Its environment variables:

| Variable | Default |
| --- | --- |
| `VELORA_VENV` | `~/.local/share/velora/venv` |
| `VELORA_BIN` | `~/.local/bin/velora` |
| `PYTHON` | `python3` |
| `VELORA_DESKTOP` | unset (set to `1` for a desktop entry) |

The script needs pip to reach an index. Without one, use the manual venv route below.

## Manual virtualenv

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip wheel
.venv/bin/pip install .
.venv/bin/velora --help
```

Or use the Makefile:

```bash
make venv       # create .venv, upgrade pip and wheel
make install    # pip install .
make dev        # pip install -e ".[dev,pdf,reference-stack]"
make test       # pytest if present, otherwise unittest discovery
make lint       # ruff check velora tests
make format     # black, then ruff --fix
make typecheck  # mypy velora
make run        # velora dashboard
```

`make test` is written to work either way:

```bash
PYTHONPATH=.:tests/fixtures python -m unittest discover -s tests -t . -p "test_*.py"
```

That is the exact fallback it runs when `pytest` is not installed. It runs 409 tests and
passes without `pytest`, `respx` or any other dev dependency installed.

Without installing at all, you can run from the checkout:

```bash
python -m velora.cli.main --help
```

## First run

```bash
velora init
velora doctor
```

`velora init` writes `config.yaml` if it is missing and initializes the database, printing
both paths. Running it again warns that the config exists and leaves it alone.

`velora doctor` prints PASS/WARN/FAIL lines and exits `1` only if something FAILed. A
healthy first run on a machine with no external security tools looks like this:

```text
Velora Doctor
─────────────
PASS Python 3.11.15
PASS OS: Linux 6.18.44-fc-v37 (x86_64)
PASS dependency: httpx
PASS dependency: bs4
PASS dependency: pydantic
PASS dependency: jinja2
PASS dependency: yaml
PASS dependency: cryptography
PASS dependency: click
PASS dependency: starlette
PASS dependency: uvicorn
PASS config file: /home/you/.config/velora/config.yaml
PASS data dir writable: /home/you/.local/share/velora
PASS database schema up to date
PASS disk space: 29.4 GB free
WARN external tool not found: nmap (optional adapter disabled)
WARN external tool not found: zap.sh (optional adapter disabled)
WARN external tool not found: nuclei (optional adapter disabled)
PASS external tool: docker (/usr/bin/docker)
PASS AI provider: heuristic (offline, no key required)

Summary
───────
WARN 0 failures, 4 warning(s)
```

Warnings are informational. The four external-tool checks warn whenever a tool is absent,
which is the normal state on a fresh machine.

## Configuration

| Item | Default | Override |
| --- | --- | --- |
| Config file | `~/.config/velora/config.yaml` | `VELORA_CONFIG_DIR`, or `--config PATH` per invocation |
| Data directory | `~/.local/share/velora` | `VELORA_DATA_DIR` |
| Database | `sqlite:///<data dir>/velora.db` | `database.url` in the config file |
| Reports | `<data dir>/reports` | `reports.output_dir` |

The config directory honours `XDG_CONFIG_HOME` and the data directory honours
`XDG_DATA_HOME` when `VELORA_CONFIG_DIR` / `VELORA_DATA_DIR` are not set.

Precedence, highest first: environment variables, then the YAML file, then built-in secure
defaults.

Environment overrides use `VELORA_<SECTION>__<KEY>`, with a double underscore for nesting:

```bash
export VELORA_API__HOST=127.0.0.1
export VELORA_API__PORT=8787
export VELORA_LOGGING__LEVEL=INFO
export VELORA_AI__PROVIDER=heuristic
```

`VELORA_CONFIG_DIR`, `VELORA_DATA_DIR` and `VELORA_AI_API_KEY` are handled separately and
are not treated as section overrides.

Configuration sections, with their defaults:

| Section | Keys |
| --- | --- |
| `database` | `url` |
| `api` | `host` `127.0.0.1`, `port` `8787`, `cors_allow_origins` `[]` |
| `dashboard` | `enabled` `true`, `title` `Velora`, `theme` `dark` |
| `scope` | `allowed_schemes` `[http, https]`, `allowed_ports` `[80, 443, 8080, 8443, 3000]`, `max_requests` `500`, `max_concurrency` `5`, `request_delay` `0.2`, `timeout` `15.0`, `redirect_policy` `same-scope`, `allow_private_targets` `false` |
| `scanner` | `default_profile` `safe`, `user_agent`, `verify_tls` `true`, `follow_redirects` `false`, `max_crawl_depth` `3`, `max_crawl_pages` `200`, `respect_robots` `true` |
| `logging` | `level` `INFO` (one of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `SECURITY`), `json_file` |
| `ai` | `provider` `heuristic`, `model`, `base_url`, `api_key_env` `VELORA_AI_API_KEY`, `max_tokens`, `temperature`, `timeout`, `allow_ai_confirmation` `false` |
| `reports` | `output_dir`, `company_name`, `default_formats` `[html, json]` |

Print the effective configuration at any time:

```bash
velora config
```

### Secrets

No secret is ever written to `config.yaml`. The AI API key is read from the environment
variable named by `ai.api_key_env` (default `VELORA_AI_API_KEY`) at call time only.
Authorization-test credentials work the same way: the plan file stores a `secret_ref`
naming an environment variable, never a value.

`.env.example` in the repository root documents the common variables. Copy it to `.env` and
never commit real values.

`ai.allow_ai_confirmation` defaults to `false` and is described in the code as a hard
safety switch: AI may never set a finding to `Confirmed` regardless of provider.

## Docker

```bash
make docker-build     # docker build -f docker/Dockerfile -t velora:0.1.0 .
make docker-up        # docker compose -f docker/docker-compose.yml up --build
```

`docker/Dockerfile` builds from `python:3.12-slim`, installs the package with
`pip install --no-cache-dir .`, creates a system user `velora`, chowns `/data`, `/config`
and `/app` to it, and switches to `USER velora` — the web app does not run as root. It sets
`VELORA_DATA_DIR=/data` and `VELORA_CONFIG_DIR=/config`, exposes `8787`, and its default
command is:

```text
velora dashboard --host 0.0.0.0 --port 8787
```

`0.0.0.0` there means "all interfaces inside the container". The compose file is what keeps
it off the network:

```yaml
ports:
  - "127.0.0.1:8787:8787"
```

That publishes the container port only on the host's loopback address. If you change that
mapping, you are exposing an unauthenticated dashboard.

Compose also sets `VELORA_AI__PROVIDER=heuristic` (offline) and mounts named volumes
`velora_data` at `/data` and `velora_config` at `/config`, with `restart: unless-stopped`.
The `VELORA_AI_API_KEY` line is present but commented out; uncomment it only if you use an
external LLM provider.

Run CLI commands inside the container the same way you would outside:

```bash
docker compose -f docker/docker-compose.yml exec velora velora doctor
```

## systemd

`systemd/velora.service` runs the dashboard as a dedicated non-root user. The header of the
unit file gives the install steps:

```bash
sudo useradd --system --home /opt/velora --shell /usr/sbin/nologin velora
sudo cp systemd/velora.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now velora
```

The unit expects a virtualenv at `/opt/velora/venv` and runs:

```text
/opt/velora/venv/bin/velora dashboard --host 127.0.0.1 --port 8787
```

with `VELORA_DATA_DIR=/opt/velora/data` and `VELORA_CONFIG_DIR=/opt/velora/config`.

Its hardening directives:

| Directive | Value |
| --- | --- |
| `User` / `Group` | `velora` / `velora` |
| `NoNewPrivileges` | `true` |
| `PrivateTmp` | `true` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `true` |
| `ReadWritePaths` | `/opt/velora/data` `/opt/velora/config` |
| `CapabilityBoundingSet` | empty |
| `AmbientCapabilities` | empty |
| `Restart` | `on-failure` |

`ProtectSystem=strict` makes the whole filesystem read-only except the two `ReadWritePaths`,
so set up the venv and directories before enabling the unit. An empty
`CapabilityBoundingSet` means the service can hold no capabilities at all — which is fine,
because the dashboard only reads a SQLite file and serves HTTP on a high port.

```bash
sudo systemctl status velora
sudo journalctl -u velora -f
```

## Uninstall

```bash
rm -rf ~/.local/share/velora/venv     # the virtualenv install.sh created
rm -f  ~/.local/bin/velora            # the PATH symlink
rm -rf ~/.config/velora               # config.yaml
rm -rf ~/.local/share/velora          # database and reports
```

Remove the data directory last, and only when you no longer need the assessment records in
it. Reports are inside it by default.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `velora: command not found` after `install.sh` | `~/.local/bin` is not on `PATH`. Add it to your shell profile. |
| `doctor` reports a missing dependency | Something in the nine-module set is not importable in the active interpreter. Check you are using the venv's `velora`, not a system one. |
| `data dir not writable` | `VELORA_DATA_DIR` points somewhere the user cannot write. |
| `pending migrations` warning | The schema is behind. `velora init` or any command that opens the database applies migrations. |
| `--format pdf` produced an HTML file | WeasyPrint is not installed. Install the `pdf` extra where pip works, or accept HTML. |
| `config already exists` from `init` | Expected. `init` never overwrites a config file. |
