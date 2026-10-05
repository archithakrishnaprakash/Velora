"""`velora doctor` — environment and installation health checks."""
from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

from ..config.settings import Settings, default_config_path
from ..database.db import Database, pending_migrations
from ..utils import console


def run_doctor(settings: Settings) -> int:
    """Print PASS/WARN/FAIL checks. Returns process exit code (0 unless a FAIL)."""
    failures = 0
    warnings = 0

    console.header("Velora Doctor")

    # Python
    v = sys.version_info
    if v >= (3, 11):
        console.ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        console.fail(f"Python {v.major}.{v.minor} (3.11+ required)")
        failures += 1

    # OS
    console.ok(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")

    # Core dependencies
    for mod in ("httpx", "bs4", "pydantic", "jinja2", "yaml", "cryptography", "click",
                "starlette", "uvicorn"):
        try:
            __import__(mod)
            console.ok(f"dependency: {mod}")
        except ImportError:
            console.fail(f"dependency missing: {mod}")
            failures += 1

    # Config
    cfg = Path(settings.config_path or default_config_path())
    if cfg.exists():
        console.ok(f"config file: {cfg}")
    else:
        console.warn(f"config file not found ({cfg}); using defaults. Run 'velora init'.")
        warnings += 1

    # Data dir + permissions
    data_dir = settings.data_dir
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        console.ok(f"data dir writable: {data_dir}")
    except OSError as exc:
        console.fail(f"data dir not writable: {data_dir} ({exc})")
        failures += 1

    # Database + migrations
    try:
        db = Database(settings)
        db.init()
        pending = pending_migrations(db.conn)
        if pending:
            console.warn(f"pending migrations: {[p.stem for p in pending]}")
            warnings += 1
        else:
            console.ok("database schema up to date")
        db.close()
    except Exception as exc:  # noqa: BLE001
        console.fail(f"database error: {exc}")
        failures += 1

    # Disk space
    try:
        usage = shutil.disk_usage(str(data_dir))
        free_gb = usage.free / (1024 ** 3)
        if free_gb < 0.5:
            console.warn(f"low disk space: {free_gb:.2f} GB free")
            warnings += 1
        else:
            console.ok(f"disk space: {free_gb:.1f} GB free")
    except OSError:
        console.warn("could not determine disk space")
        warnings += 1

    # External tools (optional)
    # Names must match what the adapters actually execute; doctor used to look for
    # zap.sh while ZapAdapter runs zap-baseline.py, reporting ZAP missing on a machine
    # where it would have worked.
    for tool in ("nmap", "zap-baseline.py", "nuclei", "docker"):
        path = shutil.which(tool)
        if path:
            console.ok(f"external tool: {tool} ({path})")
        else:
            console.warn(f"external tool not found: {tool} (optional adapter disabled)")
            warnings += 1

    # AI provider
    if settings.ai.provider in {"openai", "openai_compatible"}:
        if settings.ai.api_key:
            console.ok(f"AI provider: {settings.ai.provider} (key present)")
        else:
            console.warn(f"AI provider '{settings.ai.provider}' selected but "
                         f"{settings.ai.api_key_env} unset; will use heuristic provider")
            warnings += 1
    else:
        console.ok(f"AI provider: {settings.ai.provider} (offline, no key required)")

    console.header("Summary")
    if failures:
        console.fail(f"{failures} failure(s), {warnings} warning(s)")
        return 1
    if warnings:
        console.warn(f"0 failures, {warnings} warning(s)")
        return 0
    console.ok("all checks passed")
    return 0
