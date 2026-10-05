"""Discovery and enable/disable management for checks/plugins.

Loading an external plugin means executing its Python in this process, so the loader
does what it can to make that a deliberate act rather than an accident: it only ever
looks at a directory the operator named, it refuses to follow a symlink out of that
directory, it caps file size, and it validates every SDK plugin's declared metadata
before the plugin becomes registered.

None of that makes an untrusted plugin safe — nothing can, short of a separate process
with its own privileges. Treat a plugin exactly as you would any other code you are
about to run: read it first.
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..database.repository import Repository
from ..scanners import registry
from ..utils.errors import ConfigError
from ..utils.logging import get_logger

log = get_logger("plugins")

#: A plugin module larger than this is refused; real checks are small.
MAX_PLUGIN_BYTES = 512 * 1024


@dataclass
class PluginInfo:
    id: str
    name: str
    category: str
    safe_mode: bool
    enabled: bool
    builtin: bool = True
    version: str = "1.0.0"
    scanner_type: str = ""
    sdk_version: str = "1.x"


@dataclass
class PluginLoadResult:
    """What a load attempt produced, including the failures."""

    loaded: list[str]
    rejected: dict[str, str]


class PluginManager:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def _disabled_ids(self) -> set[str]:
        rows = self.repo.conn.execute(
            "SELECT id FROM plugins WHERE enabled = 0;"
        ).fetchall()
        return {r[0] for r in rows}

    def list(self) -> list[PluginInfo]:
        disabled = self._disabled_ids()
        out: list[PluginInfo] = []
        for c in registry.all():
            meta = getattr(c, "metadata", None)
            out.append(PluginInfo(
                id=c.id, name=c.name, category=c.category, safe_mode=c.safe_mode,
                enabled=c.id not in disabled,
                builtin=meta is None,
                version=getattr(meta, "version", "1.0.0"),
                scanner_type=getattr(getattr(meta, "scanner_type", None), "value", ""),
                sdk_version=getattr(meta, "sdk_version", "1.x"),
            ))
        return out

    def describe(self, plugin_id: str) -> dict[str, Any] | None:
        """Full metadata for one plugin, SDK contract included where present."""
        check = registry.get(plugin_id)
        if check is None:
            return None
        meta = getattr(check, "metadata", None)
        if meta is not None and hasattr(meta, "to_dict"):
            payload = meta.to_dict()
            payload["enabled"] = plugin_id not in self._disabled_ids()
            return payload
        return {
            "id": check.id, "name": check.name, "description": check.description,
            "category": check.category, "severity": check.severity.value,
            "safe_mode": check.safe_mode, "references": list(check.references),
            "evidence_schema": check.evidence_schema, "sdk_version": "1.x",
            "enabled": plugin_id not in self._disabled_ids(),
        }

    def set_enabled(self, plugin_id: str, enabled: bool) -> bool:
        if registry.get(plugin_id) is None:
            return False
        now = datetime.now(timezone.utc).isoformat()
        cur = self.repo.conn.execute("SELECT id FROM plugins WHERE id = ?;", (plugin_id,))
        check = registry.get(plugin_id)
        if cur.fetchone():
            self.repo.conn.execute("UPDATE plugins SET enabled = ? WHERE id = ?;",
                                   (1 if enabled else 0, plugin_id))
        else:
            version = getattr(getattr(check, "metadata", None), "version", "1.0.0")
            self.repo.conn.execute(
                "INSERT INTO plugins(id, name, version, description, enabled, created_at) "
                "VALUES (?,?,?,?,?,?);",
                (plugin_id, check.name, version, check.description,
                 1 if enabled else 0, now),
            )
        return True

    # ------------------------------------------------------------------
    # External plugin loading
    # ------------------------------------------------------------------
    @staticmethod
    def load_external(plugin_dir: str | Path) -> list[str]:
        """Import external plugin modules. Returns the newly registered check ids.

        Kept returning a plain list for backward compatibility with 1.x callers; use
        :meth:`load_external_detailed` when the rejection reasons matter.
        """
        return PluginManager.load_external_detailed(plugin_dir).loaded

    @staticmethod
    def load_external_detailed(plugin_dir: str | Path) -> PluginLoadResult:
        directory = Path(plugin_dir).expanduser()
        rejected: dict[str, str] = {}
        if not directory.is_dir():
            return PluginLoadResult([], {str(directory): "not a directory"})
        root = directory.resolve()

        before = {c.id for c in registry.all()}
        for path in sorted(directory.glob("*.py")):
            name = path.name
            if name.startswith("_"):
                continue
            try:
                resolved = path.resolve()
            except OSError as exc:
                rejected[name] = f"unreadable: {exc}"
                continue
            # A symlink pointing outside the named directory would load code the
            # operator did not put there.
            if root not in resolved.parents:
                rejected[name] = "resolves outside the plugin directory"
                log.error("PLUGIN_LOAD_REJECTED file=%s reason=escapes-directory", name)
                continue
            if not resolved.is_file():
                rejected[name] = "not a regular file"
                continue
            size = resolved.stat().st_size
            if size > MAX_PLUGIN_BYTES:
                rejected[name] = f"exceeds {MAX_PLUGIN_BYTES} bytes ({size})"
                log.error("PLUGIN_LOAD_REJECTED file=%s reason=too-large", name)
                continue

            module_name = f"velora_plugin_{resolved.stem}"
            spec = importlib.util.spec_from_file_location(module_name, resolved)
            if not (spec and spec.loader):
                rejected[name] = "could not be imported"
                continue
            module = importlib.util.module_from_spec(spec)
            # Register before exec so a plugin split across modules can import itself.
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except ConfigError as exc:
                # The SDK refused the plugin's declared contract.
                sys.modules.pop(module_name, None)
                rejected[name] = f"rejected contract: {exc}"
                log.error("PLUGIN_LOAD_REJECTED file=%s reason=%s", name, exc)
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not stop the rest
                sys.modules.pop(module_name, None)
                rejected[name] = str(exc)
                log.error("failed to load plugin %s: %s", name, exc)

        loaded = sorted({c.id for c in registry.all()} - before)
        for plugin_id in loaded:
            log.info("PLUGIN_LOADED id=%s dir=%s", plugin_id, root)
        return PluginLoadResult(loaded, rejected)
