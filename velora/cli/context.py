"""Shared CLI context: settings + database handle."""
from __future__ import annotations

from dataclasses import dataclass

from ..config.settings import Settings, load_settings
from ..database.db import Database
from ..database.repository import Repository
from ..utils.logging import configure_logging, get_logger

log = get_logger("cli.context")


@dataclass
class AppContext:
    settings: Settings
    db: Database

    @property
    def repo(self) -> Repository:
        return Repository(self.db.conn)


def build_context(config_path: str | None = None) -> AppContext:
    settings = load_settings(config_path)
    configure_logging(settings.logging.level, json_file=settings.logging.json_file)
    db = Database(settings)
    db.init()
    _load_configured_plugins(settings)
    return AppContext(settings=settings, db=db)


def _load_configured_plugins(settings: Settings) -> None:
    """Load external plugin directories named in the configuration.

    The check registry lives in memory, so a plugin loaded by one command is gone by
    the next. Loading the configured directories here is what makes an external plugin
    actually usable in a scan rather than only visible to the command that loaded it.
    """
    if not settings.scanner.plugin_dirs:
        return
    from ..plugins import PluginManager
    for directory in settings.scanner.plugin_dirs:
        result = PluginManager.load_external_detailed(directory)
        for name, reason in result.rejected.items():
            log.warning("plugin %s in %s was not loaded: %s", name, directory, reason)
