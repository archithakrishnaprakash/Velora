"""Plugin system.

Built-in security checks register with the scanner ``registry`` at import time. The
``PluginManager`` exposes them as plugins and persists enable/disable state in the
``plugins`` table.

External plugins come in two forms:

* **SDK 2.0** — subclass :class:`~velora.plugins.sdk.VeloraPlugin`, declare a
  :class:`~velora.plugins.sdk.PluginMetadata` contract, and register with
  :func:`~velora.plugins.sdk.register_plugin`. The contract is validated before the
  plugin becomes loadable.
* **1.x** — subclass ``velora.scanners.SecurityCheck`` and call
  ``velora.scanners.register``. Still supported, unchanged.

Either way, a plugin's requests go through the scan's scope-gated HTTP client, so
``ScopePolicy`` applies to every one of them.
"""
from .manager import PluginInfo, PluginManager
from .sdk import (
    DEFAULT_ALLOWED_METHODS,
    FORBIDDEN_METHODS,
    SDK_VERSION,
    ConfigField,
    PluginMetadata,
    ScannerType,
    VeloraPlugin,
    describe,
    register_plugin,
    validate_config,
    validate_metadata,
)

__all__ = [
    "PluginManager", "PluginInfo",
    "VeloraPlugin", "PluginMetadata", "ScannerType", "ConfigField",
    "register_plugin", "validate_metadata", "validate_config", "describe",
    "SDK_VERSION", "FORBIDDEN_METHODS", "DEFAULT_ALLOWED_METHODS",
]
