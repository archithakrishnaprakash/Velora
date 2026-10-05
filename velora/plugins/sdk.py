"""Velora Plugin SDK 2.0.

A plugin is a security check with a declared, validated contract. The contract exists
so that three questions can be answered *before* a plugin runs a single request:

1. **What is this plugin allowed to do?** ``scanner_type`` and ``allowed_methods``
   bound its behaviour; ``required_permissions`` states what authorization the operator
   must already hold.
2. **What will it produce?** ``expected_evidence`` names the evidence a detection must
   carry, so a finding without it is visibly incomplete rather than quietly trusted.
3. **Is its own metadata safe to read?** :func:`validate_metadata` rejects ids, names
   and descriptions that could smuggle control characters, terminal escapes or
   injection markers into logs, reports and AI prompts.

A plugin never gets its own HTTP client. It receives the scan's scope-gated client
through :class:`~velora.scanners.base.ScanContext`, so every request it makes is
checked against ``ScopePolicy`` exactly like a built-in check's. There is no supported
way for a plugin to reach the network otherwise, and a plugin that constructs its own
client is doing something the framework neither sanctions nor protects.

Backward compatibility: :class:`VeloraPlugin` subclasses
:class:`~velora.scanners.base.SecurityCheck` and projects its metadata onto the
attributes the 1.x registry, runner and profile selection already read. A 1.x check
written against ``SecurityCheck`` keeps working untouched.
"""
from __future__ import annotations

import abc
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Iterable

from ..models.enums import Severity
from ..scanners.base import CheckOutput, ScanContext, SecurityCheck
from ..scanners.base import registry as _check_registry
from ..utils.errors import ConfigError
from ..utils.logging import get_logger

log = get_logger("plugins.sdk")

SDK_VERSION = "2.0"

#: Verbs a plugin may never issue. Velora is an assessment framework, not a tool for
#: changing or destroying a target's state.
FORBIDDEN_METHODS: frozenset[str] = frozenset({"DELETE", "CONNECT", "TRACE", "PATCH", "PUT"})

#: Verbs any plugin may use without declaring anything extra.
DEFAULT_ALLOWED_METHODS: tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "POST")

_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?$")

#: Markers that have no business in plugin metadata. Metadata is rendered into logs,
#: reports and — for the AI layer — prompts, so it is treated as untrusted text even
#: though a human wrote it.
_METADATA_INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "disregard the above",
    "system:", "assistant:", "<|", "|>", "```", "\x1b[",
)

_MAX_ID = 64
_MAX_NAME = 120
_MAX_DESCRIPTION = 2000
_MAX_REFERENCES = 20
_MAX_CONFIG_KEYS = 40


class ScannerType(str, Enum):
    """What kind of interaction a plugin performs.

    The type is a *declaration of intent* that Velora enforces, not a hint. It decides
    which scan profiles may run the plugin and, together with ``allowed_methods``,
    bounds what it may send.
    """

    #: Reads only what the scan already collected, or issues plain reads. Safe profile.
    PASSIVE = "passive"
    #: Sends additional, non-mutating requests (extra paths, header probes). Safe profile.
    ACTIVE_SAFE = "active_safe"
    #: Sends crafted input (payloads in parameters, forms). Never in the safe profile.
    ACTIVE_INTRUSIVE = "active_intrusive"
    #: Produces guidance for a human tester; performs no requests of its own.
    MANUAL_ONLY = "manual_only"

    @property
    def runs_in_safe_profile(self) -> bool:
        return self in {ScannerType.PASSIVE, ScannerType.ACTIVE_SAFE,
                        ScannerType.MANUAL_ONLY}


_CONFIG_TYPES: dict[str, type | tuple[type, ...]] = {
    "str": str,
    "int": int,
    "float": (int, float),
    "bool": bool,
    "list[str]": list,
}


@dataclass(frozen=True)
class ConfigField:
    """One declared configuration option.

    Declaring options rather than reading a free-form dict means a typo becomes an
    error at load time instead of silently disabling a check at scan time.
    """

    type: str = "str"
    default: Any = None
    description: str = ""
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[Any, ...] | None = None
    required: bool = False

    def validate(self, key: str, value: Any) -> Any:
        expected = _CONFIG_TYPES[self.type]
        if self.type == "bool":
            if not isinstance(value, bool):
                raise ConfigError(f"config '{key}' must be a boolean")
        elif self.type == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"config '{key}' must be an integer")
        elif self.type == "list[str]":
            if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                raise ConfigError(f"config '{key}' must be a list of strings")
        elif not isinstance(value, expected) or isinstance(value, bool):
            raise ConfigError(f"config '{key}' must be of type {self.type}")

        if self.choices is not None and value not in self.choices:
            allowed = ", ".join(repr(c) for c in self.choices)
            raise ConfigError(f"config '{key}' must be one of: {allowed}")
        if self.minimum is not None and isinstance(value, (int, float)) and value < self.minimum:
            raise ConfigError(f"config '{key}' must be >= {self.minimum}")
        if self.maximum is not None and isinstance(value, (int, float)) and value > self.maximum:
            raise ConfigError(f"config '{key}' must be <= {self.maximum}")
        return value


@dataclass(frozen=True)
class PluginMetadata:
    """The declared contract of a plugin. Validated before the plugin is registered."""

    id: str
    name: str
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    category: str = "general"
    scanner_type: ScannerType = ScannerType.PASSIVE
    severity: Severity = Severity.INFO

    # ---- what it is allowed to do ----
    #: Scope is non-negotiable; the field exists so the contract states it explicitly.
    requires_scope: bool = True
    #: Authorization the operator must already hold for this plugin to be appropriate.
    required_permissions: tuple[str, ...] = ("written authorization for the target",)
    #: HTTP verbs the plugin may issue. Destructive verbs are refused outright.
    allowed_methods: tuple[str, ...] = DEFAULT_ALLOWED_METHODS
    #: True only for plugins that must not run outside a lab you control.
    lab_only: bool = False

    # ---- what it produces ----
    #: Names of the evidence a detection from this plugin is expected to carry.
    expected_evidence: tuple[str, ...] = ()
    #: Default remediation guidance; an individual detection may override it.
    remediation: str = ""
    references: tuple[str, ...] = ()
    cwe_id: str = "UNKNOWN"
    owasp_category: str = "UNKNOWN"

    # ---- configuration ----
    config_schema: dict[str, ConfigField] = field(default_factory=dict)

    sdk_version: str = SDK_VERSION

    @property
    def safe_mode(self) -> bool:
        """Whether this plugin runs in the default SAFE profile."""
        return self.scanner_type.runs_in_safe_profile and not self.lab_only

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "version": self.version,
            "author": self.author, "description": self.description,
            "category": self.category, "scanner_type": self.scanner_type.value,
            "severity": self.severity.value, "requires_scope": self.requires_scope,
            "required_permissions": list(self.required_permissions),
            "allowed_methods": list(self.allowed_methods), "lab_only": self.lab_only,
            "expected_evidence": list(self.expected_evidence),
            "references": list(self.references), "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category, "safe_mode": self.safe_mode,
            "config": {k: {"type": v.type, "default": v.default,
                           "description": v.description, "required": v.required}
                       for k, v in self.config_schema.items()},
            "sdk_version": self.sdk_version,
        }


# ---------------------------------------------------------------------------
# Metadata validation — plugin metadata is untrusted text
# ---------------------------------------------------------------------------
def _clean_text(label: str, value: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"plugin {label} must be a string")
    if len(value) > limit:
        raise ConfigError(f"plugin {label} exceeds {limit} characters")
    for ch in value:
        if ch in "\t\n":
            continue
        if unicodedata.category(ch) in {"Cc", "Cf", "Co", "Cs"}:
            raise ConfigError(
                f"plugin {label} contains a control or formatting character "
                f"(U+{ord(ch):04X}); metadata is rendered into logs and reports")
    lowered = value.lower()
    for marker in _METADATA_INJECTION_MARKERS:
        if marker in lowered:
            raise ConfigError(
                f"plugin {label} contains the disallowed sequence {marker!r}; plugin "
                "metadata must not carry prompt or terminal control sequences")
    return value


def validate_metadata(meta: PluginMetadata) -> PluginMetadata:
    """Validate a plugin's declared contract, raising :class:`ConfigError` on refusal.

    This runs before registration, so a plugin with unsafe or incoherent metadata never
    becomes loadable in the first place.
    """
    if not isinstance(meta, PluginMetadata):
        raise ConfigError("plugin metadata must be a PluginMetadata instance")

    if not isinstance(meta.id, str) or not _ID_RE.match(meta.id) or len(meta.id) > _MAX_ID:
        raise ConfigError(
            f"invalid plugin id {meta.id!r}: use lowercase words joined by '.', '_' "
            f"or '-' (max {_MAX_ID} characters), e.g. 'headers.cache_control'")
    if not _VERSION_RE.match(meta.version or ""):
        raise ConfigError(f"invalid plugin version {meta.version!r}: expected MAJOR.MINOR[.PATCH]")

    _clean_text("name", meta.name, _MAX_NAME)
    if not meta.name.strip():
        raise ConfigError("plugin name must not be empty")
    _clean_text("description", meta.description, _MAX_DESCRIPTION)
    _clean_text("author", meta.author, _MAX_NAME)
    _clean_text("category", meta.category, _MAX_NAME)
    _clean_text("remediation", meta.remediation, _MAX_DESCRIPTION)

    if not isinstance(meta.scanner_type, ScannerType):
        raise ConfigError("scanner_type must be a ScannerType value")
    if not isinstance(meta.severity, Severity):
        raise ConfigError("severity must be a Severity value")

    if not meta.requires_scope:
        raise ConfigError(
            "requires_scope cannot be disabled: every plugin request passes through "
            "ScopePolicy, and no plugin may opt out of scope enforcement")

    methods = tuple(m.upper() for m in meta.allowed_methods)
    if not methods:
        raise ConfigError("allowed_methods must name at least one HTTP verb")
    forbidden = sorted(set(methods) & FORBIDDEN_METHODS)
    if forbidden:
        raise ConfigError(
            f"plugin {meta.id} declares forbidden method(s) {', '.join(forbidden)}: "
            "Velora does not issue state-changing or tunnelling verbs")
    unknown = sorted(set(methods) - set(DEFAULT_ALLOWED_METHODS))
    if unknown:
        raise ConfigError(
            f"plugin {meta.id} declares unsupported method(s) {', '.join(unknown)}")

    if meta.scanner_type is ScannerType.ACTIVE_INTRUSIVE and not meta.lab_only:
        raise ConfigError(
            f"plugin {meta.id} is ACTIVE_INTRUSIVE and must also set lab_only=True: "
            "intrusive checks are only appropriate against a system you control")
    if meta.scanner_type is ScannerType.MANUAL_ONLY and meta.expected_evidence:
        raise ConfigError(
            f"plugin {meta.id} is MANUAL_ONLY, so it performs no requests and cannot "
            "declare expected evidence")
    if meta.scanner_type is not ScannerType.MANUAL_ONLY and not meta.expected_evidence:
        raise ConfigError(
            f"plugin {meta.id} must declare expected_evidence: a detection with no "
            "stated evidence cannot be validated by a human reviewer")

    if len(meta.references) > _MAX_REFERENCES:
        raise ConfigError(f"plugin {meta.id} declares more than {_MAX_REFERENCES} references")
    for ref in meta.references:
        _clean_text("reference", ref, 300)
        if not ref.startswith(("http://", "https://")):
            raise ConfigError(f"plugin reference must be an http(s) URL: {ref!r}")

    if len(meta.config_schema) > _MAX_CONFIG_KEYS:
        raise ConfigError(f"plugin {meta.id} declares more than {_MAX_CONFIG_KEYS} config keys")
    for key, spec in meta.config_schema.items():
        if not isinstance(key, str) or not _ID_RE.match(key):
            raise ConfigError(f"invalid config key {key!r} in plugin {meta.id}")
        if not isinstance(spec, ConfigField):
            raise ConfigError(f"config '{key}' must be declared as a ConfigField")
        if spec.type not in _CONFIG_TYPES:
            raise ConfigError(
                f"config '{key}' has unknown type {spec.type!r}; supported: "
                + ", ".join(sorted(_CONFIG_TYPES)))
        _clean_text(f"config '{key}' description", spec.description, 300)
        if spec.default is not None:
            spec.validate(key, spec.default)
        if spec.required and spec.default is not None:
            raise ConfigError(f"config '{key}' is required, so it must not carry a default")

    for permission in meta.required_permissions:
        _clean_text("required permission", permission, 200)
    for evidence in meta.expected_evidence:
        _clean_text("expected evidence", evidence, 200)
    return meta


def validate_config(meta: PluginMetadata, config: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve a plugin's configuration against its declared schema.

    Unknown keys are refused rather than ignored, so a misspelled option is visible
    immediately instead of silently leaving a check at its default.
    """
    provided = dict(config or {})
    unknown = sorted(set(provided) - set(meta.config_schema))
    if unknown:
        known = ", ".join(sorted(meta.config_schema)) or "(none declared)"
        raise ConfigError(
            f"plugin {meta.id}: unknown config key(s) {', '.join(unknown)}; declared: {known}")

    resolved: dict[str, Any] = {}
    for key, spec in meta.config_schema.items():
        if key in provided:
            resolved[key] = spec.validate(key, provided[key])
        elif spec.required:
            raise ConfigError(f"plugin {meta.id}: config '{key}' is required")
        else:
            resolved[key] = spec.default
    return resolved


# ---------------------------------------------------------------------------
# The plugin base class
# ---------------------------------------------------------------------------
class VeloraPlugin(SecurityCheck, abc.ABC):
    """Base class for SDK 2.0 plugins.

    Subclasses set a single :class:`PluginMetadata` class attribute; the SDK validates
    it and projects it onto the :class:`~velora.scanners.base.SecurityCheck` attributes
    the scan runner reads, so an SDK plugin and a 1.x check are interchangeable at the
    registry level.

    Lifecycle, in order:

    ``configure(config)`` → ``run(ctx)`` → ``cleanup()``

    ``cleanup()`` always runs if ``configure()`` succeeded, including when ``run()``
    raised — so a plugin that opened a temporary file or a counter can release it.
    """

    metadata: ClassVar[PluginMetadata]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        meta = getattr(cls, "metadata", None)
        if meta is None:
            # An intermediate abstract base may legitimately carry no metadata.
            if not getattr(cls, "__abstractmethods__", None) and cls.__name__ != "VeloraPlugin":
                raise ConfigError(f"{cls.__name__} must define a `metadata` PluginMetadata")
            return
        validate_metadata(meta)
        # Project onto the 1.x SecurityCheck surface.
        cls.id = meta.id
        cls.name = meta.name
        cls.description = meta.description
        cls.category = meta.category
        cls.severity = meta.severity
        cls.safe_mode = meta.safe_mode
        cls.references = list(meta.references)
        cls.remediation = meta.remediation
        cls.evidence_schema = {"expected": list(meta.expected_evidence)}

    def __init__(self) -> None:
        self.config: dict[str, Any] = validate_config(type(self).metadata, {})
        self._configured = False

    # ---- lifecycle -------------------------------------------------------
    def configure(self, config: dict[str, Any] | None = None) -> None:
        """Validate and apply configuration. Called once before :meth:`run`."""
        self.config = validate_config(type(self).metadata, config)
        self._configured = True
        self.on_configure()

    def on_configure(self) -> None:
        """Hook for subclasses that need to derive state from ``self.config``."""

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> list[CheckOutput]:
        """Return zero or more evidence-backed detections.

        A plugin observes and reports. It must not decide that a finding is Confirmed,
        and it must not attempt to exploit, persist, or modify the target.
        """

    async def cleanup(self) -> None:
        """Release anything :meth:`run` acquired. Safe to call more than once."""

    # ---- helpers available to subclasses ---------------------------------
    def check_method(self, method: str) -> str:
        """Return ``method`` if this plugin declared it, else raise ``ConfigError``."""
        upper = method.upper()
        if upper not in type(self).metadata.allowed_methods:
            raise ConfigError(
                f"plugin {type(self).metadata.id} attempted {upper}, which it did not "
                f"declare in allowed_methods")
        return upper

    def applies_to_profile(self, profile: str) -> bool:
        meta = type(self).metadata
        if meta.lab_only:
            return profile == "lab"
        if profile == "safe":
            return meta.safe_mode
        return True


def register_plugin(cls: type[VeloraPlugin]) -> type[VeloraPlugin]:
    """Validate and register a plugin with the global check registry.

    Registration is refused for a duplicate id, so a dropped-in plugin cannot silently
    shadow a built-in check.
    """
    meta = getattr(cls, "metadata", None)
    if meta is None:
        raise ConfigError(f"{cls.__name__} has no metadata and cannot be registered")
    validate_metadata(meta)
    if _check_registry.get(meta.id) is not None:
        raise ConfigError(
            f"plugin id {meta.id!r} is already registered; a plugin may not replace an "
            "existing check")
    _check_registry.register(cls)
    log.info("PLUGIN_REGISTERED id=%s version=%s type=%s safe_mode=%s",
             meta.id, meta.version, meta.scanner_type.value, meta.safe_mode)
    return cls


def describe(plugin_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Return the declared contract of every registered SDK plugin."""
    wanted = set(plugin_ids) if plugin_ids else None
    out: list[dict[str, Any]] = []
    for check_cls in _check_registry.all():
        meta = getattr(check_cls, "metadata", None)
        if meta is None or not isinstance(meta, PluginMetadata):
            continue
        if wanted and meta.id not in wanted:
            continue
        out.append(meta.to_dict())
    return out
