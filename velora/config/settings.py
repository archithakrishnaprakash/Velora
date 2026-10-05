"""Typed settings model.

Precedence (highest first): environment variables (VELORA_*) > YAML config file >
built-in secure defaults. Secrets (AI API keys) are read only from the environment and
never persisted to the YAML file.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

ENV_PREFIX = "VELORA_"


def default_config_dir() -> Path:
    base = os.environ.get("VELORA_CONFIG_DIR")
    if base:
        return Path(base).expanduser()
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "velora"


def default_config_path() -> Path:
    return default_config_dir() / "config.yaml"


def default_data_dir() -> Path:
    base = os.environ.get("VELORA_DATA_DIR")
    if base:
        return Path(base).expanduser()
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "velora"


class DatabaseConfig(BaseModel):
    # SQLAlchemy-style URL. sqlite is the built-in default; a postgresql+psycopg URL
    # is accepted by the architecture for production deployments.
    url: str = Field(default_factory=lambda: f"sqlite:///{default_data_dir() / 'velora.db'}")

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")

    @property
    def sqlite_path(self) -> Path:
        assert self.is_sqlite
        raw = self.url.split("sqlite:///", 1)[-1]
        return Path(raw).expanduser()


class APIConfig(BaseModel):
    host: str = "127.0.0.1"  # secure default: loopback only
    port: int = 8787
    cors_allow_origins: list[str] = Field(default_factory=list)


class DashboardConfig(BaseModel):
    enabled: bool = True
    title: str = "Velora"
    theme: str = "dark"


class ScopeDefaults(BaseModel):
    """Defaults applied to a scope policy when a target does not override them."""

    allowed_schemes: list[str] = Field(default_factory=lambda: ["http", "https"])
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443, 3000])
    max_requests: int = 500
    max_concurrency: int = 5
    request_delay: float = 0.2  # seconds between requests per worker
    timeout: float = 15.0
    # redirect policy: "same-scope" (follow only in-scope), "never", "same-origin"
    redirect_policy: str = "same-scope"
    allow_private_targets: bool = False  # RFC1918/loopback blocked unless explicitly allowed


class ScannerConfig(BaseModel):
    default_profile: str = "safe"
    user_agent: str = "Velora/0.1 (+authorized-security-assessment)"
    verify_tls: bool = True
    follow_redirects: bool = False
    max_crawl_depth: int = 3
    max_crawl_pages: int = 200
    respect_robots: bool = True
    #: Directories of external plugin modules, loaded at startup so a plugin dropped in
    #: here is available to every command — including `velora scan`. Loading a plugin
    #: executes its Python in this process, so only list directories you control.
    plugin_dirs: list[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    level: str = "INFO"
    json_file: str | None = None

    @field_validator("level")
    @classmethod
    def _valid_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "SECURITY"}
        up = v.upper()
        if up not in allowed:
            raise ValueError(f"level must be one of {sorted(allowed)}")
        return up


class AIConfig(BaseModel):
    # provider: "null" (deterministic, no external calls), "heuristic", or "openai_compatible"
    provider: str = "heuristic"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    # API key is NEVER stored here; it is read from VELORA_AI_API_KEY at call time.
    api_key_env: str = "VELORA_AI_API_KEY"
    max_tokens: int = 800
    temperature: float = 0.1
    timeout: float = 30.0
    # Hard safety switch: AI may never set a finding to Confirmed regardless of provider.
    allow_ai_confirmation: bool = False

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)


class ReportConfig(BaseModel):
    output_dir: str = Field(default_factory=lambda: str(default_data_dir() / "reports"))
    company_name: str = "Independent Security Assessment"
    default_formats: list[str] = Field(default_factory=lambda: ["html", "json"])


class Settings(BaseModel):
    config_path: str | None = None
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    scope: ScopeDefaults = Field(default_factory=ScopeDefaults)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)

    def to_yaml_dict(self) -> dict[str, Any]:
        """Serialize to a YAML-safe dict, omitting secrets and runtime-only fields."""
        data = self.model_dump(exclude={"config_path"})
        return data

    @property
    def data_dir(self) -> Path:
        return default_data_dir()


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply VELORA_SECTION__KEY=value overrides (double underscore = nesting)."""
    for env_key, value in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        path = env_key[len(ENV_PREFIX) :].lower()
        if path in {"config_dir", "data_dir", "ai_api_key"}:
            continue  # handled elsewhere / secret
        parts = path.split("__")
        cursor = data
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                break
        else:
            cursor[parts[-1]] = _coerce(value)
    return data


def _coerce(value: str) -> Any:
    low = value.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load settings from defaults, then YAML file, then environment overrides."""
    path = Path(config_path) if config_path else default_config_path()
    data: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file {path} must contain a mapping at the top level")
        data = loaded
    data = _apply_env_overrides(data)
    settings = Settings(**data)
    settings.config_path = str(path)
    return settings
