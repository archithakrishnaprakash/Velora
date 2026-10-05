"""Runs the registered security checks against a ScanContext."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..utils.errors import ConfigError, RateLimitExceeded, ScopeViolation
from ..utils.logging import get_logger
from .base import CheckOutput, ScanContext, SecurityCheck, registry

log = get_logger("scanners")


@dataclass
class ScanRunOutcome:
    outputs: list[CheckOutput] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_failed: dict[str, str] = field(default_factory=dict)


class ScanRunner:
    """Executes checks selected by profile, isolating per-check failures.

    Plugin SDK 2.0 adds an optional ``configure()`` / ``cleanup()`` lifecycle. Both are
    optional: a 1.x ``SecurityCheck`` that defines neither runs exactly as before.
    ``cleanup()`` runs whether or not ``run()`` succeeded, so a check that acquired a
    resource always gets to release it.
    """

    def __init__(self, profile: str = "safe", check_ids: list[str] | None = None,
                 plugin_config: dict[str, dict[str, Any]] | None = None) -> None:
        self.profile = profile
        self.check_ids = check_ids
        #: Per-check configuration, keyed by check id. Validated by the plugin SDK.
        self.plugin_config = plugin_config or {}

    def _selected(self) -> list[type[SecurityCheck]]:
        if self.check_ids:
            classes = [registry.get(cid) for cid in self.check_ids]
            return [c for c in classes if c is not None]
        return registry.for_profile(self.profile)

    async def run(self, ctx: ScanContext) -> ScanRunOutcome:
        outcome = ScanRunOutcome()
        for check_cls in self._selected():
            check = check_cls()
            configure = getattr(check, "configure", None)
            if callable(configure):
                try:
                    configure(self.plugin_config.get(check.id))
                except ConfigError as exc:
                    # A misconfigured plugin is skipped loudly, never run on defaults.
                    log.error("check %s rejected its configuration: %s", check.id, exc)
                    outcome.checks_failed[check.id] = f"config:{exc}"
                    continue
            try:
                results = await check.run(ctx)
                outcome.outputs.extend(results)
                outcome.checks_run.append(check.id)
                log.info("SCAN_CHECK_COMPLETED check=%s findings=%d", check.id, len(results))
            except RateLimitExceeded:
                log.warning("request budget exhausted during check %s", check.id)
                outcome.checks_failed[check.id] = "rate-limit"
                await self._cleanup(check)
                break
            except ScopeViolation as exc:
                # A check tried something out of scope; record and continue.
                outcome.checks_failed[check.id] = f"scope:{exc.reason}"
            except Exception as exc:  # noqa: BLE001 - isolate check failures
                log.error("check %s failed: %s", check.id, exc)
                outcome.checks_failed[check.id] = str(exc)
            await self._cleanup(check)
        return outcome

    @staticmethod
    async def _cleanup(check: SecurityCheck) -> None:
        cleanup = getattr(check, "cleanup", None)
        if not callable(cleanup):
            return
        try:
            await cleanup()
        except Exception as exc:  # noqa: BLE001 - cleanup must never fail a scan
            log.error("cleanup for check %s failed: %s", check.id, exc)
