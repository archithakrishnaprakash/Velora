"""Velora — AI-Assisted Web Vulnerability Assessment & Security Testing Framework.

Authorized use only. This framework is intended for owned systems, intentionally
vulnerable applications, isolated labs, and explicitly authorized penetration tests.

Core principle: SECURITY EVIDENCE FIRST, AI SECOND. The AI layer never declares a
vulnerability on its own; it only explains evidence produced by deterministic scanners,
and human validation is required before a finding is Confirmed.
"""
from __future__ import annotations

__all__ = ["__version__", "APP_NAME", "APP_SLUG"]

__version__ = "2.0.0"
APP_NAME = "Velora"
APP_SLUG = "velora"
