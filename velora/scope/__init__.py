"""Scope enforcement: the authorization boundary for every outbound request."""
from .policy import RedirectPolicy, ScopePolicy
from .manager import ScopeDecision, ScopeManager

__all__ = ["ScopePolicy", "RedirectPolicy", "ScopeManager", "ScopeDecision"]
