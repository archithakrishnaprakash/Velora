"""Core primitives shared by recon, crawler, and scanners."""
from .http import HttpResponse, SafeHTTPClient

__all__ = ["SafeHTTPClient", "HttpResponse"]
