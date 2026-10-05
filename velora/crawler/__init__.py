"""Asynchronous, scope-bounded, same-origin web crawler."""
from .crawler import CrawlResult, Crawler, DiscoveredEndpoint

__all__ = ["Crawler", "CrawlResult", "DiscoveredEndpoint"]
