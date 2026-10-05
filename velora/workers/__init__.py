"""Concurrency primitives.

Velora uses in-process asyncio for concurrency (no Celery). The crawler runs a bounded
worker pool over a URL queue; ``bounded_gather`` here is the general primitive for running
many awaitables with a concurrency cap, used where independent async work is fanned out.
"""
from .pool import bounded_gather

__all__ = ["bounded_gather"]
