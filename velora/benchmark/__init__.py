"""Velora Security Benchmark — objective measurement of Velora's own accuracy.

Results are always measured from a real scan against ground truth. Nothing here
fabricates or hard-codes a metric.
"""
from .runner import BenchmarkReport, BenchmarkRunner, CaseResult, Metrics
from .suite import BUILTIN_SUITES, LABSHOP_SUITE, Suite, discover_suites, load_suite_file

__all__ = [
    "BenchmarkRunner",
    "BenchmarkReport",
    "CaseResult",
    "Metrics",
    "Suite",
    "BUILTIN_SUITES",
    "LABSHOP_SUITE",
    "discover_suites",
    "load_suite_file",
]
