"""Security knowledge layer: CWE / OWASP / CVSS mapping and the knowledge graph.

Velora never fabricates identifiers. A mapping exists only where it has been curated and
verified; CVE and CPE are never synthesized. Unknown is reported as ``UNKNOWN``.
"""
from .catalog import CWE, OWASP, UNKNOWN, Mapping, mapping_for_check, references_for
from .cvss import CVSSAssessment, InvalidVectorError, assess, base_score, parse_vector
from .service import EnrichmentResult, KnowledgeService

__all__ = [
    "CWE",
    "OWASP",
    "UNKNOWN",
    "Mapping",
    "mapping_for_check",
    "references_for",
    "CVSSAssessment",
    "InvalidVectorError",
    "assess",
    "base_score",
    "parse_vector",
    "KnowledgeService",
    "EnrichmentResult",
]
