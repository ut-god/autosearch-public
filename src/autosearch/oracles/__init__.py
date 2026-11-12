"""autosearch oracles: mechanical ground-truth indexes consulted via SDK tools.

Phase 1: idl_exposure (text-only, no clang).
Phase 2: mutable_globals + callers + thread_protections (libclang).

The single tool ``oracle_method_facts(method)`` returns a structured ``MethodFacts``
JSON the auditor cites by subfield path (e.g. ``facts.idl_exposure.exposed_to_worker``).
"""

from .store import MethodFactsStore, OraclesNotBootstrapped
from .tool import build_oracle_tool
from .citations import (
    CitationCheckResult,
    required_citation_groups_for,
    validate_factsheet_citations,
)

__all__ = [
    "MethodFactsStore", "OraclesNotBootstrapped", "build_oracle_tool",
    "CitationCheckResult", "validate_factsheet_citations",
    "required_citation_groups_for",
]
