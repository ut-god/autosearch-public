"""Phase 3: enforcement of factsheet citations on cleans (and claims).

When the auditor (or clean-check / challenger) produces a CLEAN finding
about a method that has a non-trivial bug_class_hint (e.g. RACE_*, UAF),
the parsed JSON MUST include a ``factsheet_citations`` field naming the
specific MethodFacts subfield(s) consulted via ``oracle_method_facts``.

Required citations per bug-class hint:
  - RACE_TO_UAF / RACE_TO_OOB / RACE_TO_TYPE_CONFUSION:
        idl_exposure.exposed_to_worker AND mutable_globals_touched
  - UAF:
        callers_1hop OR thread_protections (at least one)
  - everything else: no required citations (best-effort).

A citation is a dict {field_path, value, what_it_proves} where ``field_path``
is a dotted accessor into the MethodFacts JSON (e.g.
``"idl_exposure.exposed_to_worker"`` or ``"mutable_globals_touched[0].name"``).

This module only enforces the *presence* and *shape* of citations. The
``what_it_proves`` text is recorded in the DB and surfaces during manual
triage; we don't attempt to validate semantic correctness here (Phase 4
covers cross-check against actual oracle invocations in events.jsonl).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# Bug classes that REQUIRE explicit factsheet citations on CLEANs.
# When the auditor concludes CLEAN on a target hinted at one of these,
# we want forensic evidence that the oracle was consulted.
_REQUIRED_CITATIONS_FOR_BUG_CLASS: dict[str, list[set[str]]] = {
    # Each entry is a list of *alternative* required-citation groups;
    # at least one group must be fully cited.
    "RACE_TO_UAF": [
        {"idl_exposure.exposed_to_worker", "mutable_globals_touched"},
    ],
    "RACE_TO_OOB": [
        {"idl_exposure.exposed_to_worker", "mutable_globals_touched"},
    ],
    "RACE_TO_TYPE_CONFUSION": [
        {"idl_exposure.exposed_to_worker", "mutable_globals_touched"},
    ],
    "UAF": [
        {"callers_1hop"},
        {"thread_protections.self_asserts_main_thread"},
        {"thread_protections.callers_asserting_main_thread"},
    ],
}


_FIELD_PATH_RE = re.compile(
    r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*|\[[0-9]+\])*$",
    re.IGNORECASE,
)


@dataclass
class CitationCheckResult:
    ok: bool
    error: str = ""
    cited_paths: tuple[str, ...] = ()


def _normalize_field_path(path: str) -> str:
    """Strip array indices: ``mutable_globals_touched[0].name`` → ``mutable_globals_touched``."""
    return re.sub(r"\[[0-9]+\]", "", path).split(".")[0] if "." in path else \
           re.sub(r"\[[0-9]+\]", "", path)


def _path_top_level(path: str) -> str:
    """Return the top-level field of a dotted+indexed path."""
    return re.sub(r"\[[0-9]+\]", "", path).split(".", 1)[0]


def _path_full_no_index(path: str) -> str:
    return re.sub(r"\[[0-9]+\]", "", path)


def validate_factsheet_citations(
    parsed: dict,
    *,
    bug_class_hint: Optional[str] = None,
) -> CitationCheckResult:
    """Check that a CLEAN finding (kind='clean') has the required factsheet citations.

    No-op for non-clean kinds (claims do their own thing; refinement /
    threat_model never need citations).

    The ``bug_class_hint`` comes from the target row in the DB (set by the
    threat-modeler/target-generator). When it's one of the high-risk
    bug classes, citations become mandatory.
    """
    if parsed.get("kind") != "clean":
        return CitationCheckResult(ok=True)

    if bug_class_hint is None:
        return CitationCheckResult(ok=True)

    requirement = _REQUIRED_CITATIONS_FOR_BUG_CLASS.get(bug_class_hint)
    if not requirement:
        return CitationCheckResult(ok=True)

    citations = parsed.get("factsheet_citations") or []
    if not isinstance(citations, list):
        return CitationCheckResult(
            ok=False,
            error=f"factsheet_citations must be a list (got {type(citations).__name__})",
        )

    cited_paths: list[str] = []
    for i, c in enumerate(citations):
        if not isinstance(c, dict):
            return CitationCheckResult(
                ok=False,
                error=f"factsheet_citations[{i}] must be an object",
            )
        path = c.get("field_path")
        if not isinstance(path, str) or not path:
            return CitationCheckResult(
                ok=False,
                error=f"factsheet_citations[{i}].field_path missing or empty",
            )
        if not _FIELD_PATH_RE.match(path):
            return CitationCheckResult(
                ok=False,
                error=f"factsheet_citations[{i}].field_path malformed: {path!r}",
            )
        # Also require what_it_proves so reviewers see the rationale
        if not c.get("what_it_proves"):
            return CitationCheckResult(
                ok=False,
                error=f"factsheet_citations[{i}].what_it_proves missing or empty",
            )
        cited_paths.append(_path_full_no_index(path))

    cited_set = set(cited_paths)
    cited_top = {_path_top_level(p) for p in cited_paths}

    # Check at least one alternative requirement group is fully satisfied.
    # A required path is satisfied if any cited path either matches it
    # exactly or is a child of it (e.g. "mutable_globals_touched.name"
    # satisfies the requirement "mutable_globals_touched").
    for group in requirement:
        if all(
            req in cited_set or req in cited_top or
            any(p == req or p.startswith(req + ".") for p in cited_set)
            for req in group
        ):
            return CitationCheckResult(ok=True, cited_paths=tuple(cited_paths))

    needed = " OR ".join(
        "{" + ", ".join(sorted(g)) + "}" for g in requirement
    )
    return CitationCheckResult(
        ok=False,
        error=(
            f"clean for bug_class_hint={bug_class_hint!r} must cite at least "
            f"one of {needed}; got {sorted(cited_set)}"
        ),
        cited_paths=tuple(cited_paths),
    )


def required_citation_groups_for(bug_class_hint: str) -> list[set[str]]:
    """Public helper for prompt-template authors / tests."""
    return list(_REQUIRED_CITATIONS_FOR_BUG_CLASS.get(bug_class_hint, []))
