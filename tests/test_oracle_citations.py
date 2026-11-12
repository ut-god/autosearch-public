"""Tests for Phase 3: factsheet citation enforcement on cleans."""
from __future__ import annotations

import pytest

from autosearch.oracles import (
    required_citation_groups_for,
    validate_factsheet_citations,
)


def test_non_clean_kinds_are_pass_through():
    """Citations only enforced on cleans; claims/refinement are unaffected."""
    for kind in ("claim", "refinement", "threat_model", "validation", "challenge"):
        r = validate_factsheet_citations({"kind": kind}, bug_class_hint="RACE_TO_UAF")
        assert r.ok, f"{kind} should be allowed without citations"


def test_no_hint_means_no_requirement():
    """No bug_class_hint → no requirement to cite."""
    r = validate_factsheet_citations({"kind": "clean"}, bug_class_hint=None)
    assert r.ok


def test_unrecognized_hint_means_no_requirement():
    """Bug-class hints we haven't decided to enforce stay permissive."""
    r = validate_factsheet_citations(
        {"kind": "clean"}, bug_class_hint="UNKNOWN_FANCIFUL_BUG_CLASS"
    )
    assert r.ok


def test_race_uaf_requires_idl_and_globals():
    """RACE_TO_UAF cleans must cite both worker exposure AND mutable globals."""
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "idl_exposure.exposed_to_worker",
             "value": False, "what_it_proves": "not worker reachable"},
            {"field_path": "mutable_globals_touched",
             "value": [], "what_it_proves": "no shared singletons"},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert r.ok
    assert len(r.cited_paths) == 2


def test_race_uaf_rejects_partial_citations():
    """Citing only one of the required pair is insufficient."""
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "idl_exposure.exposed_to_worker",
             "value": False, "what_it_proves": "not reachable from worker"},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok
    assert "mutable_globals_touched" in r.error


def test_race_uaf_rejects_missing_citations_field():
    parsed = {"kind": "clean"}
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok


def test_uaf_accepts_callers_alone():
    """UAF cleans need only one of: callers_1hop / thread_protections paths."""
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "callers_1hop", "value": [],
             "what_it_proves": "no callers exist; method is dead code"},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="UAF")
    assert r.ok


def test_uaf_accepts_thread_protections_alone():
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "thread_protections.self_asserts_main_thread",
             "value": True, "what_it_proves": "method asserts main-thread"},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="UAF")
    assert r.ok


def test_indexed_path_satisfies_required_top_field():
    """Citing mutable_globals_touched[0].name satisfies the
    'mutable_globals_touched' requirement (parent-of relationship)."""
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "idl_exposure.exposed_to_worker",
             "value": True, "what_it_proves": "worker-reachable"},
            {"field_path": "mutable_globals_touched[0].name",
             "value": "exampleSharedContext",
             "what_it_proves": "shared singleton present, but ..."},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert r.ok


def test_malformed_field_path_rejected():
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "idl_exposure foo bar",
             "value": False, "what_it_proves": "x"},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok
    assert "malformed" in r.error.lower()


def test_missing_what_it_proves_rejected():
    parsed = {
        "kind": "clean",
        "factsheet_citations": [
            {"field_path": "idl_exposure.exposed_to_worker", "value": False},
        ],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok
    assert "what_it_proves" in r.error


def test_factsheet_citations_must_be_list():
    parsed = {
        "kind": "clean",
        "factsheet_citations": {"field_path": "x", "what_it_proves": "y"},
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok
    assert "must be a list" in r.error


def test_citation_dict_must_be_object():
    parsed = {
        "kind": "clean",
        "factsheet_citations": ["just a string, not an object"],
    }
    r = validate_factsheet_citations(parsed, bug_class_hint="RACE_TO_UAF")
    assert not r.ok
    assert "must be an object" in r.error


def test_required_citation_groups_for_helper():
    """Public introspection helper for prompt-template authors."""
    groups = required_citation_groups_for("RACE_TO_UAF")
    assert len(groups) == 1
    assert {"idl_exposure.exposed_to_worker", "mutable_globals_touched"} in groups

    assert required_citation_groups_for("UNKNOWN_HINT") == []


def test_all_three_race_classes_have_same_requirement():
    """RACE_TO_UAF, RACE_TO_OOB, RACE_TO_TYPE_CONFUSION are symmetric."""
    base = required_citation_groups_for("RACE_TO_UAF")
    assert required_citation_groups_for("RACE_TO_OOB") == base
    assert required_citation_groups_for("RACE_TO_TYPE_CONFUSION") == base
