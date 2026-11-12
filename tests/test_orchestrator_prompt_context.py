from pathlib import Path

from autosearch.orchestrator import (
    _apply_structured_refinement,
    _cap_grouped_mitigations_md,
    _format_threat_model_context,
    _threat_model_file_matches_target,
)


def test_threat_model_file_matching_prefers_exact_source_path():
    target = {
        "target_class": "WebCore::DataDetection",
        "source_path": "Source/WebCore/editing/cocoa/DataDetection.mm",
    }

    assert _threat_model_file_matches_target(
        Path("Source_WebCore_editing_cocoa_DataDetection.mm.json"),
        target,
    )
    assert not _threat_model_file_matches_target(
        Path("Source_WebCore_editing_VisibleUnits.cpp.json"),
        target,
    )


def test_format_threat_model_context_is_structured_and_target_focused():
    target = {
        "target_class": "WebCore::DataDetection",
        "target_method": "detectContentInRange",
        "source_path": "Source/WebCore/editing/cocoa/DataDetection.mm",
    }
    rendered = _format_threat_model_context(
        {
            "kind": "threat_model",
            "area": "DataDetection file",
            "paths": ["Source/WebCore/editing/cocoa/DataDetection.mm"],
            "entry_points": [
                {
                    "method": "WebCore::DataDetection::detectContentInRange",
                    "file": "Source/WebCore/editing/cocoa/DataDetection.mm",
                    "line": 762,
                    "renderer_surface": "editable DOM range",
                },
                {
                    "method": "WebCore::DataDetection::detectContentInFrame",
                    "file": "Source/WebCore/editing/cocoa/DataDetection.mm",
                    "line": 715,
                    "renderer_surface": "whole document",
                },
            ],
            "assets": [
                {"name": "Text data", "invariant": "offset <= length"},
            ],
            "candidate_methods": [
                {
                    "method": "WebCore::processDataDetectorScannerResults",
                    "bug_class": "UAF",
                    "reason": "DOM mutation can stale offsets",
                },
                {
                    "method": "WebCore::DataDetection::detectContentInFrame",
                    "bug_class": "RACE_TO_UAF",
                    "reason": "other entry point",
                },
            ],
            "corruption_sinks": [
                {
                    "file": "Source/WebCore/editing/cocoa/DataDetection.mm",
                    "line": 656,
                    "op_kind": "read",
                    "asset": "Text data",
                    "driven_by": "range.start.offset - contentOffset",
                    "bug_class": "INT_OVERFLOW_TO_OOB",
                    "existing_check": {
                        "file": "Source/WebCore/editing/cocoa/DataDetection.mm",
                        "line": 0,
                    },
                }
            ],
            "attacker_controlled_values": [],
            "invariants": [],
        },
        target,
    )

    assert "Relevant entry-point note:" in rendered
    assert "Potential areas to inspect from threat model:" in rendered
    assert "ASSET:" not in rendered
    assert "SINK:" not in rendered
    assert "prepass safety note: none recorded" in rendered
    assert "detectContentInFrame" not in rendered


def test_structured_refinement_merges_entries_without_full_markdown_output():
    catalog, mitigations = _apply_structured_refinement(
        "",
        "# Mitigations\n\nExisting intro.\n\n- M-001 (bounds check) Pattern: Existing guard. Examples: Source/A.cpp:1.\n",
        {
            "catalog_entries": [
                {
                    "bug_class": "UAF",
                    "pattern": "Callback uses a raw pointer after owner teardown",
                    "evidence": ["Source/B.cpp:10"],
                    "applies_when": "raw pointer crosses teardown callback",
                }
            ],
            "mitigation_entries": [
                {
                    "guard_kind": "bounds check",
                    "pattern": "Existing guard",
                    "witnesses": ["Source/A.cpp:1"],
                },
                {
                    "guard_kind": "lifetime owner",
                    "pattern": "Range endpoints are retained by value-owned refs",
                    "witnesses": ["Source/C.h:7"],
                    "do_not_flag_unless": "the owning range is destroyed before use",
                },
            ],
        },
    )

    assert "R-001 (UAF)" in catalog
    assert "M-001 (bounds check) Pattern: Existing guard" in mitigations
    assert "M-002 (lifetime owner) Pattern: Range endpoints" in mitigations
    assert mitigations.count("Existing guard") == 1


def test_structured_refinement_skips_case_without_pattern():
    _, mitigations = _apply_structured_refinement(
        "",
        "",
        {
            "mitigation_entries": [
                {
                    "guard_kind": "bounds check",
                    "witnesses": ["Source/OneCase.cpp:99"],
                },
                {
                    "guard_kind": "bounds check",
                    "pattern": "Container accessors fail closed when indexes exceed length",
                    "witnesses": ["Source/OneCase.cpp:99"],
                },
            ],
        },
    )

    assert "Source/OneCase.cpp:99" in mitigations
    assert mitigations.count("- M-") == 1
    assert "Pattern: Container accessors fail closed" in mitigations


def test_structured_refinement_dedupes_mitigations_by_pattern_not_witness():
    _, mitigations = _apply_structured_refinement(
        "",
        "",
        {
            "mitigation_entries": [
                {
                    "guard_kind": "bounds check",
                    "pattern": "Substring helpers clamp oversized ranges",
                    "witnesses": ["Source/A.cpp:1"],
                },
                {
                    "guard_kind": "bounds check",
                    "pattern": "Substring helpers clamp oversized ranges",
                    "witnesses": ["Source/B.cpp:2"],
                },
            ],
        },
    )

    assert mitigations.count("- M-") == 1
    assert "Source/A.cpp:1" in mitigations
    assert "Source/B.cpp:2" not in mitigations


def test_grouped_mitigations_cap_rejects_witness_only_rewrite():
    current = (
        "# Mitigations\n\n"
        "- M-001 (bounds check) Pattern: Existing reusable pattern. "
        "Examples: Source/A.cpp:1.\n"
    )
    proposed = (
        "# Mitigations\n\n"
        "- M-001 (bounds check): Source/B.cpp:2 was safe in this case.\n"
    )

    assert _cap_grouped_mitigations_md(proposed, current) == current.strip()


def test_grouped_mitigations_cap_limits_growth_and_entry_count():
    current = "# Mitigations\n\n"
    proposed_entries = []
    for idx in range(30):
        proposed_entries.append(
            f"- M-{idx + 1:03d} (bounds check) Pattern: Reusable pattern {idx}. "
            f"Examples: Source/File{idx}.cpp:{idx}. "
            f"Do not flag unless: proof {idx}."
        )
    proposed = "# Mitigations\n\n" + "\n\n".join(proposed_entries)

    capped = _cap_grouped_mitigations_md(proposed, current)

    assert capped.count("- M-") <= 16
    assert len(capped) <= 6500
    assert "- M-001" in capped
    assert "- M-017" not in capped
