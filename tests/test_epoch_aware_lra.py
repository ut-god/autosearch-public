"""Tests for epoch-aware target preselection.

When refinement updates ``catalog.md`` or ``mitigations.md``, methods whose
last clean was recorded under the old epoch should be re-audited with
priority over plain LRA — the prior CLEAN was issued without knowledge of
the new R-NN / M-NN entries, so a re-audit under the new epoch is warranted.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

# Allow `import autosearch.*` when running outside an installed venv.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from autosearch.orchestrator import Orchestrator
from autosearch.store.db import Store
from autosearch.store.workspace import WorkspaceConfig


def _new_store() -> Store:
    return Store.open(Path(tempfile.mkdtemp()))


def _seed_targets(store: Store, n: int) -> None:
    store.replace_targets([
        {
            "target_class": f"C{i}", "target_method": f"m{i}",
            "bug_class_hint": "OOB_WRITE", "reason": "r", "campaign": "c",
            "sub_area": f"area{i % 4}", "source_path": "foo.cpp",
        }
        for i in range(n)
    ])


def _record_clean(store: Store, cycle_n: int, idx: int,
                  catalog_id: int, mitigations_id: int,
                  prompt_version_id: int) -> None:
    ar = store.record_agent_run(
        cycle_n=cycle_n, agent_name="auditor", slot=f"s{idx}", model="claude",
        cli_version="x", prompt_version_id=prompt_version_id,
        rendered_prompt="p", raw_response="r", parse_status="ok",
        parsed_json={}, started_at="t", ended_at="t",
        duration_ms=1, exit_code=0, error_message="",
        prompt_tokens=0, completion_tokens=0, cost_usd=0,
    )
    store.insert_clean(
        run_id=ar, cycle_n=cycle_n,
        parsed={
            "kind": "clean", "target_class": f"C{idx}",
            "target_method": f"m{idx}", "checks_verified": [], "body": "trivial",
        },
        model="claude",
        catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha="sha1",
    )


def test_least_recently_audited_marks_stale_epoch():
    """`epoch_stale=1` only when latest clean was under a different epoch."""
    store = _new_store()
    cat1 = store.upsert_catalog_version("# v1\n")
    cat2 = store.upsert_catalog_version("# v2\n")
    mit1 = store.upsert_mitigations_version("# v1\n")
    mit2 = store.upsert_mitigations_version("# v2\n")
    pv = store.upsert_prompt_version("auditor", "t")

    _seed_targets(store, n=3)
    cyc = store.start_cycle(cat1, mit1, "sha1")
    _record_clean(store, cyc, 0, cat1, mit1, pv)
    store.finish_cycle(cyc, 0.0, {})

    # Same epoch → not stale.
    rows = {r["target_method"]: r for r in
            store.least_recently_audited(limit=10,
                                          catalog_id=cat1, mitigations_id=mit1)}
    assert rows["m0"]["epoch_stale"] == 0
    assert rows["m1"]["epoch_stale"] == 0  # never cleaned → not stale
    assert rows["m2"]["epoch_stale"] == 0

    # Catalog changed → m0 is stale.
    rows = {r["target_method"]: r for r in
            store.least_recently_audited(limit=10,
                                          catalog_id=cat2, mitigations_id=mit1)}
    assert rows["m0"]["epoch_stale"] == 1
    assert rows["m1"]["epoch_stale"] == 0
    assert rows["m2"]["epoch_stale"] == 0

    # Mitigations changed → m0 is stale.
    rows = {r["target_method"]: r for r in
            store.least_recently_audited(limit=10,
                                          catalog_id=cat1, mitigations_id=mit2)}
    assert rows["m0"]["epoch_stale"] == 1


def test_least_recently_audited_legacy_call_omits_epoch_stale():
    """Backward-compat: no epoch args → no `epoch_stale` column."""
    store = _new_store()
    _seed_targets(store, n=2)
    rows = store.least_recently_audited(limit=10)
    assert rows
    assert "epoch_stale" not in rows[0].keys()


def _make_orchestrator(store: Store, workspace: Path,
                       cohort_methods: int = 6) -> Orchestrator:
    config = WorkspaceConfig(target_repo=workspace, cohort_methods=cohort_methods)
    return Orchestrator(
        workspace=workspace, config=config, store=store,
        dispatcher=MagicMock(), status_writer=MagicMock(),
    )


def test_preselect_targets_boosts_stale_epoch_methods_after_phase_one():
    """When all targets are audited, an epoch change boosts stale methods
    over plain LRA — and respects the 2-per-sub_area cap."""
    workspace = Path(tempfile.mkdtemp())
    store = Store.open(workspace)

    cat1 = store.upsert_catalog_version("# v1\n")
    cat2 = store.upsert_catalog_version("# v2\n")
    mit1 = store.upsert_mitigations_version("# v1\n")
    pv = store.upsert_prompt_version("auditor", "t")

    _seed_targets(store, n=20)

    # Audit all 20 methods under (cat1, mit1) so Phase 1 has nothing to give.
    cyc = store.start_cycle(cat1, mit1, "sha1")
    for i in range(20):
        _record_clean(store, cyc, i, cat1, mit1, pv)
    store.finish_cycle(cyc, 0.0, {})

    orch = _make_orchestrator(store, workspace, cohort_methods=6)

    # Same epoch → plain LRA picks oldest (m0..m5 modulo sub_area cap).
    chosen = orch._preselect_targets(6, catalog_id=cat1, mitigations_id=mit1)
    assert all(c.get("epoch_stale", 0) == 0 for c in chosen)

    # Catalog changed → all 20 cleans are stale → boost activates.
    chosen = orch._preselect_targets(6, catalog_id=cat2, mitigations_id=mit1)
    assert len(chosen) == 6
    assert all(c["epoch_stale"] == 1 for c in chosen), \
        "catalog change should boost stale-epoch methods"

    # 2-per-sub_area cap honored.
    per_area: dict[str, int] = {}
    for c in chosen:
        per_area[c["sub_area"]] = per_area.get(c["sub_area"], 0) + 1
    assert all(n <= 2 for n in per_area.values()), \
        f"sub_area cap violated: {per_area}"


def test_preselect_targets_phase_one_still_wins_over_boost():
    """Untouched (Phase 1) targets should always beat stale-epoch (Phase 1.5)
    targets — coverage of new methods takes priority over re-auditing
    already-cleaned ones, even after a catalog change."""
    workspace = Path(tempfile.mkdtemp())
    store = Store.open(workspace)

    cat1 = store.upsert_catalog_version("# v1\n")
    cat2 = store.upsert_catalog_version("# v2\n")
    mit1 = store.upsert_mitigations_version("# v1\n")
    pv = store.upsert_prompt_version("auditor", "t")

    # 10 targets total: clean methods 0-3 under cat1, leave 4-9 untouched.
    _seed_targets(store, n=10)
    cyc = store.start_cycle(cat1, mit1, "sha1")
    for i in range(4):
        _record_clean(store, cyc, i, cat1, mit1, pv)
    store.finish_cycle(cyc, 0.0, {})

    orch = _make_orchestrator(store, workspace, cohort_methods=6)

    # Catalog changed: methods 0-3 are stale, but methods 4-9 are untouched.
    # Phase 1 must consume all 6 slots with untouched targets.
    chosen = orch._preselect_targets(6, catalog_id=cat2, mitigations_id=mit1)
    methods = {c["target_method"] for c in chosen}
    assert methods == {"m4", "m5", "m6", "m7", "m8", "m9"}, \
        f"untouched targets must win over stale-epoch boost; got {methods}"


def test_preselect_targets_no_epoch_args_uses_legacy_path():
    """When the orchestrator passes no epoch IDs (e.g. older callers),
    selection still works using the legacy LRA-only path."""
    workspace = Path(tempfile.mkdtemp())
    store = Store.open(workspace)
    _seed_targets(store, n=5)
    orch = _make_orchestrator(store, workspace, cohort_methods=3)
    chosen = orch._preselect_targets(3)
    assert len(chosen) == 3
