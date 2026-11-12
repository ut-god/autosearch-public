"""Tests for the IDL exposure oracle (Phase 1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosearch.oracles.idl_parser import (
    IDLInterface,
    _merge_partials_and_includes,
    build_idl_exposure_index,
    parse_idl_file,
)
from autosearch.oracles.store import MethodFactsStore, build_idl_only_facts


@pytest.fixture
def fake_webcore(tmp_path: Path) -> Path:
    """Build a minimal Source/WebCore tree with a Worker-exposed mixin pattern."""
    root = tmp_path / "Source" / "WebCore" / "html" / "canvas"
    root.mkdir(parents=True)

    (root / "OffscreenCanvasRenderingContext2D.idl").write_text("""
[
    Conditional=OFFSCREEN_CANVAS,
    Exposed=(Window,Worker),
    JSGenerateToJSObject,
] interface OffscreenCanvasRenderingContext2D {
    readonly attribute OffscreenCanvas canvas;
    undefined commit();
};

OffscreenCanvasRenderingContext2D includes CanvasDrawPath;
""")

    (root / "CanvasRenderingContext2D.idl").write_text("""
[
    Exposed=Window,
    JSGenerateToJSObject,
] interface CanvasRenderingContext2D {
    readonly attribute HTMLCanvasElement canvas;
};

CanvasRenderingContext2D includes CanvasDrawPath;
""")

    (root / "CanvasDrawPath.idl").write_text("""
interface mixin CanvasDrawPath {
    undefined beginPath();
    undefined fill();
    boolean isPointInStroke(unrestricted double x, unrestricted double y);
};
""")

    (root / "Path2D.idl").write_text("""
[
    Exposed=(Window,Worker),
    JSGenerateToJSObject,
] interface Path2D {
    constructor();
    undefined addPath(Path2D path);
};

Path2D includes CanvasDrawPath;
""")

    return tmp_path


def test_parse_recognizes_interface_mixin(fake_webcore: Path):
    p = fake_webcore / "Source/WebCore/html/canvas/CanvasDrawPath.idl"
    ifaces, includes = parse_idl_file(p)
    assert len(ifaces) == 1
    assert ifaces[0].name == "CanvasDrawPath"
    assert "isPointInStroke" in ifaces[0].methods
    assert ifaces[0].exposed == []  # mixin has no Exposed= of its own


def test_parse_recognizes_includes_statement(fake_webcore: Path):
    p = fake_webcore / "Source/WebCore/html/canvas/OffscreenCanvasRenderingContext2D.idl"
    ifaces, includes = parse_idl_file(p)
    assert ("OffscreenCanvasRenderingContext2D", "CanvasDrawPath") in includes


def test_includes_merges_mixin_methods_into_target():
    target = IDLInterface(
        name="OffscreenCanvasRenderingContext2D",
        impl_class="OffscreenCanvasRenderingContext2D",
        exposed=["Window", "Worker"],
        methods=["commit"],
        idl_path="o.idl",
    )
    mixin = IDLInterface(
        name="CanvasDrawPath", impl_class="CanvasDrawPath",
        exposed=[], methods=["isPointInStroke", "fill"], idl_path="mixin.idl",
    )
    merged = _merge_partials_and_includes(
        [target, mixin], [("OffscreenCanvasRenderingContext2D", "CanvasDrawPath")]
    )
    by_name = {i.name: i for i in merged}
    assert "isPointInStroke" in by_name["OffscreenCanvasRenderingContext2D"].methods
    assert "fill" in by_name["OffscreenCanvasRenderingContext2D"].methods
    assert "commit" in by_name["OffscreenCanvasRenderingContext2D"].methods
    # Mixin retains its own methods (still in the list, but marked unexposed).
    assert by_name["CanvasDrawPath"].exposed == []


def test_index_marks_offscreen_method_worker_exposed(fake_webcore: Path):
    idx = build_idl_exposure_index(fake_webcore / "Source" / "WebCore")
    facts = idx.lookup("WebCore::OffscreenCanvasRenderingContext2D::isPointInStroke")
    assert facts["exposed_to_worker"] is True
    assert facts["exposed_to_window"] is True


def test_index_marks_canvas_method_window_only(fake_webcore: Path):
    idx = build_idl_exposure_index(fake_webcore / "Source" / "WebCore")
    facts = idx.lookup("WebCore::CanvasRenderingContext2D::isPointInStroke")
    assert facts["exposed_to_window"] is True
    assert facts["exposed_to_worker"] is False


def test_unindexed_method_returns_empty_facts(fake_webcore: Path):
    idx = build_idl_exposure_index(fake_webcore / "Source" / "WebCore")
    facts = idx.lookup("WebCore::SomeInternalImpl::doStuff")
    assert facts["exposed_to_worker"] is False
    assert facts["exposed_to_window"] is False
    assert facts["via_idls"] == []


def test_build_idl_only_facts_writes_complete_payload(fake_webcore: Path, tmp_path: Path):
    out = tmp_path / "method_facts.json"
    payload = build_idl_only_facts(fake_webcore, out, target_sha="abc123")
    assert out.is_file()
    assert payload["target_sha"] == "abc123"
    assert payload["schema_version"] == 1
    n_methods = len(payload["methods"])
    assert n_methods >= 4  # commit, beginPath, fill, isPointInStroke, addPath, ...
    # FactSheet shape contains every required field, even if null.
    f = next(iter(payload["methods"].values()))
    assert "idl_exposure" in f
    assert "mutable_globals_touched" in f
    assert "callers_1hop" in f
    assert "thread_protections" in f


def test_factsheet_store_lookup_returns_empty_for_unknown(tmp_path: Path):
    out = tmp_path / "method_facts.json"
    out.write_text(json.dumps({
        "schema_version": 1, "target_sha": None, "cdb_path": None, "methods": {},
    }))
    s = MethodFactsStore.from_file(out)
    f = s.lookup("WebCore::Nope::doesntExist")
    assert f["idl_exposure"]["exposed_to_worker"] is False
    assert f["mutable_globals_touched"] == []
    assert f["thread_protections"]["self_asserts_main_thread"] is None


def test_factsheet_store_round_trips_real_data(fake_webcore: Path, tmp_path: Path):
    out = tmp_path / "method_facts.json"
    build_idl_only_facts(fake_webcore, out, target_sha="testsha")
    s = MethodFactsStore.from_file(out)
    f = s.lookup("WebCore::OffscreenCanvasRenderingContext2D::isPointInStroke")
    assert f["idl_exposure"]["exposed_to_worker"] is True
    assert s.target_sha == "testsha"
    assert s.schema_version == 1
