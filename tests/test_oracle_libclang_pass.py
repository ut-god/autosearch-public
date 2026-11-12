"""Tests for the libclang AST pass (Phase 2).

These tests use small synthetic .cpp files (no transitive include
dependencies) so they validate the visitor logic in isolation,
independent of how completely libclang can parse a real WebKit TU.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# These tests require the libclang shared library; skip if missing.
try:
    import clang.cindex as cc
    _LIBCLANG = "/usr/lib/x86_64-linux-gnu/libclang-18.so.18"
    cc.Config.set_library_file(_LIBCLANG)
    if not Path(_LIBCLANG).is_file():
        raise RuntimeError("libclang not present")
except Exception as e:  # noqa: BLE001
    pytest.skip(f"libclang unavailable: {e}", allow_module_level=True)


from autosearch.oracles.libclang_pass import (  # noqa: E402
    _entry_to_args,
    _select_cdb_entries,
    _visit_tu,
    filter_args_for_libclang,
    merge_phase2_into_facts,
    remap_args,
    remap_paths,
    run_phase2,
)
from autosearch.oracles.store import build_idl_only_facts  # noqa: E402


@pytest.fixture
def synthetic_tu(tmp_path: Path) -> dict:
    """Build a minimal singleton-using .cpp + a CDB pointing at it."""
    src = tmp_path / "src"
    src.mkdir()
    cpp = src / "thing.cpp"
    cpp.write_text("""
namespace WebCore {

template<typename T> class NeverDestroyed {
public:
    NeverDestroyed() = default;
    T& get() { return value; }
    T value;
};

class CGContextRef {};

class Thing {
public:
    bool strokeContains(int point) const;
    int strokeBoundingRect();
};

static CGContextRef& exampleSharedContext() {
    static NeverDestroyed<CGContextRef> ctx;
    return ctx.get();
}

bool Thing::strokeContains(int point) const {
    auto& ctx = exampleSharedContext();
    return point > 0;
}

int Thing::strokeBoundingRect() {
    auto& ctx = exampleSharedContext();
    return 42;
}

void assertIsMainThread();

void mainThreadOnly() {
    assertIsMainThread();
}

}  // namespace WebCore
""")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([{
        "directory": str(tmp_path),
        "file": str(cpp),
        "arguments": ["c++", "-std=c++17", "-c", str(cpp)],
    }]))
    return {"src": src, "cpp": cpp, "cdb": cdb, "tmp": tmp_path}


def test_filter_args_drops_gcc_only_warnings():
    args = ["-std=c++17", "-Wno-stringop-overread", "-Wno-subobject-linkage",
            "-fPIC", "-Wno-format-truncation", "-c", "foo.cpp"]
    out = filter_args_for_libclang(args)
    assert "-Wno-stringop-overread" not in out
    assert "-Wno-subobject-linkage" not in out
    assert "-Wno-format-truncation" not in out
    assert "-c" not in out
    assert "foo.cpp" not in out
    assert "-std=c++17" in out
    assert "-fPIC" in out
    assert "-Wno-unknown-warning-option" in out  # auto-added


def test_filter_args_drops_werror_and_output():
    args = ["-Werror", "-o", "out.o", "-DFOO=1", "input.mm"]
    out = filter_args_for_libclang(args)
    assert "-Werror" not in out
    assert "-o" not in out
    assert "out.o" not in out
    assert "input.mm" not in out
    assert "-DFOO=1" in out


def test_remap_paths_translates_sandbox_prefix():
    s = "-I/sdk/webkit/Source/WTF -I/sdk/webkit/Source/WebCore"
    out = remap_paths(s, {"/sdk/webkit": "/home/me/WebKit"})
    assert out == "-I/home/me/WebKit/Source/WTF -I/home/me/WebKit/Source/WebCore"


def test_remap_args_applies_to_each_arg():
    args = ["-I/sdk/webkit/inc", "-DFOO", "/sdk/webkit/file.cpp"]
    out = remap_args(args, {"/sdk/webkit": "/local"})
    assert out == ["-I/local/inc", "-DFOO", "/local/file.cpp"]


def test_select_cdb_entries_filters_by_scope_after_remap(tmp_path: Path):
    cdb = tmp_path / "cdb.json"
    cdb.write_text(json.dumps([
        {"directory": "/sdk/webkit/build", "file": "/sdk/webkit/Source/A.cpp",
         "arguments": ["c++", "/sdk/webkit/Source/A.cpp"]},
        {"directory": "/sdk/webkit/build", "file": "/sdk/webkit/Source/B/foo.cpp",
         "arguments": ["c++", "/sdk/webkit/Source/B/foo.cpp"]},
        {"directory": "/sdk/webkit/build", "file": "/sdk/webkit/Source/B/bar.h",
         "arguments": ["c++", "/sdk/webkit/Source/B/bar.h"]},
    ]))
    entries = _select_cdb_entries(cdb, scope_pattern="/Source/B/",
                                  remap={"/sdk/webkit": "/x/y"})
    files = [e["file"] for e in entries]
    assert "/x/y/Source/B/foo.cpp" in files
    assert "/x/y/Source/A.cpp" not in files  # filtered by scope
    assert all(not f.endswith(".h") for f in files)  # .h dropped


def test_select_cdb_dedups_repeated_files(tmp_path: Path):
    cdb = tmp_path / "cdb.json"
    cdb.write_text(json.dumps([
        {"directory": "/d", "file": "/x/A.cpp", "arguments": ["c++", "/x/A.cpp"]},
        {"directory": "/d", "file": "/x/A.cpp", "arguments": ["c++", "/x/A.cpp"]},
    ]))
    entries = _select_cdb_entries(cdb, scope_pattern=None, remap={})
    assert len(entries) == 1


def test_visit_tu_finds_singleton_and_callers(synthetic_tu: dict):
    cpp = synthetic_tu["cpp"]
    args = filter_args_for_libclang(["-std=c++17", "-c", str(cpp)])
    out = _visit_tu(
        cdb_directory=str(synthetic_tu["tmp"]),
        filename=str(cpp),
        args=args,
        library_file=_LIBCLANG,
        source_root=str(synthetic_tu["src"]),
    )
    assert out.get("diagnostics", -1) >= 0, "TU must parse cleanly"

    # The singleton 'ctx' inside exampleSharedContext() is a function-local static
    # NeverDestroyed; both Thing::strokeContains and Thing::strokeBoundingRect
    # call exampleSharedContext, but they don't directly touch ctx — only exampleSharedContext does.
    # So ctx should be in exampleSharedContext()'s globals_touched.
    scratch_qname = "WebCore::exampleSharedContext"
    assert scratch_qname in out["method_globals"], (
        f"exampleSharedContext should have a global; "
        f"globals seen: {list(out['method_globals'].keys())}"
    )
    g_list = out["method_globals"][scratch_qname]
    assert any(g["kind"] in ("NeverDestroyed", "static") for g in g_list)

    # Callers: Thing::strokeContains and Thing::strokeBoundingRect both call exampleSharedContext
    sc = out["method_calls"].get("WebCore::Thing::strokeContains", [])
    sb = out["method_calls"].get("WebCore::Thing::strokeBoundingRect", [])
    assert "exampleSharedContext" in sc
    assert "exampleSharedContext" in sb


def test_visit_tu_detects_assertIsMainThread(synthetic_tu: dict):
    cpp = synthetic_tu["cpp"]
    args = filter_args_for_libclang(["-std=c++17", "-c", str(cpp)])
    out = _visit_tu(
        cdb_directory=str(synthetic_tu["tmp"]),
        filename=str(cpp),
        args=args,
        library_file=_LIBCLANG,
        source_root=str(synthetic_tu["src"]),
    )
    asserts = out["method_thread_asserts"].get("WebCore::mainThreadOnly", [])
    assert "assertIsMainThread" in asserts


def test_visit_tu_respects_source_root_filter(tmp_path: Path):
    """Methods declared OUTSIDE source_root must NOT be recorded."""
    src = tmp_path / "in_scope"
    src.mkdir()
    other = tmp_path / "out_of_scope"
    other.mkdir()

    in_cpp = src / "a.cpp"
    in_cpp.write_text('int in_scope_fn() { return 1; }\n')
    out_h = other / "b.h"
    out_h.write_text('inline int out_of_scope_inline() { return 2; }\n')
    in_cpp.write_text(
        '#include "' + str(out_h) + '"\n'
        'int in_scope_fn() { return out_of_scope_inline(); }\n'
    )

    args = filter_args_for_libclang(["-std=c++17", "-c", str(in_cpp)])
    out = _visit_tu(
        cdb_directory=str(tmp_path),
        filename=str(in_cpp),
        args=args,
        library_file=_LIBCLANG,
        source_root=str(src),  # ONLY in_scope
    )
    assert any("in_scope_fn" in k for k in out["method_decl_loc"])
    assert not any("out_of_scope_inline" in k for k in out["method_decl_loc"])


def test_run_phase2_aggregates_across_tus_and_reverses_callers(synthetic_tu: dict):
    res = run_phase2(
        cdb_path=synthetic_tu["cdb"],
        libclang_lib=_LIBCLANG,
        scope_pattern=None,
        remap={},
        workers=1,
        source_root=str(synthetic_tu["src"]),
    )
    assert res.tus_walked == 1
    assert res.tus_failed == 0
    # forward edges: strokeContains called exampleSharedContext
    assert "exampleSharedContext" in res.method_calls.get(
        "WebCore::Thing::strokeContains", []
    )
    # reverse edges: exampleSharedContext was called by strokeContains (and ::strokeBoundingRect)
    callers = res.callers_1hop.get("exampleSharedContext", [])
    assert "WebCore::Thing::strokeContains" in callers
    assert "WebCore::Thing::strokeBoundingRect" in callers


def test_merge_phase2_into_facts_updates_existing_factsheet(
    synthetic_tu: dict, tmp_path: Path
):
    # Set up a Phase-1 style facts.json with some IDL exposure already there.
    facts_path = tmp_path / "method_facts.json"
    facts_path.write_text(json.dumps({
        "schema_version": 1,
        "target_sha": "abc",
        "cdb_path": None,
        "methods": {
            "WebCore::Thing::strokeContains": {
                "method": "WebCore::Thing::strokeContains",
                "decl_file": None,
                "decl_line": None,
                "idl_exposure": {
                    "exposed_to_window": True, "exposed_to_worker": True,
                    "via_idls": [{"interface": "Thing", "method": "strokeContains",
                                  "exposed": "Window,Worker", "idl_path": "x.idl"}],
                },
                "mutable_globals_touched": [],
                "callers_1hop": [],
                "thread_protections": {
                    "self_asserts_main_thread": None,
                    "self_holds_lock": None,
                    "callers_asserting_main_thread": [],
                    "callers_NOT_asserting": [],
                },
            }
        },
    }))

    p2 = run_phase2(
        cdb_path=synthetic_tu["cdb"],
        libclang_lib=_LIBCLANG,
        scope_pattern=None,
        remap={},
        workers=1,
        source_root=str(synthetic_tu["src"]),
    )
    merge_phase2_into_facts(facts_path, p2)
    payload = json.loads(facts_path.read_text())
    methods = payload["methods"]

    # The pre-existing IDL exposure must be preserved.
    sc = methods["WebCore::Thing::strokeContains"]
    assert sc["idl_exposure"]["exposed_to_worker"] is True

    # exampleSharedContext now has callers populated.
    scratch = methods.get("exampleSharedContext")
    assert scratch is not None
    caller_names = {c["caller"] for c in scratch["callers_1hop"]}
    assert "WebCore::Thing::strokeContains" in caller_names
    assert "WebCore::Thing::strokeBoundingRect" in caller_names

    # mainThreadOnly's thread_protections.self_asserts_main_thread is True.
    mt = methods.get("WebCore::mainThreadOnly")
    assert mt is not None
    assert mt["thread_protections"]["self_asserts_main_thread"] is True
