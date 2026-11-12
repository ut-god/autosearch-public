"""libclang AST pass: populates mutable_globals_touched, callers_1hop,
and thread_protections on the existing MethodFacts FactSheet.

Phase 2 of the oracles plan. Reads ``compile_commands.json`` and visits
every translation unit under the configured scope, then merges per-method
facts into ``workspace/oracles/method_facts.json``.

Compatibility quirks we handle:
  • CDB paths may be hardcoded to a build-sandbox prefix (e.g.
    ``/sdk/webkit``). We rewrite to the real ``target_repo`` location.
  • CDB compile commands target gcc but libclang is clang. Strip
    gcc-specific ``-W`` flags and add ``-Wno-unknown-warning-option``.
  • Unified-builds list each TU once; we walk the unified header,
    not the individual .cpp.
"""
from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger(__name__)


# ---- arg munging --------------------------------------------------

# clang doesn't recognize these gcc-only -W flags; libclang errors silently.
_GCC_ONLY_W_FLAGS = (
    "-Wno-stringop-overread", "-Wno-stringop-overflow",
    "-Wno-subobject-linkage", "-Wno-maybe-uninitialized",
    "-Wno-format-truncation", "-Wno-class-memaccess",
    "-Wno-missing-attributes", "-Wno-restrict",
    "-Wno-format-overflow", "-Wno-cast-function-type",
    "-Wno-stringop-truncation", "-Wno-array-bounds",
)


def filter_args_for_libclang(args: list[str]) -> list[str]:
    """Strip flags that prevent libclang from parsing a gcc-built TU."""
    out: list[str] = ["-Wno-unknown-warning-option", "-ferror-limit=0"]
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a == "-c":
            continue
        if a == "-o":
            skip_next = True
            continue
        if a.endswith((".cpp", ".cc", ".mm", ".c", ".o")):
            continue
        if a in _GCC_ONLY_W_FLAGS:
            continue
        if a == "-Werror":
            continue  # don't promote anything to error during oracle parsing
        out.append(a)
    return out


def remap_paths(s: str, remap: dict[str, str]) -> str:
    """Rewrite all ``old`` prefixes to ``new`` in ``s``. Order-stable."""
    for old, new in remap.items():
        if old in s:
            s = s.replace(old, new)
    return s


def remap_args(args: list[str], remap: dict[str, str]) -> list[str]:
    return [remap_paths(a, remap) for a in args]


# ---- per-TU visitor -----------------------------------------------

@dataclass
class TUFacts:
    """Raw per-TU output. Aggregated across TUs by the merger."""
    method_globals: dict[str, list[dict]] = field(default_factory=dict)
    method_calls: dict[str, list[str]] = field(default_factory=dict)
    method_thread_asserts: dict[str, list[str]] = field(default_factory=dict)
    method_decl_loc: dict[str, tuple[str, int]] = field(default_factory=dict)
    diagnostics: int = 0


_THREAD_ASSERT_RE = re.compile(
    r"^(assertIsMainThread|isMainThread|RELEASE_ASSERT_WITH_MESSAGE|"
    r"assertIsCurrent|Locker|std::lock_guard|std::unique_lock|"
    r"holdLock|RunLoop::isMain|callOnMainThread)$"
)


def _qualified_method_name(cursor) -> str:
    """Return ``WebCore::Class::method`` for a CXX_METHOD; namespace::function for free fn."""
    parts = []
    p = cursor.semantic_parent
    while p is not None and p.kind.name not in ("TRANSLATION_UNIT",):
        if p.spelling:
            parts.append(p.spelling)
        p = p.semantic_parent
    parts.reverse()
    parts.append(cursor.spelling)
    return "::".join(parts)


def _classify_global(var_cursor) -> Optional[str]:
    """Return a kind-string if ``var_cursor`` is a process-shared mutable global, else None."""
    import clang.cindex as cc
    sc = var_cursor.storage_class
    linkage = var_cursor.linkage
    type_spelling = var_cursor.type.spelling

    # Reject const (including const arrays — check both whole type and element type)
    if var_cursor.type.is_const_qualified():
        return None
    et = var_cursor.type.get_array_element_type()
    if et and et.spelling and et.is_const_qualified():
        return None
    if "const " in type_spelling[:64] or type_spelling.startswith("const"):
        return None

    # NeverDestroyed / LazyNeverDestroyed (the WebKit singleton patterns)
    if "NeverDestroyed" in type_spelling:
        return "NeverDestroyed"
    if "LazyNeverDestroyed" in type_spelling:
        return "LazyNeverDestroyed"
    # static T at file or namespace scope
    if sc == cc.StorageClass.STATIC:
        return "static"
    # namespace-scope globals (no static, but file-scope or namespace-scope mutables)
    if linkage == cc.LinkageKind.EXTERNAL:
        if var_cursor.semantic_parent and var_cursor.semantic_parent.kind.name == "NAMESPACE":
            return "namespace_global"
    return None


def _visit_tu(
    cdb_directory: str, filename: str, args: list[str],
    library_file: str,
    source_root: Optional[str] = None,
) -> dict:
    """Worker: parse one TU and return raw TUFacts as a serializable dict.

    ``source_root``: only record facts about declarations/methods whose
    ``decl_file`` starts with this prefix (e.g. the absolute path of the
    target_repo's Source/ dir). Filters out facts from transitive system
    headers / vendored libs (libsimde, std, etc.).
    """
    import clang.cindex as cc
    if library_file:
        try:
            cc.Config.set_library_file(library_file)
        except Exception:
            pass

    facts = TUFacts()

    try:
        os.chdir(cdb_directory)
    except FileNotFoundError:
        pass

    try:
        idx = cc.Index.create()
        tu = idx.parse(filename, args=args)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "filename": filename,
                "method_globals": {}, "method_calls": {},
                "method_thread_asserts": {}, "method_decl_loc": {},
                "diagnostics": -1}

    facts.diagnostics = sum(1 for _ in tu.diagnostics)

    def _in_source_root(loc) -> bool:
        if source_root is None:
            return True
        if not loc.file:
            return False
        return str(loc.file.name).startswith(source_root)

    # Pre-pass: find all global VarDecls and remember their "is mutable global" status
    global_var_kinds: dict[int, tuple[str, str]] = {}
    for node in tu.cursor.walk_preorder():
        if node.kind == cc.CursorKind.VAR_DECL:
            kind = _classify_global(node)
            if kind:
                key = node.get_usr() or node.spelling
                global_var_kinds[hash(key)] = (node.spelling, kind)

    # Main pass: walk every CXX_METHOD / FUNCTION_DECL with a body
    for node in tu.cursor.walk_preorder():
        if node.kind not in (cc.CursorKind.CXX_METHOD, cc.CursorKind.FUNCTION_DECL,
                             cc.CursorKind.CONSTRUCTOR, cc.CursorKind.DESTRUCTOR):
            continue
        if not node.is_definition():
            continue
        loc = node.location
        if not _in_source_root(loc):
            continue
        if not str(loc.file.name).endswith((".cpp", ".cc", ".mm", ".h")):
            continue

        qname = _qualified_method_name(node)
        facts.method_decl_loc[qname] = (str(loc.file.name), loc.line)

        globals_touched: list[dict] = []
        calls_made: list[str] = []
        asserts_found: list[str] = []

        for child in node.walk_preorder():
            if child.kind == cc.CursorKind.DECL_REF_EXPR:
                ref = child.referenced
                if ref and ref.kind == cc.CursorKind.VAR_DECL:
                    rl = ref.location
                    if not _in_source_root(rl):
                        continue
                    key = ref.get_usr() or ref.spelling
                    if hash(key) in global_var_kinds:
                        name, kind = global_var_kinds[hash(key)]
                        globals_touched.append({
                            "name": name,
                            "kind": kind,
                            "decl_file": str(rl.file.name) if rl.file else None,
                            "decl_line": rl.line if rl.file else None,
                            "type": ref.type.spelling[:200],
                        })
            elif child.kind == cc.CursorKind.CALL_EXPR:
                callee = child.referenced
                if callee and callee.spelling:
                    sp = callee.spelling
                    calls_made.append(sp)
                    if _THREAD_ASSERT_RE.match(sp):
                        asserts_found.append(sp)

        if globals_touched:
            seen = set()
            uniq = []
            for g in globals_touched:
                k = (g["name"], g["decl_file"], g["decl_line"])
                if k not in seen:
                    seen.add(k)
                    uniq.append(g)
            facts.method_globals[qname] = uniq
        if calls_made:
            facts.method_calls[qname] = sorted(set(calls_made))
        if asserts_found:
            facts.method_thread_asserts[qname] = sorted(set(asserts_found))

    return {
        "method_globals": facts.method_globals,
        "method_calls": facts.method_calls,
        "method_thread_asserts": facts.method_thread_asserts,
        "method_decl_loc": {k: list(v) for k, v in facts.method_decl_loc.items()},
        "diagnostics": facts.diagnostics,
    }


# ---- driver -------------------------------------------------------

@dataclass
class Phase2Result:
    method_globals: dict[str, list[dict]]
    method_calls: dict[str, list[str]]      # forward edges: method → callees
    callers_1hop: dict[str, list[str]]      # reverse edges: method → 1-hop callers
    method_thread_asserts: dict[str, list[str]]
    method_decl_loc: dict[str, tuple[str, int]]
    tus_walked: int
    tus_failed: int


def _select_cdb_entries(
    cdb_path: Path,
    scope_pattern: Optional[str],
    remap: dict[str, str],
) -> list[dict]:
    """Read the CDB JSON, filter to the scope, and remap paths."""
    import json as _json
    raw = _json.loads(cdb_path.read_text())
    entries = []
    seen: set[str] = set()
    for e in raw:
        f = remap_paths(e.get("file", ""), remap)
        if not f.endswith((".cpp", ".cc", ".mm")):
            continue
        if scope_pattern and scope_pattern not in f:
            continue
        if f in seen:
            continue
        seen.add(f)
        # Remap directory + arguments too
        e2 = dict(e)
        e2["file"] = f
        if "directory" in e2:
            e2["directory"] = remap_paths(e2["directory"], remap)
        if "command" in e2:
            e2["command"] = remap_paths(e2["command"], remap)
        if "arguments" in e2:
            e2["arguments"] = [remap_paths(a, remap) for a in e2["arguments"]]
        entries.append(e2)
    return entries


def _entry_to_args(entry: dict) -> list[str]:
    """Extract args list from CDB entry (handles 'command' or 'arguments' form)."""
    if "arguments" in entry:
        return list(entry["arguments"])[1:]  # drop compiler binary
    import shlex
    parts = shlex.split(entry.get("command", ""))
    return parts[1:] if parts else []


def run_phase2(
    cdb_path: Path,
    *,
    libclang_lib: str = "/usr/lib/x86_64-linux-gnu/libclang-18.so.18",
    scope_pattern: Optional[str] = None,
    remap: Optional[dict[str, str]] = None,
    workers: int = 16,
    callers_cap: int = 50,
    source_root: Optional[str] = None,
) -> Phase2Result:
    """Run Phase 2 over the CDB. Returns aggregated facts.

    ``source_root``: only record facts about methods whose decl file starts
    with this prefix. Strongly recommended (without it, transitive system
    headers like libstdc++/libsimde produce huge noise).
    """
    remap = remap or {}
    entries = _select_cdb_entries(cdb_path, scope_pattern, remap)
    log.info("phase2: walking %d TUs (scope=%r, workers=%d, source_root=%r)",
             len(entries), scope_pattern, workers, source_root)

    method_globals: dict[str, list[dict]] = {}
    method_calls: dict[str, list[str]] = {}
    method_thread_asserts: dict[str, list[str]] = {}
    method_decl_loc: dict[str, tuple[str, int]] = {}
    tus_walked = 0
    tus_failed = 0

    def _merge(per_tu: dict) -> None:
        nonlocal tus_walked, tus_failed
        if per_tu.get("diagnostics") == -1:
            tus_failed += 1
            log.warning("phase2: TU parse error: %s", per_tu.get("error"))
            return
        tus_walked += 1
        for k, v in per_tu["method_globals"].items():
            method_globals.setdefault(k, []).extend(v)
        for k, v in per_tu["method_calls"].items():
            method_calls.setdefault(k, []).extend(v)
        for k, v in per_tu["method_thread_asserts"].items():
            method_thread_asserts.setdefault(k, []).extend(v)
        for k, v in per_tu["method_decl_loc"].items():
            method_decl_loc[k] = tuple(v)

    if workers <= 1:
        for e in entries:
            args = filter_args_for_libclang(_entry_to_args(e))
            per_tu = _visit_tu(e["directory"], e["file"], args, libclang_lib,
                               source_root=source_root)
            _merge(per_tu)
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = []
            for e in entries:
                args = filter_args_for_libclang(_entry_to_args(e))
                fut = pool.submit(_visit_tu, e["directory"], e["file"], args,
                                  libclang_lib, source_root)
                futures.append(fut)
            for i, fut in enumerate(as_completed(futures)):
                if (i + 1) % 50 == 0:
                    log.info("phase2: progress %d/%d", i + 1, len(futures))
                try:
                    _merge(fut.result(timeout=120))
                except Exception as ex:  # noqa: BLE001
                    tus_failed += 1
                    log.warning("phase2: future failed: %s", ex)

    # Dedup globals lists
    for k, lst in method_globals.items():
        seen = set()
        uniq = []
        for g in lst:
            key = (g["name"], g["decl_file"], g["decl_line"])
            if key not in seen:
                seen.add(key)
                uniq.append(g)
        method_globals[k] = uniq

    for k, lst in method_calls.items():
        method_calls[k] = sorted(set(lst))
    for k, lst in method_thread_asserts.items():
        method_thread_asserts[k] = sorted(set(lst))

    # Reverse edges: callers_1hop[callee] = sorted list of callers (capped)
    callers_1hop: dict[str, list[str]] = {}
    for caller, callees in method_calls.items():
        for callee in callees:
            callers_1hop.setdefault(callee, []).append(caller)
    for k, lst in callers_1hop.items():
        # Dedup + cap
        uniq = sorted(set(lst))[:callers_cap]
        callers_1hop[k] = uniq

    log.info("phase2: walked=%d failed=%d, %d methods with globals, "
             "%d methods with callers, %d methods with thread asserts",
             tus_walked, tus_failed, len(method_globals),
             len(callers_1hop), len(method_thread_asserts))

    return Phase2Result(
        method_globals=method_globals,
        method_calls=method_calls,
        callers_1hop=callers_1hop,
        method_thread_asserts=method_thread_asserts,
        method_decl_loc=method_decl_loc,
        tus_walked=tus_walked,
        tus_failed=tus_failed,
    )


def merge_phase2_into_facts(facts_path: Path, p2: Phase2Result) -> dict:
    """Update method_facts.json with Phase 2 fields. Returns the new payload."""
    import json as _json
    payload = _json.loads(facts_path.read_text())
    methods = payload.setdefault("methods", {})

    # Helper: get-or-create empty FactSheet for a method
    def _get_or_create(qname: str) -> dict:
        if qname in methods:
            return methods[qname]
        from .store import _empty_facts
        m = _empty_facts(qname)
        methods[qname] = m
        return m

    # Apply globals + decl_loc
    for qname, globals_list in p2.method_globals.items():
        m = _get_or_create(qname)
        m["mutable_globals_touched"] = [
            {**g, "lock_in_scope": None, "thread_local": False, "mutated_via": []}
            for g in globals_list
        ]
        if qname in p2.method_decl_loc:
            f, ln = p2.method_decl_loc[qname]
            m["decl_file"] = f
            m["decl_line"] = ln

    # Apply callers_1hop
    for qname, callers in p2.callers_1hop.items():
        m = _get_or_create(qname)
        m["callers_1hop"] = [{"caller": c, "file": None, "line": None} for c in callers]

    # Apply thread_protections
    for qname, asserts in p2.method_thread_asserts.items():
        m = _get_or_create(qname)
        tp = m["thread_protections"]
        tp["self_asserts_main_thread"] = any(
            a in ("assertIsMainThread", "isMainThread", "RunLoop::isMain") for a in asserts
        )
        tp["self_holds_lock"] = any(
            a in ("Locker", "std::lock_guard", "std::unique_lock", "holdLock")
            for a in asserts
        )

    payload["phase2_meta"] = {
        "tus_walked": p2.tus_walked,
        "tus_failed": p2.tus_failed,
    }

    facts_path.write_text(_json.dumps(payload, indent=1))
    return payload
