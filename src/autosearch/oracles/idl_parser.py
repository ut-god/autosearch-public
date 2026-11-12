"""IDL exposure parser + IDL→C++ stitcher.

Parses every ``*.idl`` under ``Source/WebCore/`` for the ``Exposed=`` attribute
and the implementation class. Emits the ``idl_exposure`` portion of MethodFacts.

Phase 1 deliverable. No clang dependency; pure text parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


_INTERFACE_BLOCK_RE = re.compile(
    r"(?:\[(?P<attrs>[^\]]*)\]\s*\n?\s*)?"
    r"(?:partial\s+)?(?:interface\s+mixin|interface)\s+(?P<iface>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*[A-Za-z_][A-Za-z0-9_]*\s*)?"
    r"\{(?P<body>[^}]*)\}",
    re.DOTALL,
)
_INCLUDES_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+includes\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.MULTILINE,
)
_EXPOSED_RE = re.compile(r"Exposed\s*=\s*(?:\(([^)]*)\)|([A-Za-z_][A-Za-z0-9_]*))")
_IMPL_RE = re.compile(r"ImplementedAs\s*=\s*([A-Za-z_][A-Za-z0-9_]*)")
_METHOD_RE = re.compile(
    r"(?:^|\n)\s*"
    r"(?:\[[^\]]*\]\s*)?"
    r"(?:static\s+)?"
    r"(?:Promise<[^>]*>|sequence<[^>]*>|[A-Za-z_][\w<>?, ]*?)"
    r"\s+([a-z][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

# Worker-bearing global names per Web IDL. Anything matching means the method
# is reachable from a non-main thread.
_WORKER_GLOBALS = {
    "Worker", "DedicatedWorker", "SharedWorker", "ServiceWorker",
    "AudioWorklet", "PaintWorklet", "LayoutWorklet", "AnimationWorklet",
}


@dataclass
class IDLInterface:
    name: str
    impl_class: str  # ImplementedAs or default = name
    exposed: list[str]
    methods: list[str]
    idl_path: str

    @property
    def exposed_to_window(self) -> bool:
        return "Window" in self.exposed

    @property
    def exposed_to_worker(self) -> bool:
        return any(g in _WORKER_GLOBALS for g in self.exposed)


def _parse_exposed(attrs: str) -> list[str]:
    m = _EXPOSED_RE.search(attrs)
    if not m:
        return []
    grp = m.group(1) or m.group(2) or ""
    return [g.strip() for g in grp.split(",") if g.strip()]


def _parse_impl(attrs: str, default: str) -> str:
    m = _IMPL_RE.search(attrs)
    return m.group(1) if m else default


def parse_idl_file(path: Path) -> tuple[list[IDLInterface], list[tuple[str, str]]]:
    """Parse one .idl file.

    Returns ``(interfaces, includes)`` where ``includes`` is a list of
    ``(target_interface, mixin_name)`` pairs from ``X includes Y;`` statements.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []

    out: list[IDLInterface] = []
    for m in _INTERFACE_BLOCK_RE.finditer(text):
        attrs = m.group("attrs") or ""
        iface = m.group("iface")
        body = m.group("body") or ""
        exposed = _parse_exposed(attrs)
        impl = _parse_impl(attrs, iface)
        methods = sorted(set(_METHOD_RE.findall(body)))
        out.append(IDLInterface(
            name=iface, impl_class=impl, exposed=exposed,
            methods=methods, idl_path=str(path),
        ))

    includes = [(m.group(1), m.group(2)) for m in _INCLUDES_RE.finditer(text)]
    return out, includes


def walk_idls(webcore_root: Path) -> tuple[list[IDLInterface], list[tuple[str, str]]]:
    """Walk every .idl under ``Source/WebCore/`` recursively.

    Returns ``(all_interfaces, all_includes)``.
    """
    all_ifaces: list[IDLInterface] = []
    all_includes: list[tuple[str, str]] = []
    for p in webcore_root.rglob("*.idl"):
        ifaces, includes = parse_idl_file(p)
        all_ifaces.extend(ifaces)
        all_includes.extend(includes)
    return all_ifaces, all_includes


def _merge_partials_and_includes(
    interfaces: list[IDLInterface],
    includes: list[tuple[str, str]],
) -> list[IDLInterface]:
    """Merge ``X includes Y;`` mixins into X, and partial interfaces into the main.

    Methods from Y are appended to X's method list. X's ``exposed`` /
    ``impl_class`` are preserved (mixins inherit the includer's exposure
    surface per Web IDL).
    """
    # Group all interface declarations by name (handles partial interfaces).
    by_name: dict[str, IDLInterface] = {}
    for i in interfaces:
        if i.name in by_name:
            existing = by_name[i.name]
            merged_methods = sorted(set(existing.methods) | set(i.methods))
            merged_exposed = sorted(set(existing.exposed) | set(i.exposed)) \
                             if (existing.exposed or i.exposed) else []
            by_name[i.name] = IDLInterface(
                name=i.name,
                impl_class=existing.impl_class if existing.impl_class != existing.name else i.impl_class,
                exposed=merged_exposed,
                methods=merged_methods,
                idl_path=existing.idl_path,
            )
        else:
            by_name[i.name] = i

    # Apply includes: target inherits mixin's methods.
    for target_name, mixin_name in includes:
        target = by_name.get(target_name)
        mixin = by_name.get(mixin_name)
        if not target or not mixin:
            continue
        merged_methods = sorted(set(target.methods) | set(mixin.methods))
        by_name[target_name] = IDLInterface(
            name=target.name,
            impl_class=target.impl_class,
            exposed=target.exposed,
            methods=merged_methods,
            idl_path=target.idl_path,
        )

    return list(by_name.values())


@dataclass
class IDLExposureIndex:
    """Maps fully-qualified method name → list of IDL exposure facts.

    The "method" key is best-effort: ``WebCore::<impl_class>::<method_name>``.
    Auditors should query by either the IDL interface name or the C++ impl name;
    both lead to the same row.
    """
    by_qualified: dict[str, list[dict]] = field(default_factory=dict)

    def add_interface(self, iface: IDLInterface) -> None:
        for m in iface.methods:
            keys = {f"WebCore::{iface.impl_class}::{m}", f"WebCore::{iface.name}::{m}"}
            row = {
                "interface": iface.name,
                "impl_class": iface.impl_class,
                "method": m,
                "idl_path": iface.idl_path,
                "exposed": iface.exposed,
                "exposed_to_window": iface.exposed_to_window,
                "exposed_to_worker": iface.exposed_to_worker,
            }
            for key in keys:
                rows = self.by_qualified.setdefault(key, [])
                # Dedup by (interface, method) so impl_class==name doesn't double-add.
                if not any(r["interface"] == row["interface"] and r["method"] == row["method"] for r in rows):
                    rows.append(row)

    def lookup(self, qualified_method: str) -> dict:
        rows = self.by_qualified.get(qualified_method, [])
        if not rows:
            return {
                "exposed_to_window": False,
                "exposed_to_worker": False,
                "via_idls": [],
            }
        return {
            "exposed_to_window": any(r["exposed_to_window"] for r in rows),
            "exposed_to_worker": any(r["exposed_to_worker"] for r in rows),
            "via_idls": [
                {"interface": r["interface"], "method": r["method"],
                 "exposed": ",".join(r["exposed"]), "idl_path": r["idl_path"]}
                for r in rows
            ],
        }


def build_idl_exposure_index(webcore_root: Path) -> IDLExposureIndex:
    """Walk all IDLs once, merge partials + includes, build the exposure lookup."""
    interfaces, includes = walk_idls(webcore_root)
    merged = _merge_partials_and_includes(interfaces, includes)
    idx = IDLExposureIndex()
    for iface in merged:
        # Skip mixins that were never `includes`d (no exposure of their own).
        if not iface.exposed:
            continue
        idx.add_interface(iface)
    return idx
