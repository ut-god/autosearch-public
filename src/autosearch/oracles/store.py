"""MethodFacts builder + on-disk store.

Phase 1: only ``idl_exposure`` populated.
Phase 2 will fill in the other fields via libclang.

On-disk format: a single ``method_facts.json`` keyed by qualified method name.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .cdb import OraclesNotBootstrapped, find_compile_commands  # re-export
from .idl_parser import build_idl_exposure_index

ORACLE_SCHEMA_VERSION = 1


def _empty_facts(method: str) -> dict:
    return {
        "method": method,
        "decl_file": None,
        "decl_line": None,
        "idl_exposure": {
            "exposed_to_window": False,
            "exposed_to_worker": False,
            "via_idls": [],
        },
        "mutable_globals_touched": [],
        "callers_1hop": [],
        "thread_protections": {
            "self_asserts_main_thread": None,  # null = unknown (libclang not run yet)
            "self_holds_lock": None,
            "callers_asserting_main_thread": [],
            "callers_NOT_asserting": [],
        },
    }


@dataclass
class MethodFactsStore:
    """Loads and queries the on-disk ``method_facts.json``."""
    facts: dict[str, dict]
    schema_version: int
    target_sha: Optional[str]
    cdb_path: Optional[str]

    @classmethod
    def from_file(cls, path) -> "MethodFactsStore":
        path = Path(path)
        data = json.loads(path.read_text())
        return cls(
            facts=data.get("methods", {}),
            schema_version=data.get("schema_version", 0),
            target_sha=data.get("target_sha"),
            cdb_path=data.get("cdb_path"),
        )

    def lookup(self, method: str) -> dict:
        """Return MethodFacts for ``method``, or an empty FactSheet if unknown."""
        if method in self.facts:
            return self.facts[method]
        return _empty_facts(method)

    def known_method_count(self) -> int:
        return len(self.facts)


def build_idl_only_facts(
    target_repo: Path,
    out_path: Path,
    target_sha: Optional[str] = None,
    cdb_path: Optional[str] = None,
) -> dict:
    """Phase 1: walk IDLs, write ``method_facts.json`` with only ``idl_exposure`` populated."""
    webcore = target_repo / "Source" / "WebCore"
    if not webcore.is_dir():
        raise OraclesNotBootstrapped(
            f"Expected {webcore} (Source/WebCore) under target_repo {target_repo}"
        )

    idx = build_idl_exposure_index(webcore)

    facts: dict[str, dict] = {}
    for qualified, rows in idx.by_qualified.items():
        f = _empty_facts(qualified)
        f["idl_exposure"] = {
            "exposed_to_window": any(r["exposed_to_window"] for r in rows),
            "exposed_to_worker": any(r["exposed_to_worker"] for r in rows),
            "via_idls": [
                {"interface": r["interface"], "method": r["method"],
                 "exposed": ",".join(r["exposed"]), "idl_path": r["idl_path"]}
                for r in rows
            ],
        }
        facts[qualified] = f

    payload = {
        "schema_version": ORACLE_SCHEMA_VERSION,
        "target_sha": target_sha,
        "cdb_path": cdb_path,
        "methods": facts,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=1))
    return payload
