"""Compilation database loader with bootstrap detection.

Locates ``compile_commands.json`` for the target repo and emits an actionable
error if missing.

Bootstrap matrix:
  • WebKit GTK/WPE/PlayStation (CMake + Ninja/Make):
      DEVELOPER_MODE=ON auto-enables CDB. ``build-webkit --gtk`` is enough.
  • Generic CMake project:
      Configure with ``-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`` or env
      ``CMAKE_EXPORT_COMPILE_COMMANDS=1``.
  • WebKit Cocoa (Xcode generator) / arbitrary build:
      Wrap with Bear: ``bear -- build-webkit --release``.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


_PORT_ALIASES = {
    "gtk": "GTK",
    "wpe": "WPE",
    "playstation": "PlayStation",
    "cocoa": "Cocoa",
    "mac": "Cocoa",
    "ios": "Cocoa",
}


class OraclesNotBootstrapped(RuntimeError):
    """Raised when no compile_commands.json can be located."""


@dataclass(frozen=True)
class CDBLocation:
    path: Path
    port: Optional[str]
    config: Optional[str]


def _candidate_paths(target_repo: Path, port: Optional[str]) -> Iterable[CDBLocation]:
    """Yield candidate CDB locations in preference order."""
    yield CDBLocation(target_repo / "compile_commands.json", port=None, config=None)

    norm = _PORT_ALIASES.get(port.lower(), port) if port else None
    ports = [norm] if norm else ["GTK", "WPE", "PlayStation", "Cocoa"]
    configs = ["Release", "Debug"]

    for p in ports:
        for cfg in configs:
            yield CDBLocation(
                target_repo / "WebKitBuild" / p / cfg / "compile_commands.json",
                port=p, config=cfg,
            )

    for sub in ("build", "out", "build/Release", "out/Default"):
        yield CDBLocation(target_repo / sub / "compile_commands.json", port=None, config=None)


def find_compile_commands(target_repo: Path, port: Optional[str] = None) -> CDBLocation:
    """Locate ``compile_commands.json`` or raise ``OraclesNotBootstrapped``."""
    target_repo = Path(target_repo).resolve()
    if not target_repo.is_dir():
        raise OraclesNotBootstrapped(f"target_repo does not exist: {target_repo}")

    tried: list[Path] = []
    for cand in _candidate_paths(target_repo, port):
        tried.append(cand.path)
        if cand.path.is_file():
            return cand

    paths_str = "\n  ".join(str(p) for p in tried)
    raise OraclesNotBootstrapped(textwrap.dedent(f"""
        No compile_commands.json found under {target_repo}.

        Searched:
          {paths_str}

        Bootstrap depends on the build system:
          • CMake (Makefile / Ninja generator):
              Re-configure with: -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
              Or env: export CMAKE_EXPORT_COMPILE_COMMANDS=1

          • WebKit GTK / WPE / PlayStation:
              build-webkit --<port>     (DEVELOPER_MODE auto-enables CDB)

          • WebKit Cocoa (Xcode generator):
              bear -- build-webkit --release      (brew install bear)

          • Other / arbitrary build:
              bear -- <your-build-command>        (apt install bear)
    """).strip())


def load_compilation_database(cdb_dir: Path):
    """Open the CDB via libclang. Returns a ``CompilationDatabase`` instance."""
    import clang.cindex
    return clang.cindex.CompilationDatabase.fromDirectory(str(cdb_dir))


def iter_translation_units(cdb_location: CDBLocation, include_exts: tuple[str, ...] = (".cpp", ".cc", ".mm")) -> Iterable[dict]:
    """Iterate over CDB entries, yielding ``{file, command, directory}`` dicts.

    Filters to the given extensions and de-duplicates by file path (CMake unified
    builds can list the same TU multiple times).
    """
    import json as _json
    raw = _json.loads(cdb_location.path.read_text())
    seen: set[str] = set()
    for entry in raw:
        f = entry.get("file", "")
        if not f.endswith(include_exts):
            continue
        if f in seen:
            continue
        seen.add(f)
        yield entry
