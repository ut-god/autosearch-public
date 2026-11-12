"""Workspace config + targets.md / catalog.md / mitigations.md I/O."""
from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..targets import split_qualified_target

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore

log = logging.getLogger(__name__)

# Minimum overlay length (in lines) to bother trimming.
_MIN_TRIM_LINES = 50

# Section name keywords that are always included regardless of target.
_ALWAYS_INCLUDE_KEYWORDS = frozenset({
    "preamble",
    "cross-cutting",
    "integral typedef",
    "root entry",
    "trust class",
    "namespace constant",
    "pure-enum",
})


def _parse_sections(text: str) -> list[tuple[str, str]]:
    """Split overlay text on ``=== Section Name ===`` markers.

    Returns a list of (name, body) tuples. Text before the first marker
    is returned as ("preamble", ...).
    """
    pattern = re.compile(r"^===\s*(.+?)\s*===$", re.MULTILINE)
    sections: list[tuple[str, str]] = []
    last_end = 0
    last_name = "preamble"

    for m in pattern.finditer(text):
        body = text[last_end:m.start()].strip()
        if body:
            sections.append((last_name, body))
        last_name = m.group(1)
        last_end = m.end()

    # Trailing body after the last marker
    tail = text[last_end:].strip()
    if tail:
        sections.append((last_name, tail))

    return sections


def _trim_attacker_surface(
    full_surface: str,
    target_class: str,
    source_path: str,
) -> str:
    """Extract overlay sections relevant to *target_class* / *source_path*.

    Matching rules (any hit includes the section):
      1. Section name contains an always-include keyword.
      2. The short class name (after last `::`) appears in the section name.
      3. Any meaningful token from *source_path* appears in the section name.

    Returns the full overlay unchanged when:
      - The overlay has fewer than ``_MIN_TRIM_LINES`` lines.
      - No ``===`` markers are found.
      - No sections match (safety fallback).
    """
    if full_surface.count("\n") < _MIN_TRIM_LINES:
        return full_surface

    sections = _parse_sections(full_surface)
    if len(sections) <= 1:
        return full_surface

    # Derive match tokens from target context
    class_short = (target_class.split("::")[-1] if target_class else "").lower()
    path_tokens: list[str] = []
    if source_path:
        for part in re.split(r"[/\\.]", source_path.lower()):
            # Skip very short or generic path components
            if len(part) > 3 and part not in {"source", "webcore", "platform", "modules", "graphics"}:
                path_tokens.append(part)

    matched: list[tuple[str, str]] = []
    for name, body in sections:
        name_lower = name.lower()

        # Rule 1: always-include
        if any(kw in name_lower for kw in _ALWAYS_INCLUDE_KEYWORDS):
            matched.append((name, body))
            continue

        # Rule 2: class name match
        if class_short and class_short in name_lower:
            matched.append((name, body))
            continue

        # Rule 3: source path token match
        if any(tok in name_lower for tok in path_tokens):
            matched.append((name, body))
            continue

    if not matched:
        log.debug("overlay trim: no sections matched for %s / %s — returning full overlay",
                  target_class, source_path)
        return full_surface

    trimmed = "\n\n".join(
        body if name == "preamble" else f"=== {name} ===\n{body}"
        for name, body in matched
    )
    log.debug("overlay trimmed: %d → %d chars for %s",
              len(full_surface), len(trimmed), target_class)
    return trimmed


@dataclass
class WorkspaceConfig:
    """Loaded from `<workspace>/config.toml`."""
    target_repo: Path
    target_branch: str = "main"
    # Pool of distinct vendor models. Order matters: we pair across the
    # pool so each method is audited by N distinct vendors.
    cohort_models: list[str] = field(default_factory=lambda: ["claude-opus-4.7", "gpt-5.4"])
    challenger_models: list[str] = field(default_factory=lambda: ["claude-opus-4.7", "gpt-5.4"])
    refinement_model: str = "claude-opus-4.7"
    cycle_timeout_seconds: int = 4500
    agent_timeout_seconds: int = 1500
    # Hybrid cohort: cohort_methods × cohort_models_per_method = total auditor runs.
    # Each method is audited by `cohort_models_per_method` distinct models from
    # `cohort_models` (preferring different vendors for cross-vendor quorum).
    cohort_methods: int = 8
    cohort_models_per_method: int = 2
    chain_slot_enabled: bool = True
    pre_commit_challenge_enabled: bool = True

    # Legacy fields from the subprocess-based dispatcher. Retained so
    # older config.toml files load without error, but ignored by the
    # SDK-based dispatcher (see src/autosearch/dispatch.py). Safe to
    # delete from your config.toml.
    dispatch_command: str = "copilot"
    dispatch_args: list[str] = field(default_factory=lambda: ["--yolo", "-p"])

    # ---- prompt overlay: workspace-specific framing of the trust boundary ----
    # These three strings are substituted into ALL agent prompts as
    # {{ATTACKER_SURFACE}} / {{SCOPE_INCLUDES}} / {{EXTRA_OUT_OF_SCOPE}}.
    # Defaults are generic so the bundled prompts work for ANY target without
    # extra config. Templates override with target-specific framing
    # (e.g. WebKit sets ATTACKER_SURFACE to renderer-reachable JS/HTML/IDL).
    attacker_surface: str = "external attacker-controlled input"
    scope_includes: str = ""
    extra_out_of_scope: str = ""

    @property
    def cohort_size(self) -> int:
        return self.cohort_methods * self.cohort_models_per_method

    def overlay_ctx(self) -> dict[str, str]:
        """Render-context dict containing the workspace-specific
        prompt-overlay placeholder substitutions."""
        return {
            "ATTACKER_SURFACE": self.attacker_surface,
            "SCOPE_INCLUDES": self.scope_includes,
            "EXTRA_OUT_OF_SCOPE": self.extra_out_of_scope,
        }

    def overlay_ctx_for_target(
        self, target_class: str, source_path: str = ""
    ) -> dict[str, str]:
        """Like :meth:`overlay_ctx` but trims ``ATTACKER_SURFACE`` to only
        the sections relevant to *target_class* / *source_path*."""
        return {
            "ATTACKER_SURFACE": _trim_attacker_surface(
                self.attacker_surface, target_class, source_path,
            ),
            "SCOPE_INCLUDES": self.scope_includes,
            "EXTRA_OUT_OF_SCOPE": self.extra_out_of_scope,
        }

    @classmethod
    def load(cls, workspace: Path) -> "WorkspaceConfig":
        cfg_path = workspace / "config.toml"
        if not cfg_path.exists():
            raise FileNotFoundError(f"missing workspace config: {cfg_path}")
        with cfg_path.open("rb") as f:
            data = tomllib.load(f)
        target_repo = Path(data["target_repo"]).expanduser()
        # Backward compat: if old `cohort_size` exists and `cohort_methods` doesn't,
        # interpret it as cohort_methods × 1 (per-slot, single-vendor).
        cohort_methods = data.get("cohort_methods")
        cohort_models_per_method = data.get("cohort_models_per_method")
        if cohort_methods is None and cohort_models_per_method is None and "cohort_size" in data:
            cohort_methods = int(data["cohort_size"])
            cohort_models_per_method = 1
        cohort_methods = int(cohort_methods if cohort_methods is not None else 8)
        cohort_models_per_method = int(cohort_models_per_method if cohort_models_per_method is not None else 2)
        # Dedup cohort_models while preserving order — cohort_models is a vendor pool.
        raw_cohort = data.get("cohort_models", ["claude-opus-4.7", "gpt-5.4"])
        seen = set()
        cohort_models = []
        for m in raw_cohort:
            if m not in seen:
                cohort_models.append(m)
                seen.add(m)
        # Prompt overlay: accept either a flat field or a [prompt_overlay] subtable.
        overlay = data.get("prompt_overlay", {})
        attacker_surface = data.get("attacker_surface",
                                     overlay.get("attacker_surface", "external attacker-controlled input"))
        scope_includes = data.get("scope_includes",
                                    overlay.get("scope_includes", ""))
        extra_out_of_scope = data.get("extra_out_of_scope",
                                       overlay.get("extra_out_of_scope", ""))
        return cls(
            target_repo=target_repo,
            target_branch=data.get("target_branch", "main"),
            cohort_models=cohort_models,
            challenger_models=data.get("challenger_models", ["claude-opus-4.7", "gpt-5.4"]),
            refinement_model=data.get("refinement_model", "claude-opus-4.7"),
            cycle_timeout_seconds=int(data.get("cycle_timeout_seconds", 4500)),
            agent_timeout_seconds=int(data.get("agent_timeout_seconds", 1500)),
            cohort_methods=cohort_methods,
            cohort_models_per_method=cohort_models_per_method,
            dispatch_command=data.get("dispatch_command", "copilot"),
            dispatch_args=list(data.get("dispatch_args", ["--yolo", "-p"])),
            chain_slot_enabled=bool(data.get("chain_slot_enabled", True)),
            pre_commit_challenge_enabled=bool(data.get("pre_commit_challenge_enabled", True)),
            attacker_surface=attacker_surface,
            scope_includes=scope_includes,
            extra_out_of_scope=extra_out_of_scope,
        )


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------- targets.md parser ----------

_TARGET_LINE = re.compile(
    r"^(?P<qualified>[A-Za-z_][^#]+?)"
    r"\s+#\s+(?P<bug_class>(?:n/a|[A-Z_][A-Z_|\s]*?))\s*(?:—|--)\s*(?P<reason>.+?)\s*$"
)
_CAMPAIGN_HEADING = re.compile(r"^##\s+Campaign\s+(?P<num>\d+)\s*[—-]\s*(?P<name>.+?)\s*$")
_SUB_HEADING = re.compile(r"^###\s+(?P<sub>.+?)\s*(?:\((?P<path>[^)]+)\))?\s*$")


def parse_targets(md: str) -> list[dict]:
    """Parse a targets.md file into a list of target dicts."""
    rows: list[dict] = []
    campaign = ""
    sub_area = ""
    source_path = ""
    for line in md.splitlines():
        m_camp = _CAMPAIGN_HEADING.match(line)
        if m_camp:
            campaign = f"{m_camp['num']} {m_camp['name'].strip()}"
            continue
        m_sub = _SUB_HEADING.match(line)
        if m_sub:
            sub_area = m_sub["sub"].strip()
            source_path = (m_sub["path"] or "").strip()
            continue
        m = _TARGET_LINE.match(line)
        if not m:
            continue
        qualified = m["qualified"].strip()
        split = split_qualified_target(qualified)
        if not split:
            continue
        cls, method = split
        bug_class = m["bug_class"].strip()
        rows.append(
            {
                "target_class": cls,
                "target_method": method,
                "bug_class_hint": bug_class,
                "reason": m["reason"].strip(),
                "campaign": campaign,
                "sub_area": sub_area,
                "source_path": source_path,
            }
        )
    return rows


def append_targets_section(targets_md_path: Path, section_md: str,
                           campaign_heading: str) -> None:
    """Append a generated section to targets.md under a campaign heading.

    If the campaign heading is missing, append it.
    """
    existing = read_text(targets_md_path, default="")
    if campaign_heading not in existing:
        existing = existing.rstrip() + f"\n\n## {campaign_heading}\n"
    existing = existing.rstrip() + "\n\n" + section_md.rstrip() + "\n"
    write_text(targets_md_path, existing)
