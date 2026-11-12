"""Discovery and rendering of the autosearch skill catalog.

A skill is a directory with a ``SKILL.md`` file containing YAML-style
frontmatter (``name`` and ``description``) followed by markdown body.
The loader walks ``autosearch.skills``, parses each frontmatter, and
returns a structured list the auditor prompt embeds via ``{{SKILLS_CATALOG}}``.

We deliberately use a 5-line YAML parser instead of pulling in PyYAML —
the frontmatter we accept is intentionally minimal (two keys, no nested
structures, no anchors), and adding a runtime dep just for that would
be wasteful.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterator, Optional

_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL,
)
# Matches `key: value` lines where value continues until end of line.
# Quoted values are stripped of one layer of surrounding double-quotes
# (multi-line YAML block scalars are not supported — keep descriptions
# to a single paragraph, wrapped or unwrapped).
_FM_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$")


@dataclass
class SkillRecord:
    """One entry in the skill catalog.

    ``name`` and ``description`` come from frontmatter. ``skill_md_path``
    is an absolute filesystem path the auditor can pass to its ``view``
    tool to read the full playbook on demand.
    """
    name: str
    description: str
    skill_md_path: Path

    @property
    def directory(self) -> Path:
        return self.skill_md_path.parent


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Extract a flat ``{key: value}`` dict from leading YAML frontmatter.

    Returns an empty dict when no frontmatter is present so a malformed
    skill file degrades to "skipped" rather than crashing the auditor
    cohort. Values that look like ``"quoted"`` have one pair of double
    quotes stripped (handy for descriptions starting with leading
    whitespace).
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    for raw_line in m.group("body").splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        lm = _FM_LINE_RE.match(line)
        if not lm:
            continue
        key, value = lm.group(1), lm.group(2)
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        out[key] = value
    return out


def list_skill_dirs() -> Optional[list[str]]:
    """Return a list of parent directories the SDK should scan for skills.

    Designed for ``CopilotClient.create_session(skill_directories=...)``:
    each entry is a *parent* directory containing one-level subdirectories
    that each hold a ``SKILL.md`` file. autosearch ships exactly one such
    parent (``.github/skills/`` at the repo root); the function returns
    ``[<that path>]`` when discovered, ``None`` when no in-tree skills
    exist (e.g. after a wheel install with no skills bundled).

    Returning ``None`` rather than ``[]`` lets callers pass the result
    straight into the SDK's ``skill_directories`` kwarg (which is
    documented as ``list[str] | None``) and signals "do nothing" instead
    of "explicitly empty list" — semantically identical here, but
    cleaner intent.
    """
    root = _repo_root_skills_dir()
    if root is None:
        return None
    return [str(root)]


def _repo_root_skills_dir() -> Optional[Path]:
    """Locate ``.github/skills/`` relative to this checkout, if any.

    Source-of-truth for autosearch's bundled skills lives at the repo
    root (``.github/skills/``) — the open-standard project-level location
    per the agent-skills spec. When developing in a working tree, walk
    up from this file's location until we hit a ``.github`` directory
    and its ``skills`` subdir.

    Returns ``None`` when no in-tree ``.github/skills/`` exists (e.g.
    after a wheel install — see :func:`_iter_skill_files` which falls
    back to ``importlib.resources`` package data in that case).
    """
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / ".github" / "skills"
        if candidate.is_dir():
            return candidate
    return None


def _iter_skill_files() -> Iterator[Path]:
    """Yield every ``SKILL.md`` packaged with autosearch.

    Discovery order:

    1. ``.github/skills/`` walked up from this file (developer working
       tree — source-of-truth).
    2. Package data under ``autosearch.skills`` (installed wheel — only
       relevant if a future packaging step copies skills back into the
       package, currently not done).

    The two-level layout (``<root>/<skill-name>/SKILL.md``) is the only
    one supported — keeps the discovery loop O(n_skills) and predictable.
    """
    root = _repo_root_skills_dir()
    if root is not None:
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            skill_md = entry / "SKILL.md"
            if skill_md.is_file():
                yield skill_md
        return

    # Wheel-install fallback: look for skills inside the installed
    # package (this only fires if pyproject.toml ships skills as
    # package_data, which it currently doesn't — leaving the hook
    # in place for forward compatibility).
    try:
        pkg = resources.files("autosearch.skills")
    except (ModuleNotFoundError, FileNotFoundError):
        return
    for entry in pkg.iterdir():
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if not skill_md.is_file():
            continue
        with resources.as_file(skill_md) as p:
            yield Path(p)


def list_skills() -> list[SkillRecord]:
    """Return all packaged skills sorted by name. Skips malformed entries.

    A SKILL.md is valid if its frontmatter has both ``name`` and
    ``description``. Missing either → silently skipped (logged via the
    catch-all so a typo in one skill doesn't break the cohort dispatch).
    """
    out: list[SkillRecord] = []
    for path in _iter_skill_files():
        try:
            fm = _parse_frontmatter(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        name = fm.get("name", "").strip()
        desc = fm.get("description", "").strip()
        if not name or not desc:
            continue
        out.append(SkillRecord(name=name, description=desc, skill_md_path=path))
    out.sort(key=lambda s: s.name)
    return out


def render_catalog(skills: Optional[list[SkillRecord]] = None) -> str:
    """Render the catalog as a markdown block embedded in agent prompts.

    Layout is intentionally compact — every byte counts in prompt
    overhead. The auditor sees one block per skill with name, description,
    and an absolute filesystem path it can pass to its ``view`` tool.
    """
    if skills is None:
        skills = list_skills()
    if not skills:
        return "(no skills available)"
    lines: list[str] = []
    for s in skills:
        lines.append(f"- {s.name}")
        lines.append(f"    {s.description}")
        lines.append(f"    Read: {s.skill_md_path}")
        lines.append("")
    return "\n".join(lines).rstrip()
