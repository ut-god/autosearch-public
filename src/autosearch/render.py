"""Placeholder substitution for agent prompts.

Loads `agents/<name>.md` from the package, substitutes `{{TOKEN}}`
mustache-style placeholders against a context dict, returns the
rendered prompt + the prompt template hash (for prompt_versions table).
"""
from __future__ import annotations

import hashlib
import re
from importlib import resources
from pathlib import Path
from typing import Mapping

_PLACEHOLDER = re.compile(r"\{\{([A-Z_][A-Z0-9_]*)\}\}")


def _agent_template_text(agent_name: str) -> str:
    """Read a packaged agent prompt by name (e.g. 'auditor')."""
    fname = f"{agent_name}.md"
    return resources.files("autosearch.agents").joinpath(fname).read_text()


def _taxonomy_text() -> str:
    """Read the canonical bug-class taxonomy from agents/_taxonomy.md."""
    return resources.files("autosearch.agents").joinpath("_taxonomy.md").read_text()


def template_hash(agent_name: str) -> str:
    """SHA-256 of the prompt template + taxonomy + skill catalog +
    custom-agent config for ``agent_name``.

    Includes:
      - The .md template text (the bulk of the prompt).
      - The bug-class taxonomy (auto-injected into the template).
      - The skill catalog (which playbooks the Copilot CLI knows about
        — only add/remove/rename matters; skill bodies are NOT hashed).
      - The custom-agent config dict for this ``agent_name`` (or a
        sentinel if the role isn't registered as a custom agent).
        This catches changes to the identity-line ``prompt`` field,
        the per-agent ``skills`` attachment, the ``display_name`` /
        ``description``, and the ``infer`` flag.

    Effect: if any of the above changes, ``prompt_versions`` records
    a new version. Downstream queries that filter by prompt_version_id
    can rely on cohort behavior being constant within a version.
    """
    h = hashlib.sha256()
    h.update(_agent_template_text(agent_name).encode("utf-8"))
    h.update(b"\x00TAXONOMY\x00")
    h.update(_taxonomy_text().encode("utf-8"))
    h.update(b"\x00SKILLS_CATALOG\x00")
    h.update(_skills_catalog_text().encode("utf-8"))
    h.update(b"\x00AGENT_CONFIG\x00")
    h.update(_agent_config_text(agent_name).encode("utf-8"))
    return h.hexdigest()


def _agent_config_text(agent_name: str) -> str:
    """Return a deterministic serialization of the SDK custom-agent
    config for ``agent_name`` — used by ``template_hash``.

    Lazily imports ``dispatch`` to avoid a hard dependency on the SDK
    at module-load time (CLI commands that never dispatch agents
    don't pay the import cost).

    Returns ``"(default)"`` when ``agent_name`` is not registered as a
    custom agent — semantically equivalent to "the SDK's default agent
    runs, no custom-agent config in effect".
    """
    try:
        from . import dispatch
    except Exception:  # noqa: BLE001
        return "(import-failed)"

    if agent_name not in dispatch._KNOWN_AGENT_NAMES:
        return "(default)"

    # Build the agent_configs list with the same skill names the
    # dispatcher would resolve at runtime, so the hash matches what
    # actually lands in create_session.
    try:
        from .skills import list_skills
        skill_names = [s.name for s in list_skills()] or None
    except Exception:  # noqa: BLE001
        skill_names = None

    configs = dispatch._build_agent_configs(skill_names)
    matching = next((c for c in configs if c["name"] == agent_name), None)
    if matching is None:
        return "(default)"

    # Sorted-key JSON dumps give a stable canonical form across runs.
    import json
    return json.dumps(matching, sort_keys=True, default=str)


def _skills_catalog_text() -> str:
    """Render the live skill catalog as a markdown block.

    No longer auto-injected into prompts (the Copilot CLI handles skill
    discovery natively from ``~/.copilot/skills/``). Retained because
    ``template_hash()`` includes it: when skills are added / removed /
    renamed, ``prompt_versions`` should record a new version even though
    the agent template text itself is unchanged.

    Lazily imported so that ``render`` doesn't pull in ``skills`` until
    the first prompt actually needs the hash — keeps cold-start time
    fast for CLI commands that don't dispatch agents (``findings list``,
    ``agent show``, etc.).
    """
    from .skills import render_catalog
    return render_catalog()


def render_prompt(agent_name: str, ctx: Mapping[str, str]) -> tuple[str, str]:
    """Render prompt for `agent_name` against `ctx`. Returns (prompt, template_text).

    Unknown placeholders left in the template are replaced with
    `<<<MISSING:TOKEN>>>` so they show up in the rendered prompt for
    debuggability rather than silently being dropped.

    Auto-injects `{{TAXONOMY}}` from agents/_taxonomy.md unless the caller
    overrode it in `ctx`. This centralizes the bug-class enum so adding /
    renaming a class is a single-file edit.

    Note: ``{{SKILLS_CATALOG}}`` is NO LONGER auto-injected. The Copilot
    CLI's native skill mechanism (skills installed at ``~/.copilot/skills/``)
    auto-injects an ``<available_skills>`` block into every session's
    system message and instructs the agent that calling the ``skill``
    tool is a BLOCKING REQUIREMENT when a skill matches. We previously
    embedded a catalog block in agent prompts as a workaround when our
    skills lived in the wrong directory; that workaround is now gone.
    Callers may still pass ``SKILLS_CATALOG`` explicitly if they want
    to force a specific listing into a prompt (e.g. for tests).
    """
    template = _agent_template_text(agent_name)

    # Build effective context: caller's ctx wins, but we inject TAXONOMY
    # by default so every agent sees the same canonical bug-class list.
    effective: dict[str, object] = {"TAXONOMY": _taxonomy_text()}
    effective.update(ctx)

    def sub(m: re.Match) -> str:
        token = m.group(1)
        if token in effective and effective[token] is not None:
            value = str(effective[token])
            return value if value.strip() else "(none)"
        return f"<<<MISSING:{token}>>>"

    rendered = _PLACEHOLDER.sub(sub, template)
    return rendered, template
