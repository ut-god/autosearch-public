"""Tests for the autosearch skill loader and prompt-catalog injection."""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from autosearch.skills import (  # noqa: E402
    SkillRecord,
    list_skills,
    render_catalog,
)
from autosearch.skills._loader import _parse_frontmatter  # noqa: E402


def test_parse_frontmatter_extracts_name_and_description():
    text = (
        "---\n"
        "name: foo-skill\n"
        "description: a description that may span tokens\n"
        "---\n\n"
        "# body\n"
    )
    fm = _parse_frontmatter(text)
    assert fm == {
        "name": "foo-skill",
        "description": "a description that may span tokens",
    }


def test_parse_frontmatter_strips_double_quoted_values():
    fm = _parse_frontmatter("---\nname: foo\ndescription: \"quoted desc\"\n---\n\n")
    assert fm == {"name": "foo", "description": "quoted desc"}


def test_parse_frontmatter_returns_empty_when_no_frontmatter():
    assert _parse_frontmatter("# just a markdown header") == {}
    assert _parse_frontmatter("") == {}
    # Frontmatter not at the very start (preceded by blank line) → ignored.
    assert _parse_frontmatter("\n---\nname: x\ndescription: y\n---\n") == {}


def test_parse_frontmatter_ignores_comment_and_blank_lines():
    text = (
        "---\n"
        "# this is a comment in YAML\n"
        "\n"
        "name: foo\n"
        "description: bar\n"
        "---\n"
    )
    assert _parse_frontmatter(text) == {"name": "foo", "description": "bar"}


def test_list_skills_returns_at_least_webkit_uaf_audit():
    """The webkit-uaf-audit skill is shipped in the package; loader must
    discover it without any workspace setup or external installation."""
    skills = list_skills()
    names = {s.name for s in skills}
    assert "webkit-uaf-audit" in names, f"got {names}"


def test_list_skills_record_has_resolvable_path():
    """Skill paths must point at real files on disk so the auditor's
    `view` tool can open them."""
    skills = list_skills()
    uaf = next(s for s in skills if s.name == "webkit-uaf-audit")
    assert uaf.skill_md_path.is_file()
    assert uaf.skill_md_path.name == "SKILL.md"
    assert uaf.directory.is_dir()
    # Supporting cheatsheets ship alongside the skill md.
    siblings = {p.name for p in uaf.directory.iterdir()}
    assert "smart-pointer-cheatsheet.md" in siblings
    assert "async-capture-patterns.md" in siblings
    assert "known-uaf-cves.md" not in siblings  # replaced by uaf-pattern-catalog.md
    assert "uaf-pattern-catalog.md" in siblings
    assert "wasm-jit-uaf-patterns.md" in siblings


def test_list_skills_skips_malformed_frontmatter(tmp_path, monkeypatch):
    """A malformed SKILL.md must not crash the loader — a typo in one
    skill should not break the entire auditor cohort dispatch."""
    # We can't easily inject a broken skill into the package; instead
    # exercise the parser path that drops entries with missing keys.
    text = "---\nname: \ndescription: \n---\n"
    fm = _parse_frontmatter(text)
    assert fm.get("name", "") == ""
    assert fm.get("description", "") == ""
    # _list path: a record with empty name/description is dropped — verified
    # by inspecting current catalog which has no such entries.
    for s in list_skills():
        assert s.name and s.description


def test_render_catalog_includes_name_description_and_path():
    out = render_catalog()
    assert "webkit-uaf-audit" in out
    # Description's first words appear verbatim.
    assert "Deep audit playbook" in out
    # Path must be present so the auditor knows where to view the skill.
    assert "SKILL.md" in out
    # Compact format — name lines are NOT prefixed with '- ' more than once.
    assert "- webkit-uaf-audit" in out


def test_render_catalog_with_empty_skill_list_returns_placeholder():
    assert render_catalog([]) == "(no skills available)"


def test_skills_catalog_no_longer_auto_injected_into_auditor_prompt():
    """The Copilot CLI auto-discovers skills from ~/.copilot/skills/ and
    injects an <available_skills> block into every session's system
    message. We previously embedded a SPECIALIST SKILLS catalog block
    in auditor.md as a workaround when our skills lived in the wrong
    directory; that workaround is now removed.

    Renders auditor.md and asserts:
      - The old "SPECIALIST SKILLS:" prompt section is gone.
      - The {{SKILLS_CATALOG}} placeholder is gone.
      - render_prompt does NOT auto-inject a skill name list.
      - Callers can still pass SKILLS_CATALOG explicitly (escape hatch
        for tests / future re-introduction)."""
    from autosearch import render

    ctx = {
        "TARGET_REPO": "/x", "TARGET_METHOD": "Foo::bar",
        "TARGET_FILE_HINTS": "", "TARGET_HINT": "none",
        "THREAT_MODEL_CONTEXT": "", "CATALOG": "", "MITIGATIONS": "",
        "CONFIRMED": "(none)", "ATTACKER_SURFACE": "x",
        "SCOPE_INCLUDES": "", "EXTRA_OUT_OF_SCOPE": "",
    }
    rendered, _ = render.render_prompt("auditor", ctx)

    assert "SPECIALIST SKILLS:" not in rendered, \
        "auditor.md must no longer carry the SPECIALIST SKILLS section"
    assert "{{SKILLS_CATALOG}}" not in rendered, \
        "the SKILLS_CATALOG placeholder must be removed from auditor.md"
    assert "webkit-uaf-audit" not in rendered, \
        "render_prompt must NOT auto-inject the skill list anymore — " \
        "the Copilot CLI handles skill discovery natively from " \
        "~/.copilot/skills/"

    # Explicit override still works (escape hatch).
    ctx_with_override = {**ctx, "SKILLS_CATALOG": "(custom override)"}
    rendered2, _ = render.render_prompt("auditor", ctx_with_override)
    # auditor.md no longer has the placeholder, so override doesn't land
    # in the auditor prompt anymore. But render_prompt should still
    # accept the kwarg without error (no MISSING:SKILLS_CATALOG either).
    assert "<<<MISSING:SKILLS_CATALOG>>>" not in rendered2, \
        "render must not treat SKILLS_CATALOG as a missing placeholder"


def test_template_hash_still_tracks_skill_catalog_changes():
    """Even though SKILLS_CATALOG is no longer auto-injected into
    prompts, template_hash MUST still include the skill catalog so that
    prompt_versions records a new version when skills are added /
    removed / renamed. Without this, switching skill sets would
    silently produce duplicate prompt_version_id rows in the corpus,
    breaking auditability."""
    from autosearch import render
    import autosearch.render as r

    base_hash = render.template_hash("auditor")

    original = r._skills_catalog_text
    try:
        r._skills_catalog_text = lambda: "(no skills available)"
        empty_hash = render.template_hash("auditor")
    finally:
        r._skills_catalog_text = original

    assert base_hash != empty_hash, \
        "template_hash must reflect skill catalog changes even when " \
        "the catalog is no longer rendered into the prompt"


def test_skill_record_directory_property_returns_skill_dir():
    skills = list_skills()
    uaf = next(s for s in skills if s.name == "webkit-uaf-audit")
    assert uaf.directory == uaf.skill_md_path.parent
    assert uaf.directory.name == "webkit-uaf-audit"
