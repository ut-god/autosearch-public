"""autosearch skills — markdown playbooks the Copilot CLI auto-loads
into auditor / validator / challenger sessions.

Source-of-truth for autosearch's bundled skills lives at the repo root
in ``.github/skills/`` (the open-standard project location per the
agent-skills spec). The :mod:`autosearch.dispatch` module passes the
parent directory containing those skills into ``CopilotClient.create_session``
via the SDK's ``skill_directories`` parameter, so the CLI auto-discovers
them per-session WITHOUT requiring a global install to
``~/.copilot/skills/``. This keeps autosearch hermetic — no other Copilot
session running on the same machine sees these skills.

Why skills (markdown) and not tools (RPC functions)?
- Procedural expertise is best expressed as a checklist + examples, not
  a structured JSON return.
- Cross-agent reuse: validator and challenger consult the same skill
  the auditor used, with zero code duplication.
- Author-friendly: edit markdown, no Python.
- Cheap to add: ``mkdir .github/skills/foo-audit && create SKILL.md``
  and the next session picks it up.
"""
from __future__ import annotations

from ._loader import (
    SkillRecord,
    list_skill_dirs,
    list_skills,
    render_catalog,
)

__all__ = ["SkillRecord", "list_skill_dirs", "list_skills", "render_catalog"]
