# autosearch agent prompts

Each `.md` file is the system prompt for one agent role. Prompts are
**deterministically substituted** by `autosearch.render` (mustache-style
`{{TOKEN}}` placeholders) and dispatched by `autosearch.dispatch`.

## Output contract

**Every agent MUST emit exactly one fenced JSON block** as its final output:

```json
{ "kind": "...", ... }
```

The orchestrator parses this with `autosearch.parse.extract_json`. On parse
failure (no fence, malformed JSON, schema mismatch), the orchestrator does
**one** repair re-prompt that quotes the original response and asks for a
strict re-emission. A second failure marks the agent run `parse_failed`
and the cycle proceeds without that result.

Per-agent JSON schemas are documented inside each prompt file under the
`OUTPUT JSON` section.

## Roles

### Audit cycle
| File              | Role                | Cohort | Models                    |
|-------------------|---------------------|--------|---------------------------|
| `auditor.md`      | Find new memcorr    | 6      | 3× opus + 3× gpt          |
| `validator.md`    | Cross-model gate    | 1/CLAIM| opposite vendor           |
| `clean-check.md`  | Cross-model gate    | 1/CLEAN| opposite vendor           |
| `challenger.md`   | Falsify finding     | 2      | 1 opus + 1 gpt            |
| `refinement.md`   | Update rules memory | 1      | opus                      |

The orchestrator runs `challenger.md` in two distinct *phases*:
- **pre-commit**: every CLAIM that passes validator faces both challengers
  before becoming `confirmed`. Either challenger reverting → `state=contested`.
- **post-commit**: settled findings are re-challenged only after the
  catalog version changes or the target file SHA changes.

### Scope expansion (out-of-band)
| File                    | Role                                       |
|-------------------------|--------------------------------------------|
| `threat-modeler.md`     | Code area → structured threat model        |
| `target-generator.md`   | Threat model → `targets.md` entries        |
| `scope-reviewer.md`     | Phase-1 gate + Phase-3 retirement engine   |

### Learning
| File              | Role                                              |
|-------------------|---------------------------------------------------|
| `analyst.md`      | Mine rejection codes → catalog upgrade proposals  |

## Placeholder tokens

Substituted by `autosearch.render.render_prompt(agent_name, ctx)`:

- `{{TARGETS}}`               — workspace `targets.md`
- `{{CATALOG}}`               — workspace `rules/catalog.md`
- `{{MITIGATIONS}}`           — workspace `rules/mitigations.md`
- `{{RECENT}}`                — last 15 findings, one per line
- `{{CONFIRMED}}`             — every confirmed/settled finding, one per line
- `{{TARGET_METHOD}}`         — single `Class::Method` for this auditor slot
- `{{TARGET_FILE_HINTS}}`     — `file:line` hints from threat model, if any
- `{{CLAIM_JSON}}`            — verbatim claim JSON for validator/challenger
- `{{HASH}}`                  — finding ID for challenger
- `{{FULL_FINDING_JSON}}`     — complete finding row JSON for challenger
- `{{LAST_CYCLE_RESULTS}}`    — JSON array of this cycle's audit results for refinement
- `{{REJECT_HISTORY}}`        — JSON array of rejection codes for analyst
- `{{CODE_PATHS}}`            — list of files/dirs for threat-modeler
- `{{THREAT_MODEL_JSON}}`     — verbatim threat-model output for target-generator
- `{{PROPOSED_TARGETS_JSON}}` — verbatim target-generator output for scope-reviewer
- `{{TARGET_HEALTH_JSON}}`    — per-method audit-count + clean-count + last-finding-age

## Editing rules

- Prompts are read from disk fresh each cycle; no caching.
- Every prompt edit bumps the prompt version (sha256 of the rendered template
  with empty placeholders), recorded in `agent_runs.prompt_version`.
- A prompt version change triggers re-evaluation of all retired methods
  (epoch invalidation).
- Never inline workspace-specific paths or secrets.
