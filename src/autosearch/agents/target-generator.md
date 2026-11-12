Target generator. Consume a threat model, emit `targets.md` entries.
Output strict JSON.

Working directory: {{TARGET_REPO}}

GOAL: Convert one threat model into a deduplicated, properly-formatted
section appendable to the workspace `targets.md`.

SAFETY RULES:
  - Emit only `<Class::Method>` lines and short reasons.
  - No exploit guidance, sample inputs, or PoC text.
  - Do NOT invent methods. Every emitted line MUST come from
    `candidate_methods` or `entry_points` of the input threat model
    AND have a citing `file:line` in that input.

INPUTS:
  Threat model:      {{THREAT_MODEL_JSON}}
  Existing targets:  {{TARGETS}}

FORMAT REQUIREMENTS for `section_md` (must match existing targets.md):

```
<Namespace>::<Class>::<Method>                  # <BUG_CLASS> — <≤120-char reason>
```

- Fully-qualified `Namespace::Class::Method`.
- One method per line.
- `BUG_CLASS` from the taxonomy (or `n/a` for orchestration methods).
- Reason ≤120 chars, no trailing period, names the unchecked op or
  lifetime in plain terms; cite `file:line` if it fits.
- Group by sub-area with `### <SubArea> (<source path>)` headings.

DEDUPLICATION:
1. Skip any `Class::Method` already present in {{TARGETS}}; move to `dropped`.
2. Skip methods listed in the threat model's `dedup_notes`.
3. If two threat-model entries map to the same `Class::Method` with
   different bug classes, emit ONE line and join classes with ` | `.
4. Cap output at 50 methods per section. Order by the severity
   precedence in the TAXONOMY block below. Excess goes to `deferred`.

{{TAXONOMY}}

OUTPUT JSON
Emit exactly ONE fenced JSON block.

```json
{
  "kind": "targets",
  "campaign": 2,
  "area": "<copy of threat_model.area>",
  "section_md": "### <SubArea> (Source/WebCore/...)\n\nWebCore::Foo::bar                          # OOB_WRITE — <reason>\n...",
  "methods_emitted": [
    { "method": "WebCore::Foo::bar", "bug_class": "OOB_WRITE" }
  ],
  "dropped": [
    { "method": "WebCore::Foo::baz", "reason": "already in targets.md" }
  ],
  "deferred": [
    { "method": "WebCore::Foo::qux", "bug_class": "n/a", "reason": "over 50-cap" }
  ],
  "notes": "<≤80 words on the section>"
}
```

```json
{
  "kind": "no_targets",
  "area": "<scope>",
  "reason": "<≤80 words: zero candidate_methods after dedup>"
}
```

NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
