Refinement pass. Maintain compact audit memory. Output strict JSON.

Working directory: {{TARGET_REPO}}

This cycle's CLAIMS:

{{LAST_CYCLE_RESULTS}}

This cycle's CLEANS with `checks_verified` arrays. Each check cites a verified
file:line guard; long clean prose is intentionally omitted:

{{LAST_CYCLE_CLEANS}}

CURRENT MEMORY:
  Catalog:     {{CATALOG}}
  Mitigations: {{MITIGATIONS}}

YOUR JOB:
Return compact audit-memory updates without letting mitigations grow into a
case log.

WHAT BELONGS WHERE:

- `catalog_entries`: positive memory from confirmed/settled memory-corruption
  claims only. No confirmed/settled claim means this array must be empty.

- `mitigations_md`: a full replacement for `rules/mitigations.md`, but it must
  be semantically grouped pattern memory. Merge similar guards into one pattern
  group. Do not append one entry per clean.

MITIGATION FORMAT:

Use this exact entry shape:

```markdown
- M-001 (guard kind) Pattern: <broad reusable safety pattern>.
  Covers: <APIs/types/mechanisms covered by this pattern>.
  Examples: <up to 3 file:line witnesses; examples only, not identity>.
  Do not flag unless: <specific proof needed before future auditors report it>.
```

RULES FOR MITIGATION GROUPS:

- Pattern-based, not case-based.
- File:line witnesses are examples only; they are not the mitigation.
- Merge semantically equivalent guards even when wording/file witnesses differ.
- Keep only broad patterns useful across future audits.
- Do NOT include clean IDs, long citation lists, model names, or per-method
  case summaries.
- Do NOT add witness-only entries.
- If current mitigations already cover this cycle, return current mitigations
  verbatim or a shorter grouped version.

HARD SIZE TARGETS:

- `mitigations_md`: max 16 `M-###` pattern groups.
- `mitigations_md`: target <= 6000 chars.
- New `mitigations_md` should not grow by more than about 800 chars over
  CURRENT MEMORY unless there is a confirmed/rejected/recurring pattern that
  clearly deserves a new group. The orchestrator will enforce hard caps.
- `catalog_entries`: max 3 entries per cycle.

PROMOTION BAR:

1. Add a catalog entry only for a confirmed/settled bug that teaches a reusable
   memory-corruption pattern. Include bug class and source evidence.

2. Add or edit a mitigation group only when it describes a reusable pattern
   likely to help multiple future audits:
   - same guard appears in multiple methods or independent model runs, OR
   - guard is a fundamental API/library/framework invariant, OR
   - rejected/reverted claim exposes a recurring bad hypothesis.

3. Prefer no mitigation change over adding narrow memory.

Allowed mitigation guard kinds:
bounds check, lifetime owner, type/tag check, ordering guard, synchronization
guard, ownership transfer, hardened/container invariant, fail-closed behavior,
anti-pattern.

Bug class names, when needed: HEAP_OVERFLOW, STACK_OVERFLOW, OOB_WRITE,
OOB_READ, UAF, DOUBLE_FREE, TYPE_CONFUSION, RACE_TO_TYPE_CONFUSION,
INT_OVERFLOW_TO_OOB, UNINIT_READ, RACE_TO_OOB, RACE_TO_UAF, ARBITRARY_RW,
n/a.

OUTPUT JSON
Emit exactly ONE fenced JSON block.

```json
{
  "kind": "refinement",
  "catalog_entries": [
    {
      "bug_class": "UAF",
      "pattern": "<reusable confirmed-bug pattern>",
      "evidence": ["Source/...:123"],
      "applies_when": "<when future auditors should consider this rule>"
    }
  ],
  "mitigations_md": "# Mitigations\n\n<full compact grouped mitigation markdown>",
  "rationale": "<≤120 words: what was grouped, merged, pruned, or left unchanged>",
  "new_rules": ["<short signatures only>"],
  "new_mitigations": ["<short signatures only>"]
}
```

If there is no broadly reusable new mitigation memory, return CURRENT
Mitigations verbatim or shorter.
NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
