Defensive review mode. Try to falsify a memory-corruption finding. Output strict JSON.

Working directory: {{TARGET_REPO}}

Finding under challenge (id {{HASH}}):

{{FULL_FINDING_JSON}}

CONTEXT:
  Targets:     {{TARGETS}}
  Catalog:     {{CATALOG}}
  Mitigations: {{MITIGATIONS}}

YOUR JOB: read the actual code at the cited file:line and try to
demonstrate the finding is wrong on at least one of:

1. Does the cited `unchecked_op.file:line` actually contain the operation
   the auditor described? Quote the source line verbatim.
2. Is there a CHECKED bound / lifetime guard / type check that the
   auditor missed? Walk the caller chain. If found, quote it.
3. Is the `bug_class` correct? E.g. is it really UAF, or only a missing
   null deref / DoS that does not corrupt memory?
4. Is the reachability path real ({{ATTACKER_SURFACE}}), or does it require
   privileged / non-renderer entry?
5. Is the corruption primitive actually achievable, or is the
   attacker-controlled value clamped to safe range upstream?
6. Is severity overstated? E.g. claimed ARBITRARY_RW but is really only
   a small relative read of attacker-supplied data.
7. Does `patch_counterfactual` actually close the bug?

VERDICT:
  - `survives`: you read the code carefully and could not disprove the
    finding on any of the 7 axes.
  - `reverted`: you found specific source evidence that disproves at
    least one axis. Cite it.

Default stance is `survives` ONLY when steps 1-7 all hold up. Be
adversarial — if you can find ONE source-cited axis that disproves the
claim, choose `reverted`.

{{TAXONOMY}}

OUTPUT JSON
Emit exactly ONE fenced JSON block.

```json
{
  "kind": "challenge",
  "verdict": "survives",
  "rationale": "<≤200 words: which axes you checked and why each held>",
  "axes_checked": ["op_exists", "no_upstream_check", "bug_class_correct", "reachable", "primitive_achievable", "severity_correct", "patch_closes_bug"],
  "evidence": [
    { "file": "Source/WebCore/...", "line": 848, "what": "<observation>" }
  ]
}
```

```json
{
  "kind": "challenge",
  "verdict": "reverted",
  "rationale": "<≤200 words: which axis was disproved and how>",
  "disproved_axis": "op_exists | upstream_check_exists | wrong_bug_class | not_reachable | clamped | severity_overstated | patch_wrong",
  "evidence": [
    { "file": "Source/WebCore/...", "line": 800, "what": "<existing check / wrong file:line / etc.>" }
  ]
}
```

NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
