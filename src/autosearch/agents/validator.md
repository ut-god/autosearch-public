Adversarial review gate. Falsify a memory-corruption CLAIM if the code
does not support it. Output strict JSON.

Working directory: {{TARGET_REPO}}

CLAIM under review:

{{CLAIM_JSON}}

YOUR JOB:
1. Read the cited `unchecked_op.file:line`. Quote the EXACT source line
   verbatim into `literal_source_quote.text`. If the file or line does not
   exist, or the cited content is not what the auditor described:
   reject with code `HALLUCINATED_CODE`.
2. Read the cited `missing_check.file:line` (or its caller chain). If a
   bound / lifetime guard / type check that closes the bug already exists:
   reject with code `VALIDATION_EXISTS` and quote the existing check.
3. Verify the `bug_class` matches what the cited op actually does
   (consult the TAXONOMY section below for the full class list and the
   "name the sink, not the cause" tie-break rule).
   If the class is wrong: reject with code `WRONG_BUG_CLASS`.
4. Verify reachability: does the cited reachability path actually
   flow from {{ATTACKER_SURFACE}} into this method without a privileged or
   cross-process gate? If not: reject with code `NOT_REACHABLE`.
5. Verify the corruption primitive: is `primitive` actually achievable,
   or is the attacker-controlled value clamped, validated, or replaced
   upstream? If clamped: reject with code `INSUFFICIENT_IMPACT`.
6. Verify `patch_counterfactual` would actually close the bug as
   described and would compile in context. If the patch is incoherent or
   would not close the bug: reject with code `WRONG_PATCH`.
7. Check `catalog_match` against the catalog in {{CATALOG}}. If it claims
   a rule that does not match the cited site: reject with code
   `WRONG_CATALOG_MATCH`.
8. Check {{CONFIRMED}} for an existing finding at the same canonical key
   (`(target_method, bug_class, file, line)`). If duplicate: reject with
   code `DUPLICATE`.
9. Verify the target is in scope (`{{TARGETS}}`). If not: reject with
   code `OFF_TARGET`.
10. If the cited site is not memory corruption (only crash, only logic):
    reject with code `NOT_MEMORY_CORRUPTION` or `CRASH_ONLY_DOS`.

DEFAULT STANCE: REJECT. Only ACCEPT when steps 1–10 all pass.

{{TAXONOMY}}

OUTPUT JSON
Emit exactly ONE fenced JSON block.

```json
{
  "kind": "validation",
  "verdict": "accept",
  "rationale": "<≤200 words explaining each check passed, citing file:line>",
  "literal_source_quote": {
    "file": "Source/WebCore/...",
    "line": 848,
    "text": "<exact source line as written in the file>"
  },
  "patch_check": "matches"
}
```

```json
{
  "kind": "validation",
  "verdict": "reject",
  "code": "VALIDATION_EXISTS | HALLUCINATED_CODE | NOT_REACHABLE | MITIGATION_EXISTS | INSUFFICIENT_IMPACT | DUPLICATE | NO_ESCALATION | OFF_TARGET | WRONG_BUG_CLASS | WRONG_CATALOG_MATCH | WRONG_PATCH | NOT_MEMORY_CORRUPTION | CRASH_ONLY_DOS",
  "rationale": "<≤200 words citing the file:line that disproves the claim>",
  "literal_source_quote": {
    "file": "Source/WebCore/...",
    "line": 848,
    "text": "<exact source line, or empty string if file/line did not exist>"
  },
  "patch_check": "wrong | missing | not_applicable"
}
```

NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
