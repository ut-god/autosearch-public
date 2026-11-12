Adversarial spot-check on a CLEAN report. Falsify it if the code does
not support the cleared assertion. Output strict JSON.

Working directory: {{TARGET_REPO}}

CLEAN report under review:

{{CLAIM_JSON}}

CONTEXT:
  Targets:     {{TARGETS}}
  Catalog:     {{CATALOG}}
  Mitigations: {{MITIGATIONS}}

YOUR JOB:

1. For every entry in `checks_verified`, read the cited file:line. Does
   the named check actually exist? Does it cover the size / lifetime /
   type assumption it claims to (vs only a related, weaker property)?
2. **TRIVIAL misclassification check.** If the clean's `body` starts with
   `"trivial: "`, verify the method genuinely qualifies. Read the method
   source. If it calls ANY function that:
     - takes a `(pointer, length)` or `(pointer, pointer)` argument pair,
     - has a name containing copy / move / memcpy / memmove / memset /
       append / write / read / decode / encode / parse / alloc / free /
       resize / fill / drain / consume,
     - constructs a span / StringView / ArrayBufferView / Vector /
       SharedBuffer,
     - dispatches virtually, through a function pointer, std::function,
       or callback,
     - calls into an external C library (libpng, libjpeg, libwebp,
       libavif, libjxl, ICU, OpenSSL, etc.),
   then the TRIVIAL classification is wrong. The auditor did NOT read
   the callee body. Read the callee yourself. If you find an unchecked
   memory-relevant op there, emit a `found_claim` verdict with the bug
   you uncovered. If the callee is genuinely safe, still emit `confirm`
   but note the misclassification in your rationale (`"trivial misclassified
   — callee X is sized I/O but bound by Y at file:line"`) so refinement
   can use that signal.
3. Walk sibling code paths (other entries, partial init, error-recovery
   branches, async callbacks) where the same op runs WITHOUT the cited
   check.
4. Cross-reference catalog rules R-NN: was an obvious memcorr angle
   skipped (attacker-controlled offset into a buffer, raw `.data()`
   to a sized I/O API, format-vs-buffer-extent mismatch in transforms, etc.)?
5. If you find something the auditor missed, emit a fresh CLAIM in the
   auditor.md JSON shape (kind="claim", all required fields).

6. **ORACLE CITATION CROSS-CHECK.** If the CLEAN under review includes
   a `factsheet_citations` field, you MUST independently call
   `oracle_method_facts(<target>)` and re-verify each citation:

     - Does the cited oracle subfield actually contain the claimed value?
     - Does the rebuttal in `what_it_proves` actually follow from the
       value (e.g. citing `idl_exposure.exposed_to_worker == false`
       does NOT prove "main-thread only" if the oracle ALSO shows
       Worker-exposed callers in `callers_1hop`)?

   If the citation is wrong (the value the auditor reported doesn't
   match what the oracle returns), or the rebuttal doesn't logically
   follow, emit `found_claim` with the missed bug. The auditor's
   citation is the SINGLE most important thing to falsify — it's
   their evidence of work.

   If the CLEAN has NO `factsheet_citations` field but the target's
   `bug_class_hint` is `RACE_*` or `UAF`, that itself is suspicious:
   the auditor was supposed to consult the oracle. Call
   `oracle_method_facts(<target>)` yourself; if the FactSheet shows
   non-trivial facts (worker-exposed callers, mutable globals
   touched, no thread asserts), emit `found_claim`.

{{TAXONOMY}}

OUTPUT JSON
Emit exactly ONE fenced JSON block. Either `confirm` the clean, or
emit a new claim found during spot-check.

```json
{
  "kind": "clean_check",
  "verdict": "confirm",
  "rationale": "<≤120 words: which checks you re-read, which adjacent paths you walked>"
}
```

```json
{
  "kind": "clean_check",
  "verdict": "found_claim",
  "rationale": "<≤80 words: what the auditor missed>",
  "claim": {
    "kind": "claim",
    "target_class": "...",
    "target_method": "...",
    "type": "fresh",
    "builds_on": null,
    "bug_class": "<one class from the taxonomy section above>",
    "claim": "...",
    "unchecked_op": { "file": "...", "line": 0 },
    "missing_check": { "file": "...", "line": 0 },
    "reachability": "...",
    "primitive": "...",
    "trust_type": "a",
    "severity": "Medium",
    "patch_counterfactual": "...",
    "catalog_match": null,
    "novel": true,
    "body": "<≤200 words>"
  }
}
```

NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
