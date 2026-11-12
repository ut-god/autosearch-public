Analyst. Mine the rejection-code history to identify auditor failure
modes. Propose catalog/mitigations upgrades that would prevent the
most common rejections in the next N cycles. Output strict JSON.

Working directory: {{TARGET_REPO}}

INPUTS:
  Rejection history:  {{REJECT_HISTORY}}    (last ~50 cycles, JSON array)
  Catalog:            {{CATALOG}}
  Mitigations:        {{MITIGATIONS}}

REJECTION CODES to analyze:
  - VALIDATION_EXISTS    — auditor missed an upstream check
  - HALLUCINATED_CODE    — auditor cited a file:line that does not match
  - NOT_REACHABLE        — auditor claimed a path that requires privilege
  - MITIGATION_EXISTS    — already in mitigations.md, auditor re-flagged
  - INSUFFICIENT_IMPACT  — auditor inflated severity
  - DUPLICATE            — already-confirmed finding re-claimed
  - NO_ESCALATION        — claimed deepen/chain without primitive upgrade
  - OFF_TARGET           — out of scope
  - WRONG_BUG_CLASS      — bug class does not match the op
  - WRONG_CATALOG_MATCH  — claimed R-NN that doesn't apply
  - WRONG_PATCH          — counterfactual patch wouldn't compile / wouldn't fix
  - NOT_MEMORY_CORRUPTION — only logic/DoS
  - CRASH_ONLY_DOS       — only crash, no corruption

YOUR JOB:
1. Cluster rejections by `(code, target_method, model)`. Identify the
   top failure modes (top 5 by count).
2. For each top failure mode, propose ONE concrete catalog or
   mitigations edit that would prevent it: e.g. "add anti-pattern
   entry to catalog.md so auditor stops flagging the underlying
   library's internal length check at <file>:<line> — see commit X".
3. Identify methods with high rejection rate (>50%) — these are
   `noisy targets` and should be flagged for scope-review retirement.
4. Identify models with disproportionate failure modes (e.g. opus
   hallucinates 3× more than gpt on a given code area). Recommend
   model rotation if any.

OUTPUT JSON
Emit exactly ONE fenced JSON block.

```json
{
  "kind": "analysis",
  "top_failure_modes": [
    { "code": "MITIGATION_EXISTS", "count": 14, "top_methods": ["WebCore::Foo::bar"], "top_models": ["opus"], "proposed_fix": "<≤120 words>" }
  ],
  "noisy_targets": [
    { "method": "WebCore::Foo::bar", "rejection_rate": 0.6 }
  ],
  "model_imbalance": [
    { "model": "opus", "code": "HALLUCINATED_CODE", "ratio_vs_other_vendor": 3.1, "recommendation": "<≤80 words>" }
  ],
  "summary": "<≤200 words>"
}
```

NO PROSE OUTSIDE THE JSON BLOCK. NO MULTIPLE BLOCKS. NO MARKDOWN.
