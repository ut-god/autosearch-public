"""Token estimation + per-model pricing.

The dispatcher (copilot CLI) doesn't return real usage stats today, so
token counts here are CHARACTER-COUNT ESTIMATES (rule-of-thumb 4 chars
per token, which is a reasonable mean for English + JSON + C++).

Pricing is a static table of public list prices; missing models leave
`cost_usd` as NULL (which the cost report tolerates and surfaces as
`unknown`). Keeping pricing in code rather than config means it lives
with the call-site that uses it; bump prices here when vendor rates
change and re-run. Historical `cost_usd` rows are NOT backfilled — the
cost CLI re-derives from token counts on the fly when needed.

Public refs (verify before shipping a price-change PR):
  - https://www.anthropic.com/pricing
  - https://openai.com/api/pricing/
"""
from __future__ import annotations

from typing import Optional

# Average characters per token. ~4 is a well-cited rule of thumb for
# English; code/JSON pushes lower (~3) so we slightly under-estimate cost.
# OK for trend-tracking; if real usage stats become available, replace.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: Optional[str]) -> int:
    """Rough char-count estimate. Returns 0 for None/empty."""
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)


# (input_per_million_usd, output_per_million_usd)
# Update when vendor rates change. Unknown models → NULL cost (not 0).
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    # Claude (Anthropic public list, May 2026)
    "claude-opus-4.7":            (15.00, 75.00),
    "claude-opus-4.6":            (15.00, 75.00),
    "claude-opus-4.5":            (15.00, 75.00),
    "claude-sonnet-4.6":           (3.00, 15.00),
    "claude-sonnet-4.5":           (3.00, 15.00),
    "claude-sonnet-4":             (3.00, 15.00),
    "claude-haiku-4.5":            (1.00,  5.00),
    # OpenAI (rough placeholders; verify before relying on absolute $)
    "gpt-5.4":                     (3.00, 12.00),
    "gpt-5.3-codex":               (3.00, 12.00),
    "gpt-5.2":                     (3.00, 12.00),
    "gpt-5.4-mini":                (0.50,  2.00),
    "gpt-5-mini":                  (0.50,  2.00),
    "gpt-4.1":                     (2.00,  8.00),
}


def model_pricing(model: str) -> Optional[tuple[float, float]]:
    """Return (input_per_M_usd, output_per_M_usd) or None if unknown."""
    if model in _MODEL_PRICING:
        return _MODEL_PRICING[model]
    # Fuzzy match: prefix lookup (e.g. "claude-opus-4.7-1m-internal" → "claude-opus-4.7")
    for known, price in _MODEL_PRICING.items():
        if model.startswith(known):
            return price
    return None


def estimate_cost_usd(model: str, prompt_tokens: int,
                      completion_tokens: int) -> Optional[float]:
    """Compute USD cost from tokens + model. None if model unknown."""
    pr = model_pricing(model)
    if pr is None:
        return None
    in_per_m, out_per_m = pr
    return (prompt_tokens * in_per_m + completion_tokens * out_per_m) / 1_000_000.0
