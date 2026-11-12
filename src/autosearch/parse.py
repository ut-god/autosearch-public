"""Strict JSON output extractor + one-shot repair logic.

Agents are required to emit exactly one fenced ```json ... ``` block.
On parse failure (no fence, malformed JSON, schema mismatch), the
orchestrator does ONE repair re-prompt that quotes the bad response
and asks for strict re-emission. A second failure marks the run
parse_failed and the orchestrator proceeds without the result.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

# Match a fenced JSON block; tolerate ```json or just ```.
_FENCE_RE = re.compile(
    r"```(?:json|JSON)?\s*\n(?P<body>.*?)\n```",
    re.DOTALL,
)


@dataclass
class ParseResult:
    ok: bool
    parsed: Optional[dict]
    error: str = ""
    repaired: bool = False


def extract_json(text: str) -> ParseResult:
    """Find the LAST fenced JSON block in text and parse it.

    Many LLMs emit thinking text before the final block; the *last*
    block is the canonical answer.
    """
    if not text:
        return ParseResult(False, None, error="empty response")
    blocks = _FENCE_RE.findall(text)
    if not blocks:
        # Last-ditch: if the whole response is bare JSON, try that.
        try:
            obj = json.loads(text.strip())
            return ParseResult(True, obj)
        except json.JSONDecodeError as e:
            return ParseResult(False, None, error=f"no fenced JSON block; bare parse failed: {e}")
    last = blocks[-1].strip()
    try:
        obj = json.loads(last)
    except json.JSONDecodeError as e:
        return ParseResult(False, None, error=f"JSON decode error: {e}")
    if not isinstance(obj, dict):
        return ParseResult(False, None, error="top-level JSON is not an object")
    if "kind" not in obj:
        return ParseResult(False, None, error="missing required field 'kind'")
    return ParseResult(True, obj)


def make_repair_prompt(original_prompt: str, bad_response: str, error: str) -> str:
    """Build a repair prompt that quotes the bad output and asks for re-emission."""
    return (
        "Your previous response did not satisfy the JSON output contract.\n\n"
        f"Parser error: {error}\n\n"
        "REQUIREMENTS:\n"
        "- Emit exactly ONE fenced JSON block: ```json\\n{...}\\n```\n"
        "- The JSON object MUST have a top-level `kind` field.\n"
        "- No prose before or after the block.\n"
        "- No multiple blocks.\n\n"
        "Your previous response (verbatim, between markers):\n"
        "<<<BEGIN_BAD_RESPONSE>>>\n"
        f"{bad_response}\n"
        "<<<END_BAD_RESPONSE>>>\n\n"
        "Re-emit your answer following the contract from the original prompt. "
        "Do not change your analytical conclusion; only fix the format.\n"
        "Original prompt was:\n\n"
        f"{original_prompt}\n"
    )


# ---------- per-kind schema validation ----------

_REQUIRED_FIELDS = {
    "claim": [
        "target_class", "target_method", "type", "bug_class", "claim",
        "unchecked_op", "reachability", "primitive", "trust_type",
        "severity", "patch_counterfactual", "body",
    ],
    "clean": ["target_class", "target_method", "checks_verified", "body"],
    "validation": ["verdict", "rationale"],
    "challenge": ["verdict", "rationale"],
    "clean_check": ["verdict", "rationale"],
    "refinement": ["rationale"],
    "threat_model": [
        "area", "paths", "assets", "entry_points",
        "trust_boundaries", "attacker_controlled_values",
        "corruption_sinks", "candidate_methods",
    ],
    "no_threat_model": ["area", "reason"],
    "targets": ["campaign", "area", "section_md", "methods_emitted"],
    "no_targets": ["area", "reason"],
    "scope_review": ["role", "summary"],
    "analysis": ["top_failure_modes", "summary"],
    "overlay": ["area", "attacker_surface", "scope_includes", "extra_out_of_scope", "rationale"],
    "no_overlay": ["area", "reason"],
}


def validate_schema(parsed: dict) -> tuple[bool, str]:
    kind = parsed.get("kind", "")
    required = _REQUIRED_FIELDS.get(kind)
    if required is None:
        return False, f"unknown kind: {kind!r}"
    missing = [f for f in required if f not in parsed]
    if missing:
        return False, f"missing required fields for kind={kind}: {missing}"
    return True, ""
