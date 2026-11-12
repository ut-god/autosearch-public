"""SDK Tool wrapper for the MethodFacts oracle.

Registers ``oracle_method_facts(method)`` as a callable tool the auditor invokes
mid-reasoning. Every call lands in the session's ``events.jsonl`` and is later
matched against the auditor's structured citations by the parser.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .store import MethodFactsStore

log = logging.getLogger(__name__)

_TOOL_NAME = "oracle_method_facts"

_TOOL_DESCRIPTION = (
    "Returns mechanically-computed ground-truth facts about a C++ method in the "
    "target codebase. Use this BEFORE concluding properties about reachability, "
    "thread safety, singleton mutation, or IDL exposure. Cite specific subfield "
    "paths (e.g. 'idl_exposure.exposed_to_worker', 'mutable_globals_touched[0]."
    "lock_in_scope') when producing CLEAN or RACE_* findings.\n\n"
    "Argument: 'method' must be a fully-qualified C++ method name in the form "
    "'WebCore::ClassName::methodName' (no parameter list, no return type)."
)

_TOOL_PARAMETERS = {
    "type": "object",
    "properties": {
        "method": {
            "type": "string",
            "description": "Fully qualified C++ method name, e.g. "
                           "'WebCore::PathCG::strokeContains'.",
        }
    },
    "required": ["method"],
}


def _make_handler(store: MethodFactsStore):
    """Create an SDK-compatible tool handler bound to ``store``."""
    from copilot.tools import ToolResult, ToolInvocation

    def handler(invocation: "ToolInvocation") -> "ToolResult":
        args = invocation.arguments or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                return ToolResult(
                    text_result_for_llm="",
                    error="arguments must be a JSON object with 'method' key",
                )

        method = (args.get("method") or "").strip()
        if not method:
            return ToolResult(
                text_result_for_llm="",
                error="missing required argument 'method'",
            )

        facts = store.lookup(method)
        text = json.dumps(facts, indent=1)
        # session_log is the human-readable trace line in events.jsonl
        return ToolResult(
            text_result_for_llm=text,
            session_log=f"oracle_method_facts({method}) → known={method in store.facts}",
        )

    return handler


def build_oracle_tool(store: MethodFactsStore):
    """Construct the ``oracle_method_facts`` SDK Tool bound to a loaded store."""
    from copilot.tools import Tool

    return Tool(
        name=_TOOL_NAME,
        description=_TOOL_DESCRIPTION,
        handler=_make_handler(store),
        parameters=_TOOL_PARAMETERS,
        skip_permission=True,  # read-only lookup, never needs user prompt
    )
