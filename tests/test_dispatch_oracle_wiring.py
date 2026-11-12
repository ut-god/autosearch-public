"""Tests that the dispatcher passes the oracle SDK Tool list to create_session
when the workspace has an oracle build present, and skips it when not.
"""
from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest

# Re-use the FakeClient harness from the existing dispatch test module.
from tests.test_dispatch_sdk import _install_fake_copilot_module  # type: ignore


def _write_minimal_oracle(workspace: Path) -> Path:
    """Drop a usable method_facts.json into <workspace>/oracles/."""
    oracle_dir = workspace / "oracles"
    oracle_dir.mkdir(parents=True, exist_ok=True)
    p = oracle_dir / "method_facts.json"
    p.write_text(json.dumps({
        "schema_version": 1,
        "target_sha": "deadbeef",
        "cdb_path": None,
        "methods": {
            "WebCore::Test::method": {
                "method": "WebCore::Test::method",
                "decl_file": None, "decl_line": None,
                "idl_exposure": {
                    "exposed_to_window": True,
                    "exposed_to_worker": True,
                    "via_idls": [],
                },
                "mutable_globals_touched": [],
                "callers_1hop": [],
                "thread_protections": {
                    "self_asserts_main_thread": None,
                    "self_holds_lock": None,
                    "callers_asserting_main_thread": [],
                    "callers_NOT_asserting": [],
                },
            }
        },
    }))
    return p


def test_dispatch_includes_oracle_tool_when_workspace_has_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """When AUTOSEARCH_WORKSPACE points at a workspace with oracles/method_facts.json,
    the dispatcher must pass `tools=[oracle_method_facts]` to create_session."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_minimal_oracle(workspace)
    monkeypatch.setenv("AUTOSEARCH_WORKSPACE", str(workspace))

    recorder = _install_fake_copilot_module()

    # Stub copilot.tools so we can verify the Tool object lands in create_session.
    fake_tools = types.ModuleType("copilot.tools")

    class FakeTool:
        def __init__(self, name, description, handler, parameters=None,
                     overrides_built_in_tool=False, skip_permission=False):
            self.name = name
            self.description = description
            self.handler = handler
            self.parameters = parameters

    class FakeToolResult:
        def __init__(self, text_result_for_llm="", error=None, session_log=None,
                     **kw):
            self.text = text_result_for_llm
            self.error = error
            self.session_log = session_log

    fake_tools.Tool = FakeTool
    fake_tools.ToolResult = FakeToolResult
    fake_tools.ToolInvocation = object
    fake_tools.ToolBinaryResult = object
    sys.modules["copilot.tools"] = fake_tools

    # Force re-import so dispatch picks up the fakes.
    for mod in [m for m in sys.modules if m.startswith("autosearch.dispatch")
                or m.startswith("autosearch.oracles")]:
        sys.modules.pop(mod, None)

    from autosearch import dispatch as dispatch_mod

    d = dispatch_mod.CopilotSDKDispatcher()
    result = d.dispatch(
        prompt="probe", model="claude-opus-4.7",
        timeout_s=30, cwd=tmp_path / "any-target-repo",
        agent_name="default",
    )

    assert result.exit_code in (0, -1)  # FakeClient returns 0; -1 if a fake is missing
    last_tools = recorder.get("last_tools")
    assert last_tools is not None and len(last_tools) == 1, (
        "dispatcher must pass exactly one oracle tool to create_session "
        f"(got {last_tools!r})"
    )
    assert last_tools[0].name == "oracle_method_facts"


def test_dispatch_omits_tools_when_workspace_has_no_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """When the workspace lacks oracles/method_facts.json, no `tools=` kw is sent."""
    workspace = tmp_path / "ws-no-oracle"
    workspace.mkdir()
    monkeypatch.setenv("AUTOSEARCH_WORKSPACE", str(workspace))

    recorder = _install_fake_copilot_module()

    # Force re-import
    for mod in [m for m in sys.modules if m.startswith("autosearch.dispatch")
                or m.startswith("autosearch.oracles")]:
        sys.modules.pop(mod, None)

    from autosearch import dispatch as dispatch_mod
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="probe", model="claude-opus-4.7",
               timeout_s=30, cwd=tmp_path / "any-target-repo",
               agent_name="default")

    last_tools = recorder.get("last_tools")
    # Either omitted (None / not in kw) or an empty list — both acceptable.
    assert not last_tools, f"expected no tools when no oracle present (got {last_tools!r})"


def _install_real_tool_result_stub():
    """Restore a minimal ``copilot.tools`` with ToolResult that matches SDK shape.

    Earlier tests (test_dispatch_sdk and the wiring test above) inject fake
    `copilot` modules into sys.modules. The handler-construction tests need
    a working ToolResult class; we don't need the rest of the SDK.
    """
    fake_tools = types.ModuleType("copilot.tools")

    class ToolResult:
        def __init__(self, text_result_for_llm="", error=None, session_log=None,
                     **_kw):
            self.text_result_for_llm = text_result_for_llm
            self.error = error
            self.session_log = session_log

    class Tool:
        def __init__(self, name, description, handler, parameters=None,
                     overrides_built_in_tool=False, skip_permission=False):
            self.name = name
            self.description = description
            self.handler = handler
            self.parameters = parameters
            self.skip_permission = skip_permission

    fake_tools.ToolResult = ToolResult
    fake_tools.Tool = Tool
    fake_tools.ToolInvocation = object
    fake_tools.ToolBinaryResult = object
    sys.modules["copilot.tools"] = fake_tools


def test_oracle_tool_handler_returns_factsheet_for_known_method(tmp_path: Path):
    """Bound handler dispatches lookup and returns serialized JSON."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_minimal_oracle(workspace)

    from types import SimpleNamespace
    _install_real_tool_result_stub()
    # Force re-import of oracles.tool so it picks up the stubbed copilot.tools.
    sys.modules.pop("autosearch.oracles.tool", None)
    sys.modules.pop("autosearch.oracles", None)
    from autosearch.oracles.store import MethodFactsStore
    from autosearch.oracles.tool import build_oracle_tool

    store = MethodFactsStore.from_file(workspace / "oracles" / "method_facts.json")
    tool = build_oracle_tool(store)

    invocation = SimpleNamespace(
        session_id="s", tool_call_id="c", tool_name="oracle_method_facts",
        arguments={"method": "WebCore::Test::method"},
    )
    result = tool.handler(invocation)
    assert result.error is None
    payload = json.loads(result.text_result_for_llm)
    assert payload["idl_exposure"]["exposed_to_worker"] is True


def test_oracle_tool_handler_rejects_missing_method():
    """Empty / missing 'method' arg returns error."""
    from types import SimpleNamespace
    _install_real_tool_result_stub()
    sys.modules.pop("autosearch.oracles.tool", None)
    sys.modules.pop("autosearch.oracles", None)
    from autosearch.oracles.store import MethodFactsStore
    from autosearch.oracles.tool import build_oracle_tool

    store = MethodFactsStore(facts={}, schema_version=1, target_sha=None, cdb_path=None)
    tool = build_oracle_tool(store)

    invocation = SimpleNamespace(
        session_id="s", tool_call_id="c", tool_name="oracle_method_facts",
        arguments={},
    )
    result = tool.handler(invocation)
    assert result.error is not None
    assert "method" in result.error.lower()
