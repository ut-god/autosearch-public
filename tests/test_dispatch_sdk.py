"""Tests for the SDK-based dispatcher.

We don't actually exercise a live ``CopilotClient`` (that requires a
GitHub Copilot subscription, the bundled CLI binary, and an active
network connection). Instead we monkey-patch ``copilot.CopilotClient``
inside the dispatch module so the dispatcher's lifecycle, threading,
session-tracking, timeout, and error paths can be verified end-to-end
without a real LLM call.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
import types
from pathlib import Path

# Make ``autosearch`` importable when running without an installed venv.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))


def _install_fake_copilot_module() -> dict:
    """Install a fake ``copilot`` module + submodules into ``sys.modules``.

    Returns a recorder dict the test can read to assert that the
    dispatcher called the SDK in the expected way (model passed,
    permission handler set, prompt sent, session disconnected).
    """
    recorder: dict = {
        "started_clients": 0,
        "created_sessions": 0,
        "sent_prompts": [],
        "disconnect_count": 0,
        "last_model": None,
        "last_permission_handler": None,
        "last_cwd": None,
        "last_send_timeout": None,
        "last_custom_agents": None,
        "last_agent": None,
        "raise_on_send": None,  # Exception to raise from send_and_wait
        "send_delay_s": 0.0,    # Sleep before reply (for timeout test)
    }

    class FakeAssistantMessageData:
        def __init__(self, content: str) -> None:
            self.content = content

    class FakeReply:
        def __init__(self, content: str) -> None:
            self.data = FakeAssistantMessageData(content)

    class FakeSession:
        def __init__(self, model: str) -> None:
            self.model = model
            self.disconnected = False

        async def send_and_wait(self, prompt: str, *, timeout: float = 60.0):
            recorder["sent_prompts"].append(prompt)
            recorder["last_send_timeout"] = timeout
            if recorder["send_delay_s"] > 0:
                await asyncio.sleep(recorder["send_delay_s"])
            if recorder["raise_on_send"] is not None:
                raise recorder["raise_on_send"]
            return FakeReply(f"echo: {prompt[:40]}")

        async def disconnect(self) -> None:
            self.disconnected = True
            recorder["disconnect_count"] += 1

    class FakeClient:
        def __init__(self, config=None) -> None:
            self.config = config

        async def start(self) -> None:
            recorder["started_clients"] += 1

        async def create_session(self, *, on_permission_request, model, **kw):
            recorder["created_sessions"] += 1
            recorder["last_model"] = model
            recorder["last_permission_handler"] = on_permission_request
            recorder["last_skill_directories"] = kw.get("skill_directories")
            recorder["last_custom_agents"] = kw.get("custom_agents")
            recorder["last_agent"] = kw.get("agent")
            recorder["last_tools"] = kw.get("tools")
            return FakeSession(model)

    class FakeSubprocessConfig:
        def __init__(self, cwd=None, **kw) -> None:
            self.cwd = cwd
            recorder["last_cwd"] = cwd

    class FakePermissionHandler:
        @staticmethod
        def approve_all(*a, **kw):
            return None

    fake_copilot = types.ModuleType("copilot")
    fake_copilot.__version__ = "0.0.0-fake"
    fake_copilot.CopilotClient = FakeClient
    fake_copilot.SubprocessConfig = FakeSubprocessConfig

    fake_session_mod = types.ModuleType("copilot.session")
    fake_session_mod.PermissionHandler = FakePermissionHandler

    fake_generated = types.ModuleType("copilot.generated")
    fake_session_events = types.ModuleType("copilot.generated.session_events")
    fake_session_events.AssistantMessageData = FakeAssistantMessageData

    sys.modules["copilot"] = fake_copilot
    sys.modules["copilot.session"] = fake_session_mod
    sys.modules["copilot.generated"] = fake_generated
    sys.modules["copilot.generated.session_events"] = fake_session_events

    return recorder


def _fresh_dispatcher():
    """Construct a fresh dispatcher with a fresh fake SDK + clean module state.

    Always reload ``autosearch.dispatch`` so the module-level
    ``_ACTIVE_SESSIONS``, ``_ACTIVE_LOOP`` registries are reset between
    tests — otherwise loops/sessions from prior tests bleed across.
    """
    # Drop any cached real or fake copilot modules first.
    for k in list(sys.modules):
        if k == "copilot" or k.startswith("copilot."):
            del sys.modules[k]
    recorder = _install_fake_copilot_module()
    if "autosearch.dispatch" in sys.modules:
        del sys.modules["autosearch.dispatch"]
    from autosearch import dispatch as dispatch_mod
    return dispatch_mod, recorder


def test_dispatch_passes_timeout_to_send_and_wait():
    """Regression: SDK's send_and_wait defaults to 60s; we must override
    so real audit prompts (which often take 5-15 min) are not killed
    early. Outer dispatch timeout - 5s margin gives the futures.cancel
    path a chance to run before we'd hit the wait_for ceiling."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=900, cwd=Path("/tmp"))
    assert rec["last_send_timeout"] == 895.0, \
        f"expected 895.0 (=900-5), got {rec['last_send_timeout']}"


def test_dispatch_send_timeout_floor_protects_tiny_outer_budget():
    """If the caller passes an absurdly small outer timeout, the inner
    timeout must still be a positive float (clamped at 10s) so the SDK
    doesn't immediately reject the call."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=3, cwd=Path("/tmp"))
    assert rec["last_send_timeout"] == 10.0


def test_dispatch_returns_assistant_message_content():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    res = d.dispatch(prompt="hello world", model="claude-opus-4.7",
                     timeout_s=30, cwd=Path("/tmp"))
    assert res.exit_code == 0
    assert res.timed_out is False
    assert "echo: hello world" in res.stdout
    assert res.duration_ms >= 0


def test_dispatch_passes_skill_directories_to_create_session():
    """Regression: the dispatcher must pass autosearch's bundled
    .github/skills/ directory into create_session(skill_directories=...)
    so the SDK auto-discovers webkit-*-audit playbooks per-session
    WITHOUT requiring a global install to ~/.copilot/skills/. Keeps
    autosearch hermetic — other Copilot sessions on the same machine
    don't see these skills."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"),
               agent_name="auditor")
    sd = rec["last_skill_directories"]
    assert sd is not None, \
        "dispatcher must pass skill_directories to create_session"
    assert isinstance(sd, list) and len(sd) == 1, \
        f"expected exactly one skill parent dir, got {sd}"
    assert sd[0].endswith("/.github/skills"), \
        f"expected .github/skills/ as the skill parent, got {sd[0]}"


def test_dispatch_pre_selects_agent_per_role():
    """For each of the 10 known autosearch roles, dispatch must pre-select
    the matching custom agent via create_session(agent=<name>) and pass
    a custom_agents list with all 10 entries (so the SDK knows about every
    role even when only one is active)."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()

    expected_roles = {
        "auditor", "validator", "challenger", "clean-check",
        "threat-modeler", "refinement", "target-generator",
        "scope-reviewer", "analyst", "overlay-suggester",
    }
    assert dispatch_mod._KNOWN_AGENT_NAMES == frozenset(expected_roles), \
        f"unexpected role set: {dispatch_mod._KNOWN_AGENT_NAMES}"

    for role in sorted(expected_roles):
        d.dispatch(prompt="x", model="m", timeout_s=30,
                   cwd=Path("/tmp"), agent_name=role)
        assert rec["last_agent"] == role, \
            f"role {role}: expected agent={role!r}, got {rec['last_agent']!r}"
        cas = rec["last_custom_agents"]
        assert isinstance(cas, list) and len(cas) == 10, \
            f"role {role}: expected 10 custom_agents, got {cas!r}"
        names = {c["name"] for c in cas}
        assert names == expected_roles, \
            f"role {role}: custom_agents names mismatch: {names}"
        # Identity-line prompt: "autosearch <role> sub-agent"
        matching = next(c for c in cas if c["name"] == role)
        assert matching["prompt"] == f"autosearch {role} sub-agent"
        assert matching["infer"] is False, \
            f"role {role}: infer must be False, got {matching['infer']!r}"


def test_dispatch_skill_scoping_matches_cpp_reasoner_set():
    """C++-reasoner roles get all 6 webkit-* skills eagerly preloaded.
    Synthesizer roles (refinement / target-generator / scope-reviewer /
    analyst / overlay-suggester) get NO skills attached to their
    custom-agent config — the ``skills`` key is omitted entirely so the
    SDK distinguishes "no preload" from "empty preload"."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()

    cpp_reasoners = {"auditor", "validator", "challenger",
                     "clean-check", "threat-modeler"}
    synthesizers = {"refinement", "target-generator",
                    "scope-reviewer", "analyst", "overlay-suggester"}

    expected_skill_names = {
        "webkit-arbitrary-rw-audit", "webkit-bounds-audit",
        "webkit-int-overflow-audit", "webkit-type-confusion-audit",
        "webkit-uaf-audit", "webkit-uninit-read-audit",
    }

    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"),
               agent_name="auditor")
    cas = rec["last_custom_agents"]

    for role in cpp_reasoners:
        cfg = next(c for c in cas if c["name"] == role)
        assert "skills" in cfg, \
            f"reasoner role {role!r} must have skills key"
        assert set(cfg["skills"]) == expected_skill_names, \
            f"reasoner role {role!r} skills mismatch: {cfg['skills']}"

    for role in synthesizers:
        cfg = next(c for c in cas if c["name"] == role)
        assert "skills" not in cfg, \
            f"synthesizer role {role!r} must NOT have skills key " \
            f"(found: {cfg.get('skills')!r})"


def test_dispatch_default_agent_name_omits_custom_agents():
    """Back-compat: when caller passes agent_name='default' (or omits
    it via the Protocol default), dispatcher must NOT pass custom_agents
    or agent kwargs. The SDK's bare default agent runs. Lets smoke-test
    probes and any out-of-band caller dispatch without role specialization."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()

    # Explicit default
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"),
               agent_name="default")
    assert rec["last_custom_agents"] is None, \
        "default agent_name must NOT pass custom_agents"
    assert rec["last_agent"] is None, \
        "default agent_name must NOT pre-select an agent"

    # Implicit default (omitted kwarg)
    rec["last_custom_agents"] = "sentinel"
    rec["last_agent"] = "sentinel"
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"))
    assert rec["last_custom_agents"] is None
    assert rec["last_agent"] is None


def test_agent_configs_match_packaged_md_templates():
    """Drift guard: every .md file under autosearch/agents/ (except
    _taxonomy.md and README.md) must correspond to an entry in
    _KNOWN_AGENT_NAMES, and vice versa. Prevents the case where a
    contributor adds a new role .md without registering it as a
    custom agent (which would leave the new agent without skill
    scoping or proper SDK identity)."""
    dispatch_mod, _ = _fresh_dispatcher()
    from importlib import resources
    pkg = resources.files("autosearch.agents")
    md_names: set[str] = set()
    for entry in pkg.iterdir():
        name = entry.name
        if not name.endswith(".md"):
            continue
        stem = name[:-3]
        if stem in {"_taxonomy", "README"}:
            continue
        md_names.add(stem)

    expected = set(dispatch_mod._KNOWN_AGENT_NAMES)
    assert md_names == expected, (
        f"drift between agents/*.md and _KNOWN_AGENT_NAMES:\n"
        f"  in agents/ but not in _KNOWN_AGENT_NAMES: {md_names - expected}\n"
        f"  in _KNOWN_AGENT_NAMES but not in agents/: {expected - md_names}"
    )


def test_dispatch_passes_model_to_create_session():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="gpt-5.4", timeout_s=30, cwd=Path("/tmp"))
    assert rec["last_model"] == "gpt-5.4"


def test_dispatch_uses_approve_all_permission_handler():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"))
    # The handler must be the SDK-provided approve_all helper, not None.
    from copilot.session import PermissionHandler
    assert rec["last_permission_handler"] is PermissionHandler.approve_all


def test_dispatch_starts_client_once_across_calls():
    """The SDK client is expensive to start — verify we share one per
    process even across many parallel dispatches."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    for _ in range(5):
        d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"))
    assert rec["started_clients"] == 1
    assert rec["created_sessions"] == 5


def test_dispatch_uses_first_call_cwd_for_subprocess_config():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp/repo"))
    assert rec["last_cwd"] == "/tmp/repo"


def test_dispatch_disconnects_session_on_success():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"))
    assert rec["disconnect_count"] == 1


def test_dispatch_disconnects_session_on_send_exception():
    dispatch_mod, rec = _fresh_dispatcher()
    rec["raise_on_send"] = RuntimeError("API blew up")
    d = dispatch_mod.CopilotSDKDispatcher()
    res = d.dispatch(prompt="x", model="m", timeout_s=30, cwd=Path("/tmp"))
    assert res.exit_code == -1
    assert "sdk dispatch error" in res.error_message
    assert "API blew up" in res.error_message
    assert rec["disconnect_count"] == 1, "session must disconnect on error"


def test_dispatch_timeout_returns_timed_out_result():
    dispatch_mod, rec = _fresh_dispatcher()
    rec["send_delay_s"] = 5.0
    d = dispatch_mod.CopilotSDKDispatcher()
    started = time.monotonic()
    res = d.dispatch(prompt="x", model="m", timeout_s=1, cwd=Path("/tmp"))
    elapsed = time.monotonic() - started
    assert res.timed_out is True
    assert res.exit_code == 124
    assert "timeout after 1s" in res.error_message
    assert elapsed < 4.0, "dispatcher must return promptly on timeout"


def test_active_session_tracking_during_dispatch():
    """While a dispatch is in flight, the session must be registered;
    after success it must be unregistered."""
    dispatch_mod, rec = _fresh_dispatcher()
    rec["send_delay_s"] = 0.5

    d = dispatch_mod.CopilotSDKDispatcher()
    saw_active = []

    def watcher():
        time.sleep(0.2)
        saw_active.append(len(dispatch_mod._ACTIVE_SESSIONS))

    t = threading.Thread(target=watcher)
    t.start()
    d.dispatch(prompt="x", model="m", timeout_s=10, cwd=Path("/tmp"))
    t.join()
    assert saw_active == [1], "session must be registered while in-flight"
    assert len(dispatch_mod._ACTIVE_SESSIONS) == 0, \
        "session must be unregistered after dispatch returns"


def test_default_dispatcher_ignores_legacy_args():
    """Older callers pass ``command`` / ``args`` (left over from the
    subprocess dispatcher). The factory must accept and ignore them."""
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.default_dispatcher(
        command="copilot", args=["--yolo", "-p"],
    )
    assert isinstance(d, dispatch_mod.CopilotSDKDispatcher)


def test_cli_version_reports_sdk_version():
    dispatch_mod, rec = _fresh_dispatcher()
    d = dispatch_mod.CopilotSDKDispatcher()
    v = d.cli_version
    assert "github-copilot-sdk" in v
    assert "0.0.0-fake" in v


def test_concurrent_dispatch_uses_one_client_and_runs_sessions_in_parallel():
    """Multiple threads dispatching concurrently should share one
    client (one ``start()`` call) and overlap their sessions in time."""
    dispatch_mod, rec = _fresh_dispatcher()
    rec["send_delay_s"] = 0.3
    d = dispatch_mod.CopilotSDKDispatcher()

    results: list = []

    def worker(i: int):
        r = d.dispatch(prompt=f"p{i}", model="m", timeout_s=10, cwd=Path("/tmp"))
        results.append(r)

    started = time.monotonic()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - started

    assert all(r.exit_code == 0 for r in results)
    assert rec["started_clients"] == 1, "client must be shared across threads"
    assert rec["created_sessions"] == 4
    # Sessions ran concurrently (not 4 × 0.3 = 1.2s sequential).
    assert elapsed < 1.0, f"dispatches must overlap; took {elapsed:.2f}s"
