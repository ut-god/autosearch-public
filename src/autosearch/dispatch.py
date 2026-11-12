"""Dispatch via the github-copilot-sdk Python client.

Replaces the previous fork-and-exec model (`copilot --yolo -p <prompt>`
per call) with a long-lived ``CopilotClient`` + background asyncio loop:

  - A single ``CopilotClient`` is started once per process and reused
    across every dispatch. The CLI binary stays warm — no per-call
    process spawn, no per-call CLI startup latency.
  - Each ``dispatch()`` opens a short-lived session, sends the prompt,
    waits for the final assistant message via ``send_and_wait``, then
    disconnects the session.
  - Sessions can run concurrently; the orchestrator's ThreadPoolExecutor
    keeps working unchanged — each worker thread calls the synchronous
    ``dispatch()`` which submits a coroutine to the background event
    loop and blocks on the result.
  - The ``model`` argument is **honored** (passed to ``create_session``).
    The legacy CLI invocation ignored ``--model`` because the CLI's user
    config wins; the SDK lets us pick model per session.

Active-session tracking
───────────────────────
Each in-flight session is registered so the SIGINT/SIGTERM handler in
``cli.py:run`` can disconnect them on shutdown. Without this, Ctrl-C
kills the orchestrator but its open SDK sessions keep their LLM API
calls draining (often 5+ minutes, often paid).
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import TimeoutError as FutTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

log = logging.getLogger(__name__)


# Module-level registry of active sessions for SIGINT cleanup.
# Keyed by id(session) so unhashable session objects are still tracked,
# and so the same session can't be registered twice by accident.
_ACTIVE_SESSIONS: dict[int, Any] = {}
_ACTIVE_LOOP: Optional[asyncio.AbstractEventLoop] = None
_ACTIVE_LOCK = threading.Lock()


def _register_session(session: Any) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE_SESSIONS[id(session)] = session


def _unregister_session(session: Any) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE_SESSIONS.pop(id(session), None)


def terminate_all_active(grace_s: float = 2.0) -> int:
    """Disconnect every in-flight SDK session.

    Safe to call from a signal handler. Returns the count of sessions
    targeted. Schedules ``session.disconnect()`` on the dispatcher's
    background event loop and waits ``grace_s`` for in-flight RPC calls
    to drain. Best-effort — swallows individual disconnect failures so
    one stuck session can't block the rest of the shutdown.

    Used by the SIGINT/SIGTERM handler in cli.py:run() so that Ctrl-C on
    the orchestrator immediately cancels all LLM subagents instead of
    leaving them to drain their (paid) API calls.
    """
    with _ACTIVE_LOCK:
        snapshot = list(_ACTIVE_SESSIONS.values())
        loop = _ACTIVE_LOOP
    if not snapshot or loop is None or not loop.is_running():
        return 0
    for session in snapshot:
        try:
            asyncio.run_coroutine_threadsafe(session.disconnect(), loop)
        except Exception:  # noqa: BLE001
            pass
    if grace_s > 0:
        time.sleep(grace_s)
    return len(snapshot)


@dataclass
class DispatchResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool = False
    error_message: str = ""


class Dispatcher(Protocol):
    def dispatch(self, prompt: str, model: str, timeout_s: int,
                 cwd: Optional[Path] = None,
                 agent_name: str = "default") -> DispatchResult: ...

    @property
    def cli_version(self) -> str: ...


# ─── Custom-agent definitions ──────────────────────────────────────────
#
# Each autosearch role (auditor, validator, ...) is registered with the
# Copilot SDK as a named custom agent. The runtime uses the agent's
# ``name`` for telemetry (events.jsonl), the ``display_name`` for any
# UI surfaces, and the ``skills`` list to eagerly preload skill content
# into the agent's context at session start.
#
# The ``prompt`` field is intentionally a single identity line. The .md
# templates already contain ROLE / GOAL / SAFETY RULES / OUTPUT JSON
# in detail, and we send the full rendered template as the user message.
# A multi-line wrapper system prompt would just duplicate that and risk
# drifting out of sync with the .md over time.
#
# ``infer: False`` on every agent — we always pre-select the agent
# explicitly via ``agent=<name>``; the runtime never auto-routes.
# ───────────────────────────────────────────────────────────────────────

# Roles that reason about WebKit C++ memory safety. Get all 6 webkit-*
# audit playbooks eagerly preloaded into their context. The remaining
# 5 roles (refinement, target-generator, scope-reviewer, analyst,
# overlay-suggester) are synthesizers — they aggregate / mutate text
# corpora but don't analyze C++ for memory bugs, so they get no skills.
_NAMES_WITH_SKILLS = frozenset({
    "auditor",
    "validator",
    "challenger",
    "clean-check",
    "threat-modeler",
})

# Display names + one-line descriptions for SDK telemetry. Keep
# descriptions specific (per the agent-skills doc's best practice on
# `description` quality) so any future intent-routing UI has good
# signal — even though we set ``infer: False``, we want the
# descriptions to stay informative.
_DISPLAY_NAMES: dict[str, str] = {
    "auditor":           "Auditor",
    "validator":         "Validator",
    "challenger":        "Challenger",
    "clean-check":       "Clean-check",
    "refinement":        "Refinement",
    "threat-modeler":    "Threat Modeler",
    "target-generator":  "Target Generator",
    "scope-reviewer":    "Scope Reviewer",
    "analyst":           "Analyst",
    "overlay-suggester": "Overlay Suggester",
}

_DESCRIPTIONS: dict[str, str] = {
    "auditor":           "Reviews ONE method for memory-corruption bugs, returns CLAIM or CLEAN.",
    "validator":         "Adversarially confirms or rejects a single CLAIM with one of 13 rejection codes.",
    "challenger":        "Adversarially attacks a CLAIM along 7 axes; verdict survives or reverted.",
    "clean-check":       "Spot-checks a CLEAN to find bugs the auditor missed.",
    "refinement":        "Updates catalog.md / mitigations.md from one cycle's claims and cleans.",
    "threat-modeler":    "Per-file threat model: assets, entry points, corruption sinks, candidate methods.",
    "target-generator":  "Aggregates per-file threat models into a targets.md section.",
    "scope-reviewer":    "Gates new targets or retires saturated ones from targets.md.",
    "analyst":           "Mines rejection-code history for noisy targets and model imbalance.",
    "overlay-suggester": "Builds the [prompt_overlay] block from an area's IDL + headers.",
}

# Source-of-truth for which agent_name values are valid SDK custom
# agents. Used both to drive _build_agent_configs and to decide in
# CopilotSDKDispatcher.dispatch() whether to pass custom_agents+agent
# to the SDK or fall through to the default agent.
_KNOWN_AGENT_NAMES = frozenset(_DISPLAY_NAMES)


def _build_agent_configs(skill_names: Optional[list[str]]) -> list[dict]:
    """Return the list of CustomAgentConfig dicts for ``create_session``.

    One entry per autosearch role. ``skills`` is included only for roles
    in ``_NAMES_WITH_SKILLS`` and only when ``skill_names`` is a
    non-empty list (e.g. the in-tree .github/skills/ exists). Roles
    without skills omit the key entirely (the SDK distinguishes
    "no skills field" from "skills: []").
    """
    configs: list[dict] = []
    for role in sorted(_KNOWN_AGENT_NAMES):
        cfg: dict = {
            "name": role,
            "display_name": _DISPLAY_NAMES[role],
            "description": _DESCRIPTIONS[role],
            "prompt": f"autosearch {role} sub-agent",
            "infer": False,
        }
        if role in _NAMES_WITH_SKILLS and skill_names:
            cfg["skills"] = list(skill_names)
        configs.append(cfg)
    return configs


class CopilotSDKDispatcher:
    """Dispatcher backed by ``github-copilot-sdk``.

    Lazily starts a single ``CopilotClient`` on a dedicated background
    event loop on first dispatch. The client's working directory is
    taken from the first dispatch call (in practice this is always
    ``config.target_repo``, which is constant per orchestrator run).
    Later calls with a different ``cwd`` log a warning and use the
    original — sessions inherit the client's process cwd, which can't
    change without restarting the CLI subprocess.
    """

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._client: Any = None
        self._client_cwd: Optional[Path] = None
        self._init_lock = threading.Lock()
        self._client_init_lock = threading.Lock()
        self._cached_version: Optional[str] = None
        # Memoized list of CustomAgentConfig dicts. Built once on first
        # dispatch (we need list_skill_dirs() → list of skill names,
        # and importing skills before first dispatch is not free).
        self._agent_configs: Optional[list[dict]] = None
        self._skill_names: Optional[list[str]] = None
        # Memoized oracle tool list, resolved per-cwd. Loaded lazily so
        # workspaces without an oracle build still work (tools=None).
        self._oracle_tools: Optional[list[Any]] = None
        self._oracle_tools_cwd: Optional[Path] = None

    # ---- version ----------------------------------------------------

    @property
    def cli_version(self) -> str:
        if self._cached_version is not None:
            return self._cached_version
        try:
            import copilot as _cp
            sdk_v = getattr(_cp, "__version__", "unknown")
            v = f"github-copilot-sdk {sdk_v}"
        except Exception as e:  # noqa: BLE001
            v = f"copilot sdk import error: {e}"
        self._cached_version = v
        return v

    # ---- background event loop --------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Start the background asyncio loop on first use.

        Module-level ``_ACTIVE_LOOP`` is updated so ``terminate_all_active``
        can submit disconnect coroutines from a signal handler without
        needing a reference to this dispatcher instance.
        """
        global _ACTIVE_LOOP
        if self._loop is not None:
            return self._loop
        with self._init_lock:
            if self._loop is not None:
                return self._loop
            loop = asyncio.new_event_loop()

            def runner() -> None:
                asyncio.set_event_loop(loop)
                loop.run_forever()

            t = threading.Thread(
                target=runner, daemon=True, name="copilot-sdk-loop",
            )
            t.start()
            self._loop = loop
            self._loop_thread = t
            with _ACTIVE_LOCK:
                _ACTIVE_LOOP = loop
            return loop

    # ---- client (one per process) -----------------------------------

    async def _ensure_client(self, cwd: Optional[Path]) -> Any:
        """Lazily start the singleton ``CopilotClient`` in the loop thread.

        The CLI subprocess inherits ``cwd`` from ``SubprocessConfig`` at
        client startup. We can't change it without restarting the
        subprocess, so we lock the cwd to the first dispatch call.
        """
        if self._client is not None:
            if cwd is not None and self._client_cwd != cwd:
                log.warning(
                    "CopilotSDKDispatcher: cwd changed from %s to %s; "
                    "reusing original (sessions inherit client process cwd)",
                    self._client_cwd, cwd,
                )
            return self._client

        # Import inside to keep import cost off the hot path for
        # callers that never dispatch (e.g. `autosearch findings list`).
        from copilot import CopilotClient, SubprocessConfig

        config = SubprocessConfig(cwd=str(cwd) if cwd else None)
        client = CopilotClient(config)
        await client.start()
        self._client = client
        self._client_cwd = cwd
        return client

    # ---- skill / agent config (memoized) ----------------------------

    def _resolve_skill_metadata(self) -> tuple[Optional[list[str]], list[dict]]:
        """Return ``(skill_directories, agent_configs)`` — both memoized.

        ``skill_directories`` goes into ``create_session(skill_directories=...)``.
        ``agent_configs`` is the list of 10 CustomAgentConfig dicts; only
        non-empty when the in-tree ``.github/skills/`` exists. Defensive:
        any import or filesystem error is swallowed and we return
        ``(None, [])`` so the cohort still runs without skills.
        """
        if self._agent_configs is not None:
            return self._cached_skill_dirs, self._agent_configs

        skill_dirs: Optional[list[str]] = None
        skill_names: Optional[list[str]] = None
        try:
            from .skills import list_skill_dirs, list_skills
            skill_dirs = list_skill_dirs()
            skill_names = [s.name for s in list_skills()] if skill_dirs else None
        except Exception:  # noqa: BLE001
            pass

        self._cached_skill_dirs = skill_dirs
        self._skill_names = skill_names
        self._agent_configs = _build_agent_configs(skill_names)
        return skill_dirs, self._agent_configs

    # ---- oracle tools (memoized per cwd) ----------------------------

    def _resolve_oracle_tools(self, cwd: Optional[Path]) -> list[Any]:
        """Return SDK Tool list for oracles, or [] if no oracle build is found.

        The oracle JSON lives in the autosearch *workspace*, NOT the target_repo
        (``cwd`` here is target_repo). We discover the workspace via:
          1. ``AUTOSEARCH_WORKSPACE`` environment variable (set by orchestrator)
          2. ``Path.cwd()`` fallback (autosearch CLI typically runs from workspace)

        Defensive: any error returns [] so audits still proceed without
        oracle access — schema enforcement (Phase 3) handles the
        "missing citation" case separately.
        """
        import os as _os
        ws_str = _os.environ.get("AUTOSEARCH_WORKSPACE")
        ws = Path(ws_str) if ws_str else Path.cwd()

        if self._oracle_tools is not None and self._oracle_tools_cwd == ws:
            return self._oracle_tools

        tools: list[Any] = []
        try:
            facts_path = ws / "oracles" / "method_facts.json"
            if facts_path.is_file():
                from .oracles import MethodFactsStore, build_oracle_tool
                store = MethodFactsStore.from_file(facts_path)
                tools.append(build_oracle_tool(store))
                import logging as _l
                _l.getLogger(__name__).info(
                    "oracle: loaded %d methods from %s",
                    store.known_method_count(), facts_path,
                )
        except Exception as e:  # noqa: BLE001
            import logging as _l
            _l.getLogger(__name__).warning("oracle tool load failed: %s", e)

        self._oracle_tools = tools
        self._oracle_tools_cwd = ws
        return tools

    # ---- the dispatch coroutine -------------------------------------

    async def _dispatch_async(self, prompt: str, model: str,
                              cwd: Optional[Path],
                              timeout_s: float,
                              agent_name: str) -> DispatchResult:
        from copilot.generated.session_events import AssistantMessageData
        from copilot.session import PermissionHandler

        started = time.monotonic()
        try:
            client = await self._ensure_client(cwd)
        except Exception as e:  # noqa: BLE001
            duration_ms = int((time.monotonic() - started) * 1000)
            return DispatchResult(
                stdout="", stderr="", exit_code=-1,
                duration_ms=duration_ms,
                error_message=f"client startup error: {e}",
            )

        # Resolve skills + agent configs (memoized; cheap on subsequent calls).
        skill_dirs, agent_configs = self._resolve_skill_metadata()
        oracle_tools = self._resolve_oracle_tools(cwd)

        # Pre-select the autosearch role if it's a known custom agent;
        # otherwise (e.g. agent_name="default" for a smoke probe), let
        # the SDK's default agent run with no custom-agent config.
        # Pre-selection keeps the orchestrator's deterministic state
        # machine in charge — infer:False on every agent ensures the
        # runtime never auto-routes between them.
        session_extra: dict = {}
        if agent_name in _KNOWN_AGENT_NAMES and agent_configs:
            session_extra["custom_agents"] = agent_configs
            session_extra["agent"] = agent_name
        if oracle_tools:
            session_extra["tools"] = oracle_tools

        session = None
        try:
            session = await client.create_session(
                on_permission_request=PermissionHandler.approve_all,
                model=model,
                skill_directories=skill_dirs,
                **session_extra,
            )
            _register_session(session)
            # IMPORTANT: SDK's send_and_wait defaults to 60s. Real audit
            # prompts (overlay-suggester, threat-modeler, auditor) routinely
            # exceed that. Pass our caller-supplied timeout through so the
            # outer asyncio.wait_for (in dispatch()) is the only ceiling.
            # Subtract 5s margin so the outer future cancellation has time
            # to clean up before we'd hit it.
            inner_timeout = max(10.0, timeout_s - 5.0)
            reply = await session.send_and_wait(prompt, timeout=inner_timeout)

            text = ""
            if reply is not None and isinstance(reply.data, AssistantMessageData):
                text = reply.data.content or ""
            duration_ms = int((time.monotonic() - started) * 1000)
            return DispatchResult(
                stdout=text, stderr="", exit_code=0,
                duration_ms=duration_ms,
            )
        except Exception as e:  # noqa: BLE001
            duration_ms = int((time.monotonic() - started) * 1000)
            return DispatchResult(
                stdout="", stderr=str(e), exit_code=-1,
                duration_ms=duration_ms,
                error_message=f"sdk dispatch error: {e}",
            )
        finally:
            # Single cleanup path: registered iff create_session succeeded.
            # Both unregister and disconnect are idempotent / best-effort.
            if session is not None:
                _unregister_session(session)
                try:
                    await session.disconnect()
                except Exception:  # noqa: BLE001
                    pass

    # ---- sync entrypoint --------------------------------------------

    def dispatch(self, prompt: str, model: str, timeout_s: int,
                 cwd: Optional[Path] = None,
                 agent_name: str = "default") -> DispatchResult:
        loop = self._ensure_loop()
        coro = self._dispatch_async(prompt, model, cwd, float(timeout_s), agent_name)
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return fut.result(timeout=timeout_s)
        except FutTimeout:
            fut.cancel()
            return DispatchResult(
                stdout="", stderr="", exit_code=124,
                duration_ms=timeout_s * 1000,
                timed_out=True,
                error_message=f"timeout after {timeout_s}s",
            )


def default_dispatcher(*args: Any, **kwargs: Any) -> CopilotSDKDispatcher:
    """Construct the default dispatcher.

    Accepts and ignores legacy ``command`` / ``args`` keyword arguments
    for back-compat with older config.toml files that set
    ``dispatch_command`` and ``dispatch_args``. Those settings were
    meaningful only for the subprocess-based dispatcher; the SDK
    dispatcher takes no constructor arguments.
    """
    if args or kwargs:
        log.debug(
            "default_dispatcher: ignoring legacy positional args=%r and "
            "keyword args=%r — the SDK dispatcher takes no constructor "
            "arguments. dispatch_command/dispatch_args in config.toml are "
            "no longer needed.",
            args, kwargs,
        )
    return CopilotSDKDispatcher()
