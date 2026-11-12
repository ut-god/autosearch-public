"""Generic agent invocation.

Single shared path: render the agent's prompt template with placeholder
substitution, dispatch via subprocess, extract strict JSON from the
response with ONE repair retry on failure, record the run to
`agent_runs`, and optionally mirror to `logs/cycles/<n>/`.

Used by both:
  - `Orchestrator` for in-cycle audit/validator/challenger/refinement runs.
  - CLI commands (`threat-model`, `generate-targets`, `review-scope`,
    `analyze`) for out-of-band runs (cycle_n=None).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import dispatch as dispatch_mod
from . import parse as parse_mod
from . import pricing as pricing_mod
from . import render
from .store.db import Store, _utc_now


def invoke(
    *,
    store: Store,
    dispatcher: dispatch_mod.Dispatcher,
    agent_name: str,
    slot: str,
    model: str,
    ctx: dict,
    cycle_n: Optional[int],
    target_repo: Path,
    agent_timeout_s: int,
    log_dir: Optional[Path] = None,
) -> dict:
    """Render → dispatch → parse → (one repair retry) → record.

    Returns:
        {
            "agent_run_id": int,
            "model": str,
            "slot": str,
            "parsed": dict | None,
            "parse_status": "ok" | "repaired" | "parse_failed" | "timeout" | "error",
            "repaired": bool,
        }
    """
    prompt, template_text = render.render_prompt(agent_name, ctx)
    prompt_version_id = store.upsert_prompt_version(agent_name, template_text)
    started_at = _utc_now()

    result = dispatcher.dispatch(
        prompt=prompt, model=model,
        timeout_s=agent_timeout_s, cwd=target_repo,
        agent_name=agent_name,
    )
    ended_at = _utc_now()

    pres = parse_mod.extract_json(result.stdout)
    parse_status = "ok" if pres.ok else "parse_failed"
    repaired = False

    if pres.ok:
        ok_schema, schema_err = parse_mod.validate_schema(pres.parsed)
        if not ok_schema:
            pres = parse_mod.ParseResult(False, None, error=schema_err)
            parse_status = "parse_failed"

    raw_response = result.stdout

    # One-shot repair attempt
    if not pres.ok and result.stdout:
        repair_prompt = parse_mod.make_repair_prompt(prompt, result.stdout, pres.error)
        repair_result = dispatcher.dispatch(
            prompt=repair_prompt, model=model,
            timeout_s=agent_timeout_s, cwd=target_repo,
            agent_name=agent_name,
        )
        ended_at = _utc_now()
        pres = parse_mod.extract_json(repair_result.stdout)
        if pres.ok:
            ok_schema, schema_err = parse_mod.validate_schema(pres.parsed)
            if not ok_schema:
                pres = parse_mod.ParseResult(False, None, error=schema_err)
        if pres.ok:
            parse_status = "repaired"
            repaired = True
            raw_response = result.stdout + "\n\n<<<REPAIR>>>\n" + repair_result.stdout
            result = dispatch_mod.DispatchResult(
                stdout=raw_response,
                stderr=result.stderr + "\n" + repair_result.stderr,
                exit_code=repair_result.exit_code,
                duration_ms=result.duration_ms + repair_result.duration_ms,
            )
        else:
            parse_status = "parse_failed"
            raw_response = result.stdout + "\n\n<<<REPAIR_ATTEMPT>>>\n" + (repair_result.stdout or "")

    if result.timed_out:
        parse_status = "timeout"

    # Cost telemetry: estimate from char counts (dispatcher doesn't return
    # real usage stats today). Stored alongside duration_ms for later cost
    # roll-ups by `autosearch findings cost` and the TUI status panel.
    prompt_tokens = pricing_mod.estimate_tokens(prompt)
    completion_tokens = pricing_mod.estimate_tokens(raw_response)
    cost_usd = pricing_mod.estimate_cost_usd(model, prompt_tokens, completion_tokens)

    run_id = store.record_agent_run(
        cycle_n=cycle_n,
        agent_name=agent_name,
        slot=slot,
        model=model,
        cli_version=dispatcher.cli_version,
        prompt_version_id=prompt_version_id,
        rendered_prompt=prompt,
        raw_response=raw_response,
        parse_status=parse_status,
        parsed_json=pres.parsed,
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=result.duration_ms,
        exit_code=result.exit_code,
        error_message=result.error_message,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=cost_usd,
    )

    # Per-cycle (or per-run) log mirror — convenience for browsing
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        # Safe filename: replace path separators
        safe_slot = slot.replace("/", "_").replace("#", "n").replace(":", "_")
        fname = f"{run_id:05d}_{agent_name}_{safe_slot}.json"
        (log_dir / fname).write_text(json.dumps({
            "agent_run_id": run_id,
            "agent_name": agent_name,
            "slot": slot,
            "model": model,
            "cli_version": dispatcher.cli_version,
            "cycle_n": cycle_n,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": result.duration_ms,
            "exit_code": result.exit_code,
            "parse_status": parse_status,
            "repaired": repaired,
            "rendered_prompt": prompt,
            "raw_response": raw_response,
            "parsed_json": pres.parsed,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": cost_usd,
        }, indent=2, default=str))

    return {
        "agent_run_id": run_id,
        "model": model,
        "slot": slot,
        "parsed": pres.parsed if pres.ok else None,
        "parse_status": parse_status,
        "repaired": repaired,
    }
