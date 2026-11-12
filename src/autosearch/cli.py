"""autosearch CLI."""
from __future__ import annotations

import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from . import agent_invoke
from . import dispatch as dispatch_mod
from . import import_git as import_git_mod
from . import status as status_mod
from .orchestrator import Orchestrator
from .store.db import Store
from .targets import split_qualified_target
from .store.workspace import (
    WorkspaceConfig,
    parse_targets,
    read_text,
    write_text,
    append_targets_section,
)


console = Console()


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _setup_logging(verbose: bool, log_path: Optional[Path] = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path)))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


def _resolve_workspace(workspace: Optional[str]) -> Path:
    """Resolve workspace path. Defaults to CWD."""
    if workspace:
        p = Path(workspace).expanduser().resolve()
    else:
        p = Path.cwd()
    if not (p / "config.toml").exists():
        raise click.ClickException(
            f"not a workspace: {p} (no config.toml). "
            "Run `autosearch init <name>` first or pass --workspace."
        )
    return p


@click.group()
@click.version_option(__version__, prog_name="autosearch")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
@click.option("-w", "--workspace", default=None,
              help="Workspace path (default: current directory).")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, workspace: Optional[str]) -> None:
    """Static memory-corruption code-audit pipeline driven by LLM agents."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["workspace_arg"] = workspace


# ------------------------------ init ------------------------------


@cli.command()
@click.argument("name")
@click.option("--target", "target_repo", required=True, type=click.Path(),
              help="Path to the target source repo (read-only).")
@click.option("--template", default=None,
              help=f"Starter template name (e.g. webkit-image-decoders).")
@click.option("--root", default="~/autosearch-workspaces",
              help="Workspaces root directory (default: ~/autosearch-workspaces).")
@click.option("--force", is_flag=True, help="Overwrite existing workspace dir.")
def init(name: str, target_repo: str, template: Optional[str],
         root: str, force: bool) -> None:
    """Create a new workspace.

    Example:
        autosearch init webkit-image-decoders \\
            --target ~/code/WebKit \\
            --template webkit-image-decoders
    """
    root_path = Path(root).expanduser().resolve()
    ws = root_path / name
    target = Path(target_repo).expanduser().resolve()
    if not target.exists():
        raise click.ClickException(f"target_repo does not exist: {target}")
    if ws.exists() and not force:
        raise click.ClickException(f"workspace already exists: {ws} (use --force)")
    if force and ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    (ws / "rules").mkdir()
    (ws / "logs" / "cycles").mkdir(parents=True)
    (ws / "reports").mkdir()

    # Drop the template files if requested
    if template:
        try:
            tdir = resources.files("autosearch").joinpath("..", "..", "templates", template)
        except Exception:
            tdir = None  # type: ignore
        # robust: walk the source-tree templates dir relative to package root
        pkg_root = Path(resources.files("autosearch")).resolve()
        tpl_root = pkg_root.parent.parent / "templates" / template
        if not tpl_root.exists():
            console.print(f"[yellow]template not found: {tpl_root}; creating empty workspace[/yellow]")
        else:
            for f in tpl_root.rglob("*"):
                if f.is_dir():
                    continue
                rel = f.relative_to(tpl_root)
                dst = ws / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, dst)
            console.print(f"[green]template applied: {template}[/green]")

    # Always ensure config.toml + rules files exist (even without template)
    cfg_path = ws / "config.toml"
    if not cfg_path.exists():
        cfg_path.write_text(
            f'target_repo = "{target}"\n'
            'target_branch = "main"\n'
            '\n'
            '# Hybrid cohort: cohort_methods × cohort_models_per_method = total auditor runs.\n'
            'cohort_methods           = 6\n'
            'cohort_models_per_method = 2\n'
            '\n'
            'cohort_models     = ["claude-opus-4.7", "gpt-5.4"]\n'
            'challenger_models = ["claude-opus-4.7", "gpt-5.4"]\n'
            'refinement_model  = "claude-opus-4.7"\n'
            '\n'
            'cycle_timeout_seconds        = 4500\n'
            'agent_timeout_seconds        = 1500\n'
            'pre_commit_challenge_enabled = true\n'
        )
    else:
        # Replace target_repo line if user supplied one different from template's
        cfg = cfg_path.read_text()
        new_cfg = []
        for line in cfg.splitlines():
            if line.strip().startswith("target_repo ="):
                new_cfg.append(f'target_repo = "{target}"')
            else:
                new_cfg.append(line)
        cfg_path.write_text("\n".join(new_cfg) + "\n")

    for f in ("targets.md", "rules/catalog.md", "rules/mitigations.md"):
        p = ws / f
        if not p.exists():
            write_text(p, f"# {f}\n")

    # Initialize the database
    store = Store.open(ws)
    store.set_target_repo(str(target))
    targets_md = read_text(ws / "targets.md", default="")
    rows = parse_targets(targets_md)
    if rows:
        store.replace_targets(rows)
    store.close()

    console.print(f"[bold green]workspace created: {ws}[/bold green]")
    console.print(f"  target_repo: {target}")
    console.print(f"  templates: {len(rows)} target methods loaded from targets.md")
    console.print("\nNext steps:")
    console.print(f"  cd {ws}")
    console.print(f"  autosearch run --once")


# ------------------------------ run ------------------------------


@cli.command()
@click.option("--once", "mode", flag_value="once", default=True,
              help="Run a single cycle and exit.")
@click.option("--cycles", "n_cycles", type=int, default=None,
              help="Run N cycles then exit.")
@click.option("--forever", "mode", flag_value="forever",
              help="Run cycles indefinitely (Ctrl-C to stop).")
@click.option("--target-method", default=None,
              help="Override: run a single auditor on this Class::Method or Class::Method(args) only.")
@click.pass_context
def run(ctx: click.Context, mode: str, n_cycles: Optional[int],
        target_method: Optional[str]) -> None:
    """Run the audit cycle (Phase 2)."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    log_path = ws / "logs" / "autosearch.log"
    _setup_logging(ctx.obj["verbose"], log_path=log_path)
    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )
    sw = status_mod.StatusWriter(ws / "logs" / "status.json")

    # Override cohort to single-target debug mode
    forced = None
    if target_method:
        split = split_qualified_target(target_method)
        if not split:
            raise click.ClickException("--target-method must be Class::Method or Class::Method(args)")
        cls, meth = split
        cfg.cohort_methods = 1
        cfg.cohort_models_per_method = 1
        cfg.cohort_models = cfg.cohort_models[:1]
        cfg.pre_commit_challenge_enabled = False
        # Insert a synthetic target row if missing so the targets table is consistent
        existing = store.conn.execute(
            "SELECT 1 FROM targets WHERE target_class=? AND target_method=?",
            (cls, meth)).fetchone()
        if not existing:
            store.conn.execute(
                "INSERT INTO targets (target_class, target_method, bug_class_hint, reason, campaign, sub_area, source_path) "
                "VALUES (?, ?, '', 'debug override', 'debug', '', '')",
                (cls, meth))
        forced = [{
            "target_class": cls, "target_method": meth,
            "bug_class_hint": "", "reason": "debug override",
            "campaign": "debug", "sub_area": "", "source_path": "",
        }]

    orch = Orchestrator(workspace=ws, config=cfg, store=store,
                         dispatcher=dispatcher, status_writer=sw,
                         force_targets=forced)

    # Clean Ctrl-C: kill all in-flight LLM subagents before exiting.
    # Without this, subprocess.Popen children outlive the orchestrator
    # because they ignore SIGINT (copilot CLI runs agentic loops). They
    # then drain their (paid) API calls for several minutes after the
    # operator thinks they've stopped the loop.
    import signal as _signal
    _shutdown_requested = {"flag": False}
    def _on_signal(signum, frame):
        if _shutdown_requested["flag"]:
            # Second Ctrl-C — give up gracefully and let Python's default
            # handler kick in (immediate exit on the next line).
            _signal.signal(signum, _signal.SIG_DFL)
            _signal.raise_signal(signum)
            return
        _shutdown_requested["flag"] = True
        n = dispatch_mod.terminate_all_active(grace_s=2.0)
        msg = f"\n[yellow]signal {signum} received; killed {n} subagent(s); exiting...[/yellow]"
        try:
            console.print(msg)
        except Exception:
            print(msg)
        # Re-raise as KeyboardInterrupt so the run loop's existing
        # except-clause exits cleanly.
        raise KeyboardInterrupt
    _signal.signal(_signal.SIGINT, _on_signal)
    _signal.signal(_signal.SIGTERM, _on_signal)

    if mode == "forever":
        loop_n = 0
        while True:
            loop_n += 1
            try:
                result = orch.run_cycle()
                console.print(f"[Cycle {result['cycle']}] score={result['score']} {result['breakdown']}")
            except KeyboardInterrupt:
                console.print("\n[yellow]interrupted[/yellow]")
                break
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]forever loop iteration {loop_n} failed: {e}[/red]")
                if ctx.obj["verbose"]:
                    raise
        store.close()
        return

    n = n_cycles if n_cycles else 1
    for _ in range(n):
        try:
            result = orch.run_cycle()
            console.print(f"[Cycle {result['cycle']}] score={result['score']} {result['breakdown']}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]cycle failed: {e}[/red]")
            if ctx.obj["verbose"]:
                raise
            break
    store.close()


# ------------------------------ findings ------------------------------


@cli.group()
def findings() -> None:
    """Inspect the findings corpus."""


@findings.command("list")
@click.option("--state", default=None, help="Filter by state.")
@click.option("--limit", default=20, type=int)
@click.pass_context
def findings_list(ctx: click.Context, state: Optional[str], limit: int) -> None:
    """List findings."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    if state:
        rows = store.claims_by_state(state, limit=limit)
    else:
        rows = list(store.conn.execute(
            "SELECT * FROM claims ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())
    table = Table(title=f"findings (state={state or 'any'})")
    table.add_column("id", justify="right")
    table.add_column("cycle", justify="right")
    table.add_column("state")
    table.add_column("class")
    table.add_column("method")
    table.add_column("bug_class")
    table.add_column("file:line")
    for r in rows:
        table.add_row(
            str(r["id"]),
            str(r["cycle_n"]),
            r["state"],
            r["target_class"] or "",
            r["target_method"] or "",
            r["bug_class"] or "",
            f"{r['unchecked_op_file']}:{r['unchecked_op_line']}",
        )
    console.print(table)
    store.close()


@findings.command("show")
@click.argument("finding_id", type=int)
@click.pass_context
def findings_show(ctx: click.Context, finding_id: int) -> None:
    """Show a finding's full payload, validations, and challenges."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    row = store.claim_by_id(finding_id)
    if not row:
        raise click.ClickException(f"no finding with id {finding_id}")
    d = dict(row)
    console.print_json(json.dumps(d, default=str))
    vs = list(store.conn.execute(
        "SELECT * FROM validations WHERE claim_id=? ORDER BY id", (finding_id,)
    ).fetchall())
    cs = list(store.conn.execute(
        "SELECT * FROM challenges WHERE claim_id=? ORDER BY id", (finding_id,)
    ).fetchall())
    console.print(f"\n[bold]validations:[/bold] {len(vs)}")
    for v in vs:
        console.print_json(json.dumps(dict(v), default=str))
    console.print(f"\n[bold]challenges:[/bold] {len(cs)}")
    for c in cs:
        console.print_json(json.dumps(dict(c), default=str))
    store.close()


@findings.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "markdown"]), default="json")
@click.option("--state", default="confirmed,settled", help="Comma-separated states.")
@click.pass_context
def findings_export(ctx: click.Context, fmt: str, state: str) -> None:
    """Export findings to stdout."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    states = [s.strip() for s in state.split(",")]
    placeholders = ",".join("?" * len(states))
    rows = list(store.conn.execute(
        f"SELECT * FROM claims WHERE state IN ({placeholders}) ORDER BY id",
        states,
    ).fetchall())
    if fmt == "json":
        click.echo(json.dumps([dict(r) for r in rows], indent=2, default=str))
    else:
        for r in rows:
            click.echo(f"## #{r['id']} {r['target_class']}::{r['target_method']}")
            click.echo(f"- state: {r['state']}")
            click.echo(f"- bug_class: {r['bug_class']}")
            click.echo(f"- file:line: {r['unchecked_op_file']}:{r['unchecked_op_line']}")
            click.echo(f"- severity: {r['severity']}")
            click.echo(f"\n{r['body']}\n")
    store.close()


@findings.command("cost")
@click.option("--since-cycles", type=int, default=None,
              help="Restrict to runs in the last N cycles (default: all-time).")
@click.option("--by", type=click.Choice(["agent", "model", "agent_model"]),
              default="agent_model",
              help="Group rows by agent, model, or both (default: both).")
@click.pass_context
def findings_cost(ctx: click.Context, since_cycles: Optional[int],
                   by: str) -> None:
    """Show cost / token / duration roll-up for agent runs.

    Tokens are CHARACTER-COUNT ESTIMATES (~4 chars/token). Cost rows
    marked `n/a` are runs whose model isn't in the pricing table —
    extend `src/autosearch/pricing.py:_MODEL_PRICING` to value them.
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    summary = store.cost_summary(since_cycles=since_cycles)

    # Re-aggregate to the requested grouping
    bucket_key = {
        "agent":       lambda r: (r["agent_name"], "*"),
        "model":       lambda r: ("*", r["model"]),
        "agent_model": lambda r: (r["agent_name"], r["model"]),
    }[by]
    buckets: dict[tuple[str, str], dict] = {}
    for r in summary["rows"]:
        k = bucket_key(r)
        b = buckets.setdefault(k, {
            "n_runs": 0, "prompt_tokens": 0, "completion_tokens": 0,
            "cost_usd": 0.0, "n_unknown_cost": 0, "duration_ms": 0,
        })
        b["n_runs"] += r["n_runs"]
        b["prompt_tokens"] += r["prompt_tokens"]
        b["completion_tokens"] += r["completion_tokens"]
        b["cost_usd"] += (r["cost_usd"] or 0.0)
        b["n_unknown_cost"] += r["n_unknown_cost"]
        b["duration_ms"] += r["duration_ms"]

    scope = f"last {since_cycles} cycles" if since_cycles else "all-time"
    console.print(f"\n[bold]Cost report ({scope})[/bold]")
    console.print(
        f"  total runs:   {summary['total_runs']}\n"
        f"  total cost:   [green]${summary['total_cost_usd']:.2f}[/green]"
        + (f"  [dim](+ {summary['total_unknown_cost_runs']} runs with unknown pricing)[/dim]"
           if summary['total_unknown_cost_runs'] else "")
    )

    if not buckets:
        console.print("  [dim]no agent runs yet[/dim]")
        store.close()
        return

    from rich.table import Table
    t = Table(show_header=True, header_style="bold")
    t.add_column("agent")
    t.add_column("model")
    t.add_column("runs", justify="right")
    t.add_column("in tok", justify="right")
    t.add_column("out tok", justify="right")
    t.add_column("cost $", justify="right")
    t.add_column("avg $/run", justify="right")
    t.add_column("dur (min)", justify="right")
    rows_sorted = sorted(buckets.items(), key=lambda kv: -kv[1]["cost_usd"])
    for (agent_name, model), b in rows_sorted:
        cost_str = (f"${b['cost_usd']:.2f}" if b["cost_usd"] > 0
                    else (f"[dim]n/a ({b['n_unknown_cost']})[/dim]"
                          if b["n_unknown_cost"] else "$0.00"))
        avg_str = (f"${b['cost_usd'] / b['n_runs']:.3f}" if b["cost_usd"] > 0
                   else "[dim]n/a[/dim]")
        t.add_row(
            agent_name, model,
            str(b["n_runs"]),
            f"{b['prompt_tokens']:,}",
            f"{b['completion_tokens']:,}",
            cost_str, avg_str,
            f"{b['duration_ms'] / 60_000:.1f}",
        )
    console.print(t)
    console.print(
        "[dim]Tokens are estimates (chars / 4). "
        "Pricing in src/autosearch/pricing.py.[/dim]"
    )
    store.close()


# ------------------------------ agent (debug inspect) ------------------------------


@cli.group()
def agent() -> None:
    """Inspect individual LLM agent runs (debug)."""


@agent.command("list")
@click.option("--cycle", default=None, type=int, help="Filter by cycle number.")
@click.option("--latest", is_flag=True, help="Filter to the latest cycle only.")
@click.option("--name", default=None,
              help="Filter by agent_name (auditor|validator|challenger|clean-check|refinement|threat-modeler|target-generator|scope-reviewer|analyst).")
@click.option("--model", default=None, help="Filter by model name.")
@click.option("--state", "parse_state", default=None,
              help="Filter by parse_status (ok|repaired|parse_failed|timeout|error).")
@click.option("--slot", default=None, help="Filter by slot (e.g. 'auditor/m1#a').")
@click.option("--limit", default=30, type=int)
@click.pass_context
def agent_list(ctx: click.Context, cycle: Optional[int], latest: bool,
               name: Optional[str], model: Optional[str],
               parse_state: Optional[str], slot: Optional[str], limit: int) -> None:
    """List recent agent runs.

    Combine filters to drill down. Examples:
      autosearch agent list --latest
      autosearch agent list --name auditor --state parse_failed
      autosearch agent list --cycle 8 --slot auditor/m1#a
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    where: list[str] = []
    params: list = []
    if cycle is not None:
        where.append("cycle_n = ?")
        params.append(cycle)
    elif latest:
        latest_n = store.conn.execute("SELECT MAX(n) AS n FROM cycles").fetchone()
        if latest_n and latest_n["n"] is not None:
            where.append("cycle_n = ?")
            params.append(latest_n["n"])
    if name:
        where.append("agent_name = ?")
        params.append(name)
    if model:
        where.append("model = ?")
        params.append(model)
    if parse_state:
        where.append("parse_status = ?")
        params.append(parse_state)
    if slot:
        where.append("slot LIKE ?")
        params.append(f"%{slot}%")
    where_clause = " WHERE " + " AND ".join(where) if where else ""
    sql = (
        "SELECT id, cycle_n, agent_name, slot, model, parse_status, "
        "       COALESCE(duration_ms, 0) AS dur_ms, parsed_json "
        f"FROM agent_runs{where_clause} ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)
    rows = list(store.conn.execute(sql, params).fetchall())
    table = Table(title=f"agent runs ({len(rows)} shown)")
    table.add_column("id", justify="right")
    table.add_column("cycle", justify="right")
    table.add_column("agent")
    table.add_column("slot")
    table.add_column("model")
    table.add_column("parse")
    table.add_column("dur", justify="right")
    table.add_column("target", overflow="ellipsis", max_width=36)
    for r in rows:
        target = ""
        try:
            if r["parsed_json"]:
                d = json.loads(r["parsed_json"])
                tc = d.get("target_class", "") or ""
                tm = d.get("target_method", "") or ""
                if tc and tm:
                    short_cls = tc.split("::")[-1]
                    target = f"{short_cls}::{tm}"
                elif d.get("kind") in ("validation", "challenge", "clean_check"):
                    target = f"({d.get('verdict','?')})"
                elif d.get("kind") in ("refinement", "analysis", "threat_model", "targets", "scope_review"):
                    target = f"({d.get('kind')})"
        except Exception:
            pass
        secs = (r["dur_ms"] or 0) // 1000
        dur = f"{secs}s" if secs < 60 else f"{secs // 60}m{secs % 60:02d}s"
        parse_color = {
            "ok": r["parse_status"],
            "repaired": f"[yellow]{r['parse_status']}[/yellow]",
            "parse_failed": f"[red]{r['parse_status']}[/red]",
            "timeout": f"[red]{r['parse_status']}[/red]",
            "error": f"[red]{r['parse_status']}[/red]",
        }.get(r["parse_status"], r["parse_status"])
        table.add_row(
            str(r["id"]), str(r["cycle_n"]), r["agent_name"],
            r["slot"] or "", r["model"], parse_color, dur, target,
        )
    console.print(table)
    store.close()


@agent.command("show")
@click.argument("agent_run_id", type=int)
@click.option("--format", "fmt", default="full",
              type=click.Choice(["full", "header", "prompt", "response", "parsed", "json"]),
              help="What to show. 'full' = all sections; 'header' = metadata only; "
                   "'prompt|response|parsed' = just that section to stdout (suitable for piping); "
                   "'json' = the entire row as a single JSON object.")
@click.option("--no-pager", is_flag=True, help="Don't truncate long output to fit terminal.")
@click.pass_context
def agent_show(ctx: click.Context, agent_run_id: int, fmt: str, no_pager: bool) -> None:
    """Show a specific agent run's prompt + response + parsed JSON.

    Examples:
      autosearch agent show 142
      autosearch agent show 142 --format prompt | less
      autosearch agent show 142 --format response | grep -A5 "json"
      autosearch agent show 142 --format parsed | jq .
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    row = store.conn.execute(
        "SELECT * FROM agent_runs WHERE id = ?", (agent_run_id,)
    ).fetchone()
    if not row:
        store.close()
        raise click.ClickException(f"no agent run with id {agent_run_id}")

    # Plain-text outputs for piping
    if fmt == "prompt":
        click.echo(row["rendered_prompt"] or "")
        store.close()
        return
    if fmt == "response":
        click.echo(row["raw_response"] or "")
        store.close()
        return
    if fmt == "parsed":
        if row["parsed_json"]:
            click.echo(json.dumps(json.loads(row["parsed_json"]), indent=2))
        else:
            click.echo(f"(no parsed JSON — parse_status: {row['parse_status']})", err=True)
        store.close()
        return
    if fmt == "json":
        d = dict(row)
        # parsed_json is stored as text; decode for cleaner output
        if d.get("parsed_json"):
            try:
                d["parsed_json"] = json.loads(d["parsed_json"])
            except Exception:
                pass
        click.echo(json.dumps(d, indent=2, default=str))
        store.close()
        return

    # Pretty header
    secs = (row["duration_ms"] or 0) // 1000
    dur = f"{secs}s" if secs < 60 else f"{secs // 60}m{secs % 60:02d}s"
    console.print(f"[b]ID:[/b]            {row['id']}")
    console.print(f"[b]Cycle:[/b]         {row['cycle_n']}")
    console.print(f"[b]Agent:[/b]         {row['agent_name']}")
    console.print(f"[b]Slot:[/b]          {row['slot']}")
    console.print(f"[b]Model:[/b]         {row['model']}")
    console.print(f"[b]CLI version:[/b]   {row['cli_version']}")
    console.print(f"[b]Started:[/b]       {row['started_at']}")
    console.print(f"[b]Ended:[/b]         {row['ended_at'] or '—'}")
    console.print(f"[b]Duration:[/b]      {dur}")
    parse_marker = {
        "ok": "[green]ok[/green]",
        "repaired": "[yellow]repaired[/yellow] (one-shot repair retry succeeded)",
        "parse_failed": "[red]parse_failed[/red]",
        "timeout": "[red]timeout[/red]",
        "error": "[red]error[/red]",
    }.get(row["parse_status"], row["parse_status"])
    console.print(f"[b]Parse status:[/b]  {parse_marker}")
    console.print(f"[b]Exit code:[/b]     {row['exit_code']}")
    if row["error_message"]:
        console.print(f"[b][red]Error:[/red][/b] {row['error_message']}")
    console.print(f"[b]Prompt hash:[/b]   {row['prompt_hash'][:16]}…")
    if fmt == "header":
        store.close()
        return

    prompt_len = len(row["rendered_prompt"] or "")
    response_len = len(row["raw_response"] or "")
    console.print()
    console.print(f"[b]=== Rendered prompt ({prompt_len} chars) ===[/b]")
    if no_pager or prompt_len < 8000:
        console.print(row["rendered_prompt"] or "(empty)")
    else:
        console.print(row["rendered_prompt"][:4000] + f"\n\n[dim]... [{prompt_len - 8000} chars elided] ...[/dim]\n\n" + row["rendered_prompt"][-4000:])
    console.print()
    console.print(f"[b]=== Raw response ({response_len} chars) ===[/b]")
    if no_pager or response_len < 8000:
        console.print(row["raw_response"] or "(empty)")
    else:
        console.print(row["raw_response"][:4000] + f"\n\n[dim]... [{response_len - 8000} chars elided] ...[/dim]\n\n" + row["raw_response"][-4000:])
    console.print()
    if row["parsed_json"]:
        console.print("[b]=== Parsed JSON ===[/b]")
        try:
            console.print_json(row["parsed_json"])
        except Exception:
            console.print(row["parsed_json"])
    else:
        console.print(f"[b]=== Parsed JSON ===[/b] [dim](none — parse_status: {row['parse_status']})[/dim]")
    store.close()


@agent.command("path")
@click.argument("agent_run_id", type=int)
@click.pass_context
def agent_path(ctx: click.Context, agent_run_id: int) -> None:
    """Print the per-cycle log file path for a given agent run.

    The log file is a JSON mirror of the DB row, useful for `less`/`jq`/grep.
    Example:
      $(autosearch agent path 142) | jq .parsed_json
      less $(autosearch agent path 142)
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    row = store.conn.execute(
        "SELECT id, cycle_n, agent_name, slot FROM agent_runs WHERE id = ?",
        (agent_run_id,),
    ).fetchone()
    if not row:
        store.close()
        raise click.ClickException(f"no agent run with id {agent_run_id}")
    cycle_dir = ws / "logs" / "cycles" / f"{row['cycle_n']:06d}"
    safe_slot = (row["slot"] or "").replace("/", "_").replace("#", "n").replace(":", "_")
    fname = f"{row['id']:05d}_{row['agent_name']}_{safe_slot}.json"
    p = cycle_dir / fname
    click.echo(str(p))
    if not p.exists():
        click.echo(f"[warn] file does not exist: {p}", err=True)
    store.close()


# ------------------------------ catalog / targets ------------------------------


@cli.command()
@click.option("--since-cycles", type=int, default=10,
              help="Compare current catalog vs N cycles ago.")
@click.pass_context
def catalog_diff(ctx: click.Context, since_cycles: int) -> None:
    """Show catalog evolution over the last N cycles."""
    import difflib
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    cur = store.latest_catalog()
    if not cur:
        console.print("[yellow]no catalog versions yet[/yellow]")
        store.close()
        return
    older = store.conn.execute(
        "SELECT * FROM catalog_versions WHERE id < ? ORDER BY id DESC LIMIT 1 OFFSET ?",
        (cur["id"], since_cycles),
    ).fetchone()
    if not older:
        console.print(f"[yellow]no catalog version from {since_cycles} cycles ago[/yellow]")
        store.close()
        return
    diff = difflib.unified_diff(
        older["body"].splitlines(keepends=True),
        cur["body"].splitlines(keepends=True),
        fromfile=f"catalog v{older['id']}",
        tofile=f"catalog v{cur['id']}",
    )
    sys.stdout.writelines(diff)
    store.close()


# ------------------------------ import-git ------------------------------


@cli.command("import-git")
@click.option("--from", "from_repo", required=True, type=click.Path(exists=True),
              help="Path to the source git repo (e.g. ~/code/WebKit).")
@click.option("--branch", default="HEAD", help="Branch or ref to import.")
@click.option("--materialize/--no-materialize", default=True,
              help="Also materialize claims/cleans/challenges (default: yes).")
@click.option("--dry-run", is_flag=True, help="Parse only; don't write derived rows.")
@click.pass_context
def import_git_cmd(ctx: click.Context, from_repo: str, branch: str,
                   materialize: bool, dry_run: bool) -> None:
    """Import legacy `[autosearch]` commits into raw_commits + materialize."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    store = Store.open(ws)
    repo = Path(from_repo).expanduser().resolve()
    console.print(f"[cyan]importing from {repo} ref={branch}...[/cyan]")
    counts = import_git_mod.import_branch(store, repo, branch)
    console.print(f"raw_commits: matched={counts['matched']} parsed={counts['parsed']} "
                  f"partial={counts['partial']} unparseable={counts['unparseable']}")
    if materialize:
        console.print("[cyan]materializing claims/cleans/challenges...[/cyan]")
        m = import_git_mod.materialize(store, dry_run=dry_run)
        console.print(f"materialized: {m}")
    store.close()


# ------------------------------ tui ------------------------------


@cli.command()
@click.pass_context
def tui(ctx: click.Context) -> None:
    """Launch the live monitor TUI."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    from .tui.app import run_tui
    run_tui(ws)


# ------------------------------ stubs (planned) ------------------------------


@cli.command("suggest-overlay")
@click.option("--area", "area_path", default=None,
              help="Path to the code area to model (relative to target_repo or absolute). "
                   "Required unless --apply-from is given.")
@click.option("--model", default=None,
              help="Model to dispatch (defaults to refinement_model).")
@click.option("--apply", "apply_flag", is_flag=True,
              help="After generating the proposal, also replace the existing "
                   "[prompt_overlay] block in <workspace>/config.toml. "
                   "Use this for one-shot generate+apply.")
@click.option("--apply-from", "apply_from", default=None,
              type=click.Path(exists=True),
              help="Apply a previously-generated overlay proposal to config.toml WITHOUT "
                   "calling the LLM again. Pass either the .json or .toml proposal path "
                   "saved under <workspace>/threat-models/overlay-proposal-*. "
                   "Mutually exclusive with --area / --apply.")
@click.option("--include", "include_exts", default="idl,h",
              help="Extensions to walk for context (default: 'idl,h').")
@click.option("--max-context-files", type=int, default=80,
              help="Soft cap on files surveyed for context (default: 80).")
@click.option("--batch-size", type=int, default=30,
              help="Max IDL+header files per LLM call. When total files exceed this, "
                   "dispatches multiple batches in parallel and merges results. (default: 30)")
@click.option("--pool", type=int, default=6,
              help="Max parallel batch workers (default: 6).")
@click.pass_context
def suggest_overlay(ctx: click.Context, area_path: Optional[str], model: Optional[str],
                    apply_flag: bool, apply_from: Optional[str],
                    include_exts: str, max_context_files: int,
                    batch_size: int, pool: int) -> None:
    """Suggest a [prompt_overlay] block from an area's IDL + headers.

    Three modes:

      Generate (default): walks <--area>, dispatches overlay-suggester
      LLM call(s), saves the proposal under <workspace>/threat-models/,
      prints to stdout. With --apply also writes to config.toml.

      When the area has more IDL+header files than --batch-size (default 30),
      files are split into batches and dispatched in parallel. A final merge
      LLM call combines and deduplicates the partial overlays.

      Apply-from: takes a previously-generated proposal (.json or .toml)
      and writes it to config.toml. NO LLM call. Use this after reviewing
      a proposal you generated earlier — avoids paying for the suggester
      twice.

    Examples:
      # Generate + review
      autosearch suggest-overlay --area Source/WebCore/Modules/webcodecs/

      # Large area with batching (e.g. 145 IDL files)
      autosearch suggest-overlay --area Source/WebCore/Modules/WebGPU/ --batch-size 30 --pool 8

      # Apply a reviewed proposal — no LLM call
      autosearch suggest-overlay --apply-from threat-models/overlay-proposal-20260501T203310Z.json

      # One-shot: generate + apply in one command
      autosearch suggest-overlay --area Source/WebCore/Modules/webcodecs/ --apply
    """
    import re

    # Validate flag combos
    if apply_from and (area_path or apply_flag):
        raise click.ClickException(
            "--apply-from is mutually exclusive with --area / --apply"
        )
    if not apply_from and not area_path:
        raise click.ClickException(
            "Either --area (to generate) or --apply-from (to apply a saved proposal) is required"
        )

    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")

    # ------------------ APPLY-FROM PATH (no LLM call) ------------------
    if apply_from:
        ap = Path(apply_from).expanduser().resolve()
        if not ap.is_file():
            raise click.ClickException(f"--apply-from path is not a file: {ap}")
        # Accept .json (parsed and re-serialized to TOML) or .toml (used verbatim)
        toml_block: str
        if ap.suffix.lower() == ".json":
            try:
                proposal = json.loads(ap.read_text())
            except Exception as e:
                raise click.ClickException(f"--apply-from JSON parse failed: {e}")
            if proposal.get("kind") not in ("overlay",):
                raise click.ClickException(
                    f"--apply-from JSON has kind={proposal.get('kind')!r}; expected 'overlay'"
                )
            for key in ("attacker_surface", "scope_includes", "extra_out_of_scope"):
                if key not in proposal:
                    raise click.ClickException(
                        f"--apply-from JSON missing required field {key!r}"
                    )
            def _e(s: str) -> str:
                return s.replace('"""', '\\"\\"\\"')
            toml_block = (
                "[prompt_overlay]\n\n"
                f'attacker_surface = """{_e(proposal["attacker_surface"])}"""\n\n'
                f'scope_includes = """{_e(proposal["scope_includes"])}"""\n\n'
                f'extra_out_of_scope = """{_e(proposal["extra_out_of_scope"])}"""\n'
            )
        elif ap.suffix.lower() == ".toml":
            toml_block = ap.read_text().strip() + "\n"
            if "[prompt_overlay]" not in toml_block:
                raise click.ClickException(
                    "--apply-from TOML file does not contain a [prompt_overlay] section"
                )
            # Trim leading content before [prompt_overlay] (defensive)
            idx = toml_block.find("[prompt_overlay]")
            if idx > 0:
                toml_block = toml_block[idx:]
        else:
            raise click.ClickException(
                f"--apply-from must be a .json or .toml file (got {ap.suffix!r})"
            )

        cfg_path = ws / "config.toml"
        cfg_text = cfg_path.read_text()
        overlay_start = cfg_text.find("[prompt_overlay]")
        if overlay_start >= 0:
            new_cfg = cfg_text[:overlay_start].rstrip() + "\n\n" + toml_block
        else:
            new_cfg = cfg_text.rstrip() + "\n\n" + toml_block
        backup = ws / "config.toml.bak"
        backup.write_text(cfg_text)
        cfg_path.write_text(new_cfg)
        console.print(
            f"[green]applied[/green]: {cfg_path} updated from {ap.name}\n"
            f"[dim]backup:[/dim] {backup}\n"
            f"[dim]LLM calls used:[/dim] 0\n\n"
            "Restart `autosearch run --forever` to pick up the new overlay."
        )
        return

    # ------------------ GENERATE PATH (batched LLM calls) ------------------
    import shlex
    import subprocess as _sub
    from concurrent.futures import ThreadPoolExecutor, as_completed

    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )
    chosen_model = model or cfg.refinement_model

    area_p = Path(area_path).expanduser()
    if not area_p.is_absolute():
        area_p = (cfg.target_repo / area_p).resolve()
    if not area_p.exists() or not area_p.is_dir():
        raise click.ClickException(f"--area must be an existing directory: {area_p}")

    include_set = {e.strip().lstrip(".").lower() for e in include_exts.split(",") if e.strip()}
    idl_files: list[Path] = []
    public_headers: list[Path] = []
    for f in sorted(area_p.iterdir()):
        if not f.is_file():
            continue
        ext = f.suffix.lstrip(".").lower()
        if ext == "idl":
            idl_files.append(f)
        elif ext in include_set and ext != "idl":
            public_headers.append(f)
    public_headers = public_headers[:max_context_files]

    readme_paths: list[Path] = []
    for cand in [area_p / "README.md", area_p / "README", area_p / "DESIGN.md",
                 area_p.parent / "README.md"]:
        if cand.exists() and cand.is_file():
            readme_paths.append(cand)

    cross_dir_lines: list[str] = []
    try:
        result = _sub.run(
            ["grep", "-rhn", "--include=*.h", "--include=*.cpp", "--include=*.mm",
             r'^#include "', str(area_p)],
            capture_output=True, text=True, timeout=30,
        )
        seen: set[str] = set()
        for line in (result.stdout or "").splitlines():
            m = re.search(r'#include "([^"]+)"', line)
            if not m:
                continue
            inc = m.group(1)
            if "/" not in inc:
                continue
            if inc in seen:
                continue
            seen.add(inc)
            cross_dir_lines.append(inc)
            if len(cross_dir_lines) >= 80:
                break
    except Exception:
        pass

    cfg_text = (ws / "config.toml").read_text()
    overlay_start = cfg_text.find("[prompt_overlay]")
    if overlay_start >= 0:
        current_overlay = cfg_text[overlay_start:].strip()
    else:
        current_overlay = "(empty)"

    def _rel(p: Path) -> str:
        try:
            return str(p.relative_to(cfg.target_repo))
        except ValueError:
            return str(p)

    stamp = _utc_stamp()
    log_dir = ws / "logs" / "out-of-band" / f"suggest-overlay-{stamp}"

    all_context_files = idl_files + public_headers
    total_files = len(all_context_files)
    needs_batching = total_files > batch_size

    console.print(
        f"[cyan]Surveying {_rel(area_p)}:[/cyan]\n"
        f"  IDL files:     {len(idl_files)}\n"
        f"  Headers:       {len(public_headers)}\n"
        f"  READMEs:       {len(readme_paths)}\n"
        f"  Cross-dir incs: {len(cross_dir_lines)}\n"
        f"  Current overlay: {'present' if current_overlay != '(empty)' else 'EMPTY'}\n"
        f"  Batch mode:    {'YES — ' + str((total_files + batch_size - 1) // batch_size) + ' batches of ~' + str(batch_size) if needs_batching else 'no (fits in one call)'}\n"
    )

    if not needs_batching:
        # ---- Single-call path (original behavior) ----
        ctx_dict = {
            "TARGET_REPO": str(cfg.target_repo),
            "AREA": _rel(area_p),
            "IDL_FILES": "\n".join(f"- {_rel(p)}" for p in idl_files) or "(none — area has no IDL)",
            "PUBLIC_HEADERS": "\n".join(f"- {_rel(p)}" for p in public_headers) or "(none)",
            "README_PATHS": "\n".join(f"- {_rel(p)}" for p in readme_paths) or "(none)",
            "CROSS_DIR_INCLUDES": "\n".join(f"- {l}" for l in cross_dir_lines) or "(none surfaced)",
            "CURRENT_OVERLAY": current_overlay,
            **cfg.overlay_ctx(),
        }

        console.print(f"[cyan]Dispatching overlay-suggester ({chosen_model})...[/cyan]")
        res = agent_invoke.invoke(
            store=store, dispatcher=dispatcher,
            agent_name="overlay-suggester",
            slot=f"suggest-overlay-{stamp}",
            model=chosen_model, ctx=ctx_dict, cycle_n=None,
            target_repo=cfg.target_repo,
            agent_timeout_s=cfg.agent_timeout_seconds,
            log_dir=log_dir,
        )
        if not res["parsed"]:
            store.close()
            raise click.ClickException(
                f"overlay-suggester returned no parseable JSON. See {log_dir}."
            )
        parsed = res["parsed"]
    else:
        # ---- Batched path: split files, dispatch in parallel, merge ----
        batches: list[list[Path]] = []
        for i in range(0, total_files, batch_size):
            batches.append(all_context_files[i:i + batch_size])

        console.print(
            f"[cyan]Dispatching {len(batches)} batch overlay-suggesters "
            f"(pool={pool}, model={chosen_model})...[/cyan]"
        )

        def _run_batch(batch_idx: int, batch_files: list[Path]) -> Optional[dict]:
            batch_idls = [f for f in batch_files if f.suffix.lower() == ".idl"]
            batch_hdrs = [f for f in batch_files if f.suffix.lower() != ".idl"]
            batch_log = log_dir / f"batch-{batch_idx}"
            batch_ctx = {
                "TARGET_REPO": str(cfg.target_repo),
                "AREA": _rel(area_p),
                "IDL_FILES": "\n".join(f"- {_rel(p)}" for p in batch_idls) or "(none in this batch)",
                "PUBLIC_HEADERS": "\n".join(f"- {_rel(p)}" for p in batch_hdrs) or "(none in this batch)",
                "README_PATHS": "\n".join(f"- {_rel(p)}" for p in readme_paths) or "(none)",
                "CROSS_DIR_INCLUDES": "\n".join(f"- {l}" for l in cross_dir_lines) or "(none surfaced)",
                "CURRENT_OVERLAY": f"(batch {batch_idx + 1}/{len(batches)} — partial generation, will be merged)",
                **cfg.overlay_ctx(),
            }
            r = agent_invoke.invoke(
                store=store, dispatcher=dispatcher,
                agent_name="overlay-suggester",
                slot=f"suggest-overlay-{stamp}-batch{batch_idx}",
                model=chosen_model, ctx=batch_ctx, cycle_n=None,
                target_repo=cfg.target_repo,
                agent_timeout_s=cfg.agent_timeout_seconds,
                log_dir=batch_log,
            )
            return r.get("parsed")

        partial_overlays: list[dict] = []
        with ThreadPoolExecutor(max_workers=pool) as tp:
            futures = {
                tp.submit(_run_batch, i, b): i
                for i, b in enumerate(batches)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    result_parsed = fut.result()
                    if result_parsed and result_parsed.get("kind") == "overlay":
                        partial_overlays.append(result_parsed)
                        console.print(f"  [green]batch {idx + 1}/{len(batches)}[/green] ✓")
                    else:
                        console.print(f"  [yellow]batch {idx + 1}/{len(batches)}[/yellow] — no overlay / parse failed")
                except Exception as e:
                    console.print(f"  [red]batch {idx + 1}/{len(batches)}[/red] — error: {e}")

        if not partial_overlays:
            store.close()
            raise click.ClickException(
                f"All {len(batches)} batches failed to produce overlays. See {log_dir}."
            )

        console.print(
            f"\n[cyan]{len(partial_overlays)}/{len(batches)} batches succeeded. "
            f"Dispatching merge+dedup ({chosen_model})...[/cyan]"
        )

        # Build merge prompt: feed all partial overlays to a final LLM call
        partials_text = ""
        for i, po in enumerate(partial_overlays):
            partials_text += f"\n--- Partial overlay {i + 1}/{len(partial_overlays)} ---\n"
            partials_text += f"attacker_surface:\n{po.get('attacker_surface', '')}\n\n"
            partials_text += f"scope_includes:\n{po.get('scope_includes', '')}\n\n"
            partials_text += f"extra_out_of_scope:\n{po.get('extra_out_of_scope', '')}\n"

        merge_ctx = {
            "TARGET_REPO": str(cfg.target_repo),
            "AREA": _rel(area_p),
            "IDL_FILES": f"({len(idl_files)} IDL files processed across {len(batches)} batches)",
            "PUBLIC_HEADERS": f"({len(public_headers)} header files processed across {len(batches)} batches)",
            "README_PATHS": "\n".join(f"- {_rel(p)}" for p in readme_paths) or "(none)",
            "CROSS_DIR_INCLUDES": "\n".join(f"- {l}" for l in cross_dir_lines) or "(none surfaced)",
            "CURRENT_OVERLAY": (
                f"MERGE MODE: {len(partial_overlays)} partial overlays were generated from batches of "
                f"{batch_size} files each. Your job is to MERGE and DEDUPLICATE them into one "
                f"coherent overlay. Remove duplicate entries, merge related trust classifications, "
                f"and produce a single unified overlay.\n\n"
                f"PARTIAL OVERLAYS TO MERGE:\n{partials_text}"
            ),
            **cfg.overlay_ctx(),
        }

        merge_log = log_dir / "merge"
        res = agent_invoke.invoke(
            store=store, dispatcher=dispatcher,
            agent_name="overlay-suggester",
            slot=f"suggest-overlay-{stamp}-merge",
            model=chosen_model, ctx=merge_ctx, cycle_n=None,
            target_repo=cfg.target_repo,
            agent_timeout_s=cfg.agent_timeout_seconds,
            log_dir=merge_log,
        )
        if not res["parsed"]:
            store.close()
            raise click.ClickException(
                f"Merge overlay-suggester returned no parseable JSON. See {merge_log}."
            )
        parsed = res["parsed"]

    if parsed.get("kind") == "no_overlay":
        console.print(f"[yellow]NO_OVERLAY[/yellow] for {parsed.get('area','')}: {parsed.get('reason','')}")
        store.close()
        return

    def _toml_escape(s: str) -> str:
        return s.replace('"""', '\\"\\"\\"')

    toml_block = (
        "[prompt_overlay]\n\n"
        f'attacker_surface = """{_toml_escape(parsed["attacker_surface"])}"""\n\n'
        f'scope_includes = """{_toml_escape(parsed["scope_includes"])}"""\n\n'
        f'extra_out_of_scope = """{_toml_escape(parsed["extra_out_of_scope"])}"""\n'
    )

    out_dir = ws / "threat-models"
    out_dir.mkdir(parents=True, exist_ok=True)
    proposal_path = out_dir / f"overlay-proposal-{stamp}.toml"
    proposal_path.write_text(toml_block)
    json_path = out_dir / f"overlay-proposal-{stamp}.json"
    json_path.write_text(json.dumps(parsed, indent=2))

    console.print(f"\n[bold]Rationale:[/bold]\n{parsed.get('rationale','')}\n")
    console.print(f"[bold]Diff from current:[/bold]\n{parsed.get('diff_from_current','')}\n")

    if not apply_flag:
        console.print("[bold]Proposed [prompt_overlay] block:[/bold]\n")
        console.print(toml_block)
        console.print(
            f"\n[dim]Saved to:[/dim] {proposal_path}\n"
            f"[dim]Saved JSON:[/dim] {json_path}\n\n"
            f"To apply later WITHOUT another LLM call:\n"
            f"  autosearch suggest-overlay --apply-from {json_path}"
        )
        store.close()
        return

    # --apply: rewrite config.toml replacing the existing [prompt_overlay] block
    cfg_path = ws / "config.toml"
    if overlay_start >= 0:
        new_cfg = cfg_text[:overlay_start].rstrip() + "\n\n" + toml_block
    else:
        new_cfg = cfg_text.rstrip() + "\n\n" + toml_block
    backup = ws / "config.toml.bak"
    backup.write_text(cfg_text)
    cfg_path.write_text(new_cfg)
    console.print(
        f"[green]applied[/green]: {cfg_path} updated\n"
        f"[dim]backup:[/dim] {backup}\n"
        f"[dim]proposal saved:[/dim] {proposal_path}\n\n"
        "Restart `autosearch run --forever` to pick up the new overlay."
    )
    store.close()


@cli.command("threat-model")
@click.argument("paths", nargs=-1, required=True)
@click.option("--model", default=None,
              help="Model to dispatch (defaults to refinement_model).")
@click.option("--name", default=None,
              help="Name for the saved threat model (default: derived from first path).")
@click.option("--per-file", "per_file", is_flag=True,
              help="Dispatch one threat-modeler PER FILE in parallel (vs one over all paths).")
@click.option("--include", "include_exts", default="cpp,mm,cc",
              help="Comma-separated extensions to walk when --per-file gets a directory "
                   "(default: 'cpp,mm,cc' — covers C++ across all WebKit ports including "
                   "Apple-platform .mm files). Examples: 'cpp', 'cpp,mm', 'cpp,h,mm,cc'.")
@click.option("--recursive/--no-recursive", default=False,
              help="When --per-file gets a directory, walk subdirectories too (default: off).")
@click.option("--max-files", type=int, default=200,
              help="Hard cap on per-file dispatch count (safety net for accidental large walks).")
@click.option("--pool", type=int, default=20,
              help="Max parallel threat-modeler workers (default: 20). "
                   "Lower this (e.g. --pool 6) when running concurrently with "
                   "`autosearch run --forever` to avoid copilot rate limits.")
@click.pass_context
def threat_model(ctx: click.Context, paths: tuple[str, ...],
                 model: Optional[str], name: Optional[str], per_file: bool,
                 include_exts: str, recursive: bool, max_files: int,
                 pool: int) -> None:
    """Run the threat-modeler agent on a code area (Phase 1 step 1).

    Two modes:

      Default (single-shot): one LLM call sees all PATHS at once. Good for
      small areas (<~5KLOC) where everything fits in one model context.

      --per-file (multi-pass): expands PATHS to individual files and
      dispatches ONE threat-modeler per file in parallel. Each call sees
      its single file deeply. Results are saved under
      <workspace>/threat-models/<name>-<timestamp>/<file>.json. Use
      `autosearch generate-targets --aggregate <dir>/*.json --apply` to
      merge them into targets.md.

      In --per-file mode, PATHS may be:
        - explicit files                   (foo.cpp bar.cpp)
        - shell globs                      (*.cpp — your shell expands)
        - quoted globs                     ("Source/X/*.cpp" — autosearch expands)
        - DIRECTORIES                      (Source/X/Y/) → walked for --include exts
        - relative or absolute paths
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")
    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )
    chosen_model = model or cfg.refinement_model
    stamp = _utc_stamp()
    out_dir = ws / "threat-models"
    out_dir.mkdir(parents=True, exist_ok=True)

    if name is None:
        first = Path(paths[0]).name.replace("/", "_") or "area"
        name = first

    if not per_file:
        # ------ Single-shot mode (original behavior) ------
        code_paths_block = "\n".join(f"- {p}" for p in paths)
        ctx_dict = {
            "TARGET_REPO": str(cfg.target_repo),
            "CODE_PATHS": code_paths_block,
            "CATALOG": read_text(ws / "rules" / "catalog.md"),
            "MITIGATIONS": read_text(ws / "rules" / "mitigations.md"),
            "TARGETS": read_text(ws / "targets.md"),
            **cfg.overlay_ctx(),
        }
        out_path = out_dir / f"{name}-{stamp}.json"
        log_dir = ws / "logs" / "out-of-band" / f"threat-model-{stamp}"
        console.print(f"[cyan]dispatching threat-modeler ({chosen_model}) on {len(paths)} path(s)...[/cyan]")
        res = agent_invoke.invoke(
            store=store, dispatcher=dispatcher,
            agent_name="threat-modeler",
            slot=f"threat-model-{stamp}",
            model=chosen_model, ctx=ctx_dict, cycle_n=None,
            target_repo=cfg.target_repo,
            agent_timeout_s=cfg.agent_timeout_seconds,
            log_dir=log_dir,
        )
        if not res["parsed"]:
            store.close()
            raise click.ClickException(
                f"threat-modeler returned no parseable JSON (status={res['parse_status']}). "
                f"See {log_dir} for the raw response."
            )
        out_path.write_text(json.dumps(res["parsed"], indent=2))
        parsed = res["parsed"]
        if parsed.get("kind") == "no_threat_model":
            console.print(f"[yellow]NO_THREAT_MODEL[/yellow] for area '{parsed.get('area','')}': {parsed.get('reason','')}")
        else:
            console.print(
                f"[green]threat model saved[/green]: {out_path}\n"
                f"  area: {parsed.get('area','')}\n"
                f"  entry_points: {len(parsed.get('entry_points', []))}   "
                f"corruption_sinks: {len(parsed.get('corruption_sinks', []))}   "
                f"candidate_methods: {len(parsed.get('candidate_methods', []))}"
            )
        store.close()
        return

    # ------ Per-file mode (parallel) ------
    import concurrent.futures as _cf
    import glob as _glob

    # Normalize the --include extension set
    include_set = {e.strip().lstrip(".").lower() for e in include_exts.split(",") if e.strip()}
    if not include_set:
        include_set = {"cpp"}

    def _is_included_file(p: Path) -> bool:
        return p.is_file() and p.suffix.lstrip(".").lower() in include_set

    # Expand each path into a concrete file list:
    #   directory  → walk (recursive or top-level), filter by --include
    #   file       → take as-is
    #   glob/other → try glob.glob() against absolute or target_repo-relative
    expanded: list[Path] = []
    for raw in paths:
        pp = (cfg.target_repo / raw) if not Path(raw).is_absolute() else Path(raw)
        if pp.is_dir():
            walker = pp.rglob("*") if recursive else pp.iterdir()
            for f in walker:
                if _is_included_file(f):
                    expanded.append(f)
        elif pp.is_file():
            expanded.append(pp)
        else:
            # Treat as glob pattern (covers quoted globs that the shell didn't expand)
            for g in _glob.glob(str(pp)):
                gp = Path(g)
                if gp.is_dir():
                    walker = gp.rglob("*") if recursive else gp.iterdir()
                    for f in walker:
                        if _is_included_file(f):
                            expanded.append(f)
                elif gp.is_file():
                    expanded.append(gp)

    expanded = sorted(set(expanded))
    if not expanded:
        raise click.ClickException(
            f"--per-file: no files matched {paths!r} (include={sorted(include_set)}, "
            f"recursive={recursive}, target_repo={cfg.target_repo})"
        )
    if len(expanded) > max_files:
        sample = "\n  ".join(str(p.relative_to(cfg.target_repo) if str(p).startswith(str(cfg.target_repo)) else p)
                              for p in expanded[:5])
        raise click.ClickException(
            f"--per-file: matched {len(expanded)} files, exceeds --max-files={max_files}. "
            f"First 5:\n  {sample}\n  ...\n"
            f"If intentional, re-run with --max-files {len(expanded)}."
        )

    out_subdir = out_dir / f"{name}-{stamp}"
    out_subdir.mkdir(parents=True, exist_ok=True)
    log_dir = ws / "logs" / "out-of-band" / f"threat-model-perfile-{stamp}"
    log_dir.mkdir(parents=True, exist_ok=True)

    catalog = read_text(ws / "rules" / "catalog.md")
    mitigations = read_text(ws / "rules" / "mitigations.md")
    targets = read_text(ws / "targets.md")
    overlay = cfg.overlay_ctx()

    console.print(
        f"[cyan]dispatching {len(expanded)} threat-modelers "
        f"(pool={pool}, model={chosen_model})...[/cyan]"
    )

    def work(idx_path: tuple[int, Path]) -> dict:
        idx, fpath = idx_path
        rel = fpath.relative_to(cfg.target_repo) if str(fpath).startswith(str(cfg.target_repo)) else fpath
        ctx_dict = {
            "TARGET_REPO": str(cfg.target_repo),
            "CODE_PATHS": f"- {rel}",
            "CATALOG": catalog,
            "MITIGATIONS": mitigations,
            "TARGETS": targets,
            **overlay,
        }
        slot = f"threat-model-perfile/{rel.name}"
        res = agent_invoke.invoke(
            store=store, dispatcher=dispatcher,
            agent_name="threat-modeler",
            slot=slot, model=chosen_model, ctx=ctx_dict, cycle_n=None,
            target_repo=cfg.target_repo,
            agent_timeout_s=cfg.agent_timeout_seconds,
            log_dir=log_dir,
        )
        # Save per-file result regardless of parse outcome (for forensics)
        safe_name = str(rel).replace("/", "_")
        out_file = out_subdir / f"{safe_name}.json"
        if res["parsed"]:
            out_file.write_text(json.dumps(res["parsed"], indent=2))
        else:
            out_file.write_text(json.dumps({
                "kind": "parse_failed", "file": str(rel),
                "parse_status": res["parse_status"],
                "agent_run_id": res["agent_run_id"],
            }, indent=2))
        return {"file": str(rel), "out_file": str(out_file), **res}

    with _cf.ThreadPoolExecutor(max_workers=min(len(expanded), max(1, pool))) as ex:
        futures = [ex.submit(work, (i, p)) for i, p in enumerate(expanded)]
        results = [f.result() for f in futures]

    n_ok = sum(1 for r in results if r["parsed"])
    n_failed = sum(1 for r in results if not r["parsed"])
    n_no_model = sum(1 for r in results if r["parsed"] and r["parsed"].get("kind") == "no_threat_model")
    n_with_model = n_ok - n_no_model
    total_methods = sum(
        len((r["parsed"] or {}).get("candidate_methods", []))
        for r in results if r["parsed"]
    )
    console.print(
        f"[green]per-file threat-modeling complete[/green]: "
        f"{n_with_model} threat models, {n_no_model} no_threat_model, "
        f"{n_failed} parse_failed → {total_methods} total candidate methods\n"
        f"  saved to: {out_subdir}/\n"
        f"  next: autosearch generate-targets --aggregate '{out_subdir}/*.json' --apply"
    )
    store.close()


@cli.command("generate-targets")
@click.option("--from-threat-model", "tm_path", default=None,
              type=click.Path(exists=True),
              help="Path to a single saved threat model JSON.")
@click.option("--aggregate", "aggregate_pattern", default=None,
              help="Glob pattern matching multiple per-file threat models "
                   "(from `threat-model --per-file`). Aggregates them into one merged "
                   "input for target-generator. Mutually exclusive with --from-threat-model.")
@click.option("--model", default=None,
              help="Model to dispatch (defaults to refinement_model).")
@click.option("--apply", "apply_flag", is_flag=True,
              help="Append the generated section to workspace targets.md.")
@click.pass_context
def generate_targets(ctx: click.Context, tm_path: Optional[str],
                     aggregate_pattern: Optional[str],
                     model: Optional[str], apply_flag: bool) -> None:
    """Run target-generator on a saved threat model (Phase 1 step 2).

    Two input modes:
      --from-threat-model FILE      single threat model
      --aggregate '<dir>/*.json'    multiple per-file threat models, merged
    """
    if not tm_path and not aggregate_pattern:
        raise click.ClickException(
            "specify --from-threat-model FILE or --aggregate '<glob>'"
        )
    if tm_path and aggregate_pattern:
        raise click.ClickException(
            "--from-threat-model and --aggregate are mutually exclusive"
        )

    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")
    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )

    # ---------- Build the threat-model input ----------
    if tm_path:
        tm = json.loads(Path(tm_path).read_text())
        if tm.get("kind") not in ("threat_model", "no_threat_model"):
            raise click.ClickException(
                f"input does not look like a threat-modeler output (kind={tm.get('kind')!r})"
            )
        if tm.get("kind") == "no_threat_model":
            console.print("[yellow]threat model is NO_THREAT_MODEL; nothing to generate[/yellow]")
            store.close()
            return
    else:
        # Aggregate mode: glob for per-file threat models, merge into one synthetic threat model
        import glob as _glob
        files = sorted(_glob.glob(aggregate_pattern))
        if not files:
            raise click.ClickException(f"--aggregate: no files match {aggregate_pattern!r}")
        per_file_tms: list[dict] = []
        skipped = 0
        for f in files:
            try:
                data = json.loads(Path(f).read_text())
            except Exception:
                skipped += 1
                continue
            if data.get("kind") not in ("threat_model",):
                skipped += 1
                continue
            per_file_tms.append(data)
        if not per_file_tms:
            raise click.ClickException(
                f"--aggregate: matched {len(files)} files but none were threat_model "
                f"(skipped {skipped} that were no_threat_model / parse_failed / bad json)"
            )
        # Merge: concatenate all list-typed sections, dedupe candidate_methods by (method, bug_class)
        merged: dict = {
            "kind": "threat_model",
            "area": f"aggregated from {len(per_file_tms)} per-file threat models ({aggregate_pattern})",
            "paths": [],
            "assets": [],
            "entry_points": [],
            "trust_boundaries": [],
            "attacker_controlled_values": [],
            "corruption_sinks": [],
            "invariants": [],
            "candidate_methods": [],
            "dedup_notes": [],
        }
        seen_methods: set[tuple[str, str]] = set()
        for tm in per_file_tms:
            for k in ("paths", "assets", "entry_points", "trust_boundaries",
                      "attacker_controlled_values", "corruption_sinks",
                      "invariants", "dedup_notes"):
                merged[k].extend(tm.get(k, []) or [])
            for cm in tm.get("candidate_methods", []) or []:
                key = (cm.get("method", ""), cm.get("bug_class", ""))
                if key in seen_methods:
                    continue
                seen_methods.add(key)
                merged["candidate_methods"].append(cm)
        console.print(
            f"[cyan]aggregated {len(per_file_tms)} per-file threat models "
            f"({skipped} skipped) → {len(merged['candidate_methods'])} unique candidate methods, "
            f"{len(merged['corruption_sinks'])} sinks[/cyan]"
        )

        # --- Batched generation for large inputs ---
        BATCH_THRESHOLD = 30   # max candidate_methods per single LLM call
        if len(merged["candidate_methods"]) > BATCH_THRESHOLD:
            console.print(
                f"[yellow]candidate count ({len(merged['candidate_methods'])}) exceeds "
                f"threshold ({BATCH_THRESHOLD}); using batched generation[/yellow]"
            )

            # Pass 0: deterministic dedup already done above via seen_methods

            # Pass 1: batch by subsystem, then by size
            from collections import defaultdict as _defaultdict
            subsystem_groups: dict[str, list[dict]] = _defaultdict(list)
            for cm in merged["candidate_methods"]:
                # Group by file path prefix
                method = cm.get("method", "")
                # Extract subsystem from method namespace or file hints
                parts = method.split("::")
                subsystem = parts[0] if len(parts) >= 2 else "other"
                subsystem_groups[subsystem].append(cm)

            # Split groups that exceed batch size
            batches: list[list[dict]] = []
            for subsystem, candidates in sorted(subsystem_groups.items()):
                while len(candidates) > BATCH_THRESHOLD:
                    batches.append(candidates[:BATCH_THRESHOLD])
                    candidates = candidates[BATCH_THRESHOLD:]
                if candidates:
                    batches.append(candidates)

            console.print(
                f"[cyan]split into {len(batches)} batches "
                f"(sizes: {', '.join(str(len(b)) for b in batches)})[/cyan]"
            )

            # Dispatch one target-generator per batch (recall-oriented)
            all_parsed_results: list[dict] = []
            failed_batches: list[int] = []
            chosen_model = model or cfg.refinement_model
            stamp = _utc_stamp()
            existing_targets = read_text(ws / "targets.md")

            for batch_idx, batch_candidates in enumerate(batches):
                # Filter context to only include items relevant to this batch's methods
                batch_methods = {cm.get("method", "") for cm in batch_candidates}
                batch_files = set()
                for m in batch_methods:
                    # Extract likely file from method name (e.g. WebCore::Foo::bar → Foo)
                    parts = m.replace("WebCore::", "").split("::")
                    if parts:
                        batch_files.add(parts[0])

                def _relevant(item: dict, keys: set[str]) -> bool:
                    """Check if an item mentions any of the batch's classes/methods."""
                    text = json.dumps(item)
                    return any(k in text for k in keys)

                batch_tm = {
                    "kind": "threat_model",
                    "area": f"batch {batch_idx+1}/{len(batches)} — {merged['area']}",
                    "paths": [p for p in merged.get("paths", []) if _relevant(p, batch_files)] if isinstance(merged.get("paths", [None])[0] if merged.get("paths") else None, dict) else [p for p in merged.get("paths", []) if any(k in str(p) for k in batch_files)],
                    "assets": [a for a in merged.get("assets", []) if _relevant(a, batch_files)],
                    "entry_points": [e for e in merged.get("entry_points", []) if _relevant(e, batch_files)],
                    "trust_boundaries": [t for t in merged.get("trust_boundaries", []) if _relevant(t, batch_files)],
                    "attacker_controlled_values": [v for v in merged.get("attacker_controlled_values", []) if _relevant(v, batch_files)],
                    "corruption_sinks": [s for s in merged.get("corruption_sinks", []) if _relevant(s, batch_files)],
                    "invariants": [inv for inv in merged.get("invariants", []) if _relevant(inv, batch_files)],
                    "candidate_methods": batch_candidates,
                    "dedup_notes": [],
                }
                batch_log_dir = ws / "logs" / "out-of-band" / f"generate-targets-{stamp}-batch{batch_idx}"
                batch_ctx = {
                    "TARGET_REPO": str(cfg.target_repo),
                    "THREAT_MODEL_JSON": json.dumps(batch_tm, indent=2),
                    "TARGETS": existing_targets,
                    **cfg.overlay_ctx(),
                }
                console.print(
                    f"[cyan]  batch {batch_idx+1}/{len(batches)}: "
                    f"{len(batch_candidates)} candidates...[/cyan]",
                    end=""
                )
                batch_res = agent_invoke.invoke(
                    store=store,
                    dispatcher=dispatcher,
                    agent_name="target-generator",
                    slot=f"generate-targets-{stamp}-b{batch_idx}",
                    model=chosen_model,
                    ctx=batch_ctx,
                    cycle_n=None,
                    target_repo=cfg.target_repo,
                    agent_timeout_s=cfg.agent_timeout_seconds,
                    log_dir=batch_log_dir,
                )
                if batch_res["parsed"]:
                    bp = batch_res["parsed"]
                    n_emit = len(bp.get("methods_emitted", []))
                    n_drop = len(bp.get("dropped", []))
                    console.print(f" emit={n_emit} drop={n_drop}")
                    all_parsed_results.append(bp)
                else:
                    console.print(f" [red]FAILED[/red]")
                    # Retry with halved batch
                    if len(batch_candidates) > 10:
                        half = len(batch_candidates) // 2
                        for retry_half in [batch_candidates[:half], batch_candidates[half:]]:
                            retry_tm = {**merged, "candidate_methods": retry_half,
                                        "area": f"retry batch {batch_idx+1} — {merged['area']}"}
                            retry_ctx = {
                                "TARGET_REPO": str(cfg.target_repo),
                                "THREAT_MODEL_JSON": json.dumps(retry_tm, indent=2),
                                "TARGETS": existing_targets,
                                **cfg.overlay_ctx(),
                            }
                            retry_res = agent_invoke.invoke(
                                store=store, dispatcher=dispatcher,
                                agent_name="target-generator",
                                slot=f"generate-targets-{stamp}-b{batch_idx}-retry",
                                model=chosen_model, ctx=retry_ctx, cycle_n=None,
                                target_repo=cfg.target_repo,
                                agent_timeout_s=cfg.agent_timeout_seconds,
                                log_dir=batch_log_dir,
                            )
                            if retry_res["parsed"]:
                                all_parsed_results.append(retry_res["parsed"])
                            else:
                                failed_batches.append(batch_idx)
                    else:
                        failed_batches.append(batch_idx)

            if failed_batches:
                console.print(
                    f"[yellow]warning: {len(failed_batches)} batch(es) failed; "
                    f"coverage is partial[/yellow]"
                )

            # Pass 2: merge all batch results and deduplicate methods_emitted
            all_methods: list[dict] = []
            all_dropped: list[dict] = []
            all_sections: list[str] = []
            seen_emit: set[tuple[str, str]] = set()
            for bp in all_parsed_results:
                for m in bp.get("methods_emitted", []):
                    # The LLM emits {"method": "WebCore::Foo::bar", "bug_class": "UAF"}
                    # not {"target_class": ..., "target_method": ...}. Build key from "method".
                    method_qualified = m.get("method", "") or f"{m.get('target_class', '')}::{m.get('target_method', '')}"
                    bug = m.get("bug_class", "") or m.get("bug_class_hint", "") or ""
                    key = (method_qualified, bug)
                    if key not in seen_emit:
                        seen_emit.add(key)
                        all_methods.append(m)
                all_dropped.extend(bp.get("dropped", []))
                if bp.get("section_md"):
                    all_sections.append(bp["section_md"])

            # Build final merged result
            parsed = {
                "kind": "targets",
                "area": merged["area"],
                "campaign": all_parsed_results[0].get("campaign", 0) if all_parsed_results else 0,
                "methods_emitted": all_methods,
                "dropped": all_dropped,
                "deferred": [],
                "section_md": "\n\n".join(all_sections),
            }
            console.print(
                f"[green]batched generation complete[/green]:\n"
                f"  total emit: {len(all_methods)}   "
                f"total drop: {len(all_dropped)}   "
                f"batches: {len(batches)} ({len(failed_batches)} failed)"
            )

            # Save and apply
            out_dir = ws / "threat-models"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"generated-{stamp}.json"
            out_path.write_text(json.dumps(parsed, indent=2))
            console.print(f"[dim]saved: {out_path}[/dim]")
            if apply_flag:
                campaign_n = parsed.get("campaign", 0)
                area = parsed.get("area", "")
                heading = f"Campaign {campaign_n} — {area}".strip(" —")
                append_targets_section(ws / "targets.md", parsed["section_md"], heading)
                rows = parse_targets(read_text(ws / "targets.md"))
                if rows:
                    store.replace_targets(rows)
                console.print(f"[green]appended to targets.md under '{heading}'[/green]")
            else:
                console.print("\n[bold]section_md preview:[/bold]")
                console.print(parsed["section_md"])
                console.print("\n[dim]Re-run with --apply to append to targets.md[/dim]")
            store.close()
            return

        tm = merged

    # ---------- Dispatch target-generator ----------
    chosen_model = model or cfg.refinement_model
    stamp = _utc_stamp()
    log_dir = ws / "logs" / "out-of-band" / f"generate-targets-{stamp}"
    ctx_dict = {
        "TARGET_REPO": str(cfg.target_repo),
        "THREAT_MODEL_JSON": json.dumps(tm, indent=2),
        "TARGETS": read_text(ws / "targets.md"),
        **cfg.overlay_ctx(),
    }
    console.print(f"[cyan]dispatching target-generator ({chosen_model})...[/cyan]")
    res = agent_invoke.invoke(
        store=store,
        dispatcher=dispatcher,
        agent_name="target-generator",
        slot=f"generate-targets-{stamp}",
        model=chosen_model,
        ctx=ctx_dict,
        cycle_n=None,
        target_repo=cfg.target_repo,
        agent_timeout_s=cfg.agent_timeout_seconds,
        log_dir=log_dir,
    )
    if not res["parsed"]:
        store.close()
        raise click.ClickException(
            f"target-generator returned no parseable JSON. See {log_dir}."
        )
    parsed = res["parsed"]
    if parsed.get("kind") == "no_targets":
        console.print(f"[yellow]NO_TARGETS[/yellow] for area '{parsed.get('area','')}': {parsed.get('reason','')}")
        store.close()
        return

    section_md = parsed.get("section_md", "")
    methods = parsed.get("methods_emitted", [])
    dropped = parsed.get("dropped", [])
    deferred = parsed.get("deferred", [])
    console.print(
        f"[green]section generated[/green]:\n"
        f"  emit: {len(methods)}   drop: {len(dropped)}   defer: {len(deferred)}"
    )
    out_dir = ws / "threat-models"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"generated-{stamp}.json"
    out_path.write_text(json.dumps(parsed, indent=2))
    console.print(f"[dim]saved: {out_path}[/dim]")
    if apply_flag:
        campaign_n = parsed.get("campaign", 0)
        area = parsed.get("area", "")
        heading = f"Campaign {campaign_n} — {area}".strip(" —")
        append_targets_section(ws / "targets.md", section_md, heading)
        # Refresh targets table
        rows = parse_targets(read_text(ws / "targets.md"))
        if rows:
            store.replace_targets(rows)
        console.print(f"[green]appended to targets.md under '{heading}'[/green]")
    else:
        console.print("\n[bold]section_md preview:[/bold]")
        console.print(section_md)
        console.print("\n[dim]Re-run with --apply to append to targets.md[/dim]")
    store.close()


@cli.command("review-scope")
@click.option("--gate", "gate_path", default=None, type=click.Path(exists=True),
              help="Path to a target-generator output JSON (Phase 1 gate mode).")
@click.option("--retire", "retire_mode", is_flag=True,
              help="Phase 3 mode: emit retirement recommendations from method health.")
@click.option("--model", default=None,
              help="Model to dispatch (defaults to refinement_model).")
@click.pass_context
def review_scope(ctx: click.Context, gate_path: Optional[str], retire_mode: bool,
                 model: Optional[str]) -> None:
    """Run scope-reviewer (Phase 1 gate / Phase 3 retirement)."""
    if not gate_path and not retire_mode:
        raise click.ClickException(
            "specify either --gate <generated-targets.json> or --retire"
        )
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")
    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )
    chosen_model = model or cfg.refinement_model
    stamp = _utc_stamp()
    log_dir = ws / "logs" / "out-of-band" / f"review-scope-{stamp}"

    proposed_json = "{}"
    target_health: list[dict] = []
    if gate_path:
        proposed_json = Path(gate_path).read_text()
    if retire_mode:
        latest_cat = store.latest_catalog()
        latest_mit = store.latest_mitigations()
        cat_id = latest_cat["id"] if latest_cat else 0
        mit_id = latest_mit["id"] if latest_mit else 0
        latest_cycle = store.latest_cycle()
        latest_n = latest_cycle["n"] if latest_cycle else 0
        for t in store.all_targets():
            h = store.method_health(t["target_class"], t["target_method"], cat_id, mit_id)
            last_finding_age = (latest_n - h["last_finding_cycle"]) if h["last_finding_cycle"] else None
            target_health.append({
                "method": f"{t['target_class']}::{t['target_method']}",
                "audited_count": (h["clean_count_epoch"] or 0) + (h["confirmed"] or 0),
                "clean_count": h["clean_count_epoch"] or 0,
                "distinct_clean_vendors": h["distinct_clean_vendors_epoch"] or 0,
                "confirmed": h["confirmed"] or 0,
                "last_audit_cycle": h["last_audit_cycle"],
                "last_finding_cycle": h["last_finding_cycle"],
                "last_finding_age": last_finding_age,
            })

    ctx_dict = {
        "TARGET_REPO": str(cfg.target_repo),
        "PROPOSED_TARGETS_JSON": proposed_json,
        "TARGETS": read_text(ws / "targets.md"),
        "TARGET_HEALTH_JSON": json.dumps(target_health, indent=2) if retire_mode else "[]",
        "CATALOG": read_text(ws / "rules" / "catalog.md"),
        "CONFIRMED": _confirmed_digest(store, limit=50),
        **cfg.overlay_ctx(),
    }
    mode_label = "gate" if gate_path else "retire"
    console.print(f"[cyan]dispatching scope-reviewer ({chosen_model}, mode={mode_label})...[/cyan]")
    res = agent_invoke.invoke(
        store=store,
        dispatcher=dispatcher,
        agent_name="scope-reviewer",
        slot=f"scope-review-{mode_label}-{stamp}",
        model=chosen_model,
        ctx=ctx_dict,
        cycle_n=None,
        target_repo=cfg.target_repo,
        agent_timeout_s=cfg.agent_timeout_seconds,
        log_dir=log_dir,
    )
    if not res["parsed"]:
        store.close()
        raise click.ClickException(f"scope-reviewer returned no parseable JSON. See {log_dir}.")
    parsed = res["parsed"]
    out_dir = ws / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"scope-review-{mode_label}-{stamp}.json"
    out_path.write_text(json.dumps(parsed, indent=2))

    console.print(f"\n[bold]summary:[/bold] {parsed.get('summary','')}")
    if parsed.get("role") == "gate":
        decisions = parsed.get("decisions", [])
        table = Table(title=f"scope-review (gate, {len(decisions)} decisions)")
        table.add_column("method")
        table.add_column("decision")
        table.add_column("rationale")
        for d in decisions:
            table.add_row(d.get("method","")[:48], d.get("decision",""), d.get("rationale","")[:80])
        console.print(table)
    else:
        recs = parsed.get("retire_recommendations", [])
        table = Table(title=f"scope-review (retire, {len(recs)} recommendations)")
        table.add_column("method")
        table.add_column("audited", justify="right")
        table.add_column("clean", justify="right")
        table.add_column("last_finding_age", justify="right")
        table.add_column("rationale")
        for r in recs:
            table.add_row(
                r.get("method","")[:48],
                str(r.get("audited_count","")),
                str(r.get("clean_count","")),
                str(r.get("last_finding_age","")),
                r.get("rationale","")[:80],
            )
        console.print(table)
    console.print(f"\n[dim]saved: {out_path}[/dim]")
    store.close()


@cli.command()
@click.option("--since-cycles", type=int, default=50,
              help="Look back this many cycles for rejection history.")
@click.option("--model", default=None,
              help="Model to dispatch (defaults to refinement_model).")
@click.pass_context
def analyze(ctx: click.Context, since_cycles: int, model: Optional[str]) -> None:
    """Run analyst on rejection-code history (Phase 3 every 10 cycles)."""
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")
    store = Store.open(ws)
    store.set_target_repo(str(cfg.target_repo))
    dispatcher = dispatch_mod.default_dispatcher(
        command=cfg.dispatch_command, args=cfg.dispatch_args,
    )
    chosen_model = model or cfg.refinement_model
    stamp = _utc_stamp()
    log_dir = ws / "logs" / "out-of-band" / f"analyze-{stamp}"

    # Build the rejection history JSON
    latest = store.latest_cycle()
    latest_n = latest["n"] if latest else 0
    cutoff = max(0, latest_n - since_cycles)
    rows = list(store.conn.execute(
        """SELECT v.code AS code,
                  v.model AS model,
                  v.rationale AS rationale,
                  cl.cycle_n AS cycle_n,
                  cl.target_class AS target_class,
                  cl.target_method AS target_method,
                  cl.bug_class AS bug_class
           FROM validations v
           JOIN claims cl ON cl.id = v.claim_id
           WHERE v.verdict = 'reject' AND cl.cycle_n >= ?
           ORDER BY cl.cycle_n DESC LIMIT 500""",
        (cutoff,),
    ).fetchall())
    reject_history = [dict(r) for r in rows]
    if not reject_history:
        console.print(f"[yellow]no rejection history in last {since_cycles} cycles; nothing to analyze[/yellow]")
        store.close()
        return

    ctx_dict = {
        "TARGET_REPO": str(cfg.target_repo),
        "REJECT_HISTORY": json.dumps(reject_history, indent=2),
        "CATALOG": read_text(ws / "rules" / "catalog.md"),
        "MITIGATIONS": read_text(ws / "rules" / "mitigations.md"),
        **cfg.overlay_ctx(),
    }
    console.print(
        f"[cyan]dispatching analyst ({chosen_model}) over {len(reject_history)} rejections "
        f"(cycles {cutoff}..{latest_n})...[/cyan]"
    )
    res = agent_invoke.invoke(
        store=store,
        dispatcher=dispatcher,
        agent_name="analyst",
        slot=f"analyze-{stamp}",
        model=chosen_model,
        ctx=ctx_dict,
        cycle_n=None,
        target_repo=cfg.target_repo,
        agent_timeout_s=cfg.agent_timeout_seconds,
        log_dir=log_dir,
    )
    if not res["parsed"]:
        store.close()
        raise click.ClickException(f"analyst returned no parseable JSON. See {log_dir}.")
    parsed = res["parsed"]
    out_dir = ws / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"analysis-{stamp}.md"

    md_lines = [
        f"# autosearch analysis — {stamp}",
        f"",
        f"Cycles analyzed: {cutoff}..{latest_n} ({len(reject_history)} rejections)",
        f"Model: {chosen_model}",
        f"",
        f"## Summary",
        f"",
        parsed.get("summary", "(no summary)"),
        f"",
        f"## Top failure modes",
        f"",
    ]
    for fm in parsed.get("top_failure_modes", []):
        md_lines.append(f"### {fm.get('code','?')} — count {fm.get('count','?')}")
        md_lines.append(f"- top methods: {', '.join(fm.get('top_methods', []))}")
        md_lines.append(f"- top models: {', '.join(fm.get('top_models', []))}")
        md_lines.append(f"- proposed fix: {fm.get('proposed_fix','')}")
        md_lines.append("")
    md_lines.append("## Noisy targets")
    md_lines.append("")
    for nt in parsed.get("noisy_targets", []):
        md_lines.append(f"- `{nt.get('method','')}` rejection_rate={nt.get('rejection_rate','')}")
    md_lines.append("")
    md_lines.append("## Model imbalance")
    md_lines.append("")
    for mi in parsed.get("model_imbalance", []):
        md_lines.append(
            f"- `{mi.get('model','')}` x `{mi.get('code','')}`: ratio "
            f"{mi.get('ratio_vs_other_vendor','')} — {mi.get('recommendation','')}"
        )
    md_lines.append("")
    out_path.write_text("\n".join(md_lines))

    # Console summary
    table = Table(title="top failure modes")
    table.add_column("code")
    table.add_column("count", justify="right")
    table.add_column("top_methods")
    table.add_column("proposed fix")
    for fm in parsed.get("top_failure_modes", [])[:10]:
        table.add_row(
            fm.get("code", "")[:32],
            str(fm.get("count", "")),
            ", ".join(fm.get("top_methods", []))[:40],
            (fm.get("proposed_fix", "") or "")[:60],
        )
    console.print(table)
    console.print(f"\n[green]report saved[/green]: {out_path}")
    store.close()


def _confirmed_digest(store: Store, limit: int = 50) -> str:
    rows = store.conn.execute(
        "SELECT cycle_n, target_class, target_method, bug_class "
        "FROM claims WHERE state IN ('confirmed','settled') ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    if not rows:
        return "(none yet)"
    return "\n".join(
        f"c{r['cycle_n']} {r['target_class']}::{r['target_method']} [{r['bug_class']}]"
        for r in rows
    )


@cli.command("build-oracle")
@click.option("--phase", type=click.Choice(["1", "all"]), default="1",
              help="Which oracle phase to build. 1=idl_exposure only (no clang). "
                   "all=Phase 1 + libclang AST pass for mutable_globals/callers/threads.")
@click.option("--port", default=None,
              help="WebKit port hint for CDB lookup (gtk|wpe|cocoa|playstation).")
@click.option("--scope", default=None,
              help="Phase 2: substring filter on TU file paths "
                   "(e.g. 'platform/graphics/cg/'). Limits which TUs are walked. "
                   "Default: all TUs in the CDB.")
@click.option("--remap", default=None, multiple=True,
              help="Phase 2: path remap rule of the form OLD=NEW. May be passed "
                   "multiple times. Use this when the CDB has hardcoded build-sandbox "
                   "paths (e.g. '/sdk/webkit=/home/me/WebKit').")
@click.option("--workers", type=int, default=16,
              help="Phase 2: parallel libclang workers. Default 16.")
@click.option("--libclang", default="/usr/lib/x86_64-linux-gnu/libclang-18.so.18",
              help="Path to libclang shared library.")
@click.pass_context
def build_oracle(ctx: click.Context, phase: str, port: Optional[str],
                 scope: Optional[str], remap: tuple[str, ...],
                 workers: int, libclang: str) -> None:
    """Build the MethodFacts oracle for this workspace's target_repo.

    Phase 1 walks every .idl under Source/WebCore/ and emits
    workspace/oracles/method_facts.json with the idl_exposure field
    populated. Phase 2 (--phase=all) additionally runs libclang over the
    CDB to populate mutable_globals_touched, callers_1hop, and
    thread_protections.
    """
    ws = _resolve_workspace(ctx.obj.get("workspace_arg"))
    cfg = WorkspaceConfig.load(ws)
    _setup_logging(ctx.obj["verbose"], log_path=ws / "logs" / "autosearch.log")

    target_repo = Path(cfg.target_repo).expanduser().resolve()
    if not (target_repo / "Source" / "WebCore").is_dir():
        raise click.ClickException(
            f"target_repo {target_repo} has no Source/WebCore — IDL parser needs it"
        )

    out_path = ws / "oracles" / "method_facts.json"
    console.print(f"[bold]building oracle[/bold] (phase={phase})")
    console.print(f"  target_repo:  {target_repo}")
    console.print(f"  out:          {out_path}")

    cdb_loc = None
    if phase == "all":
        from .oracles.cdb import find_compile_commands, OraclesNotBootstrapped
        try:
            cdb_loc = find_compile_commands(target_repo, port=port)
            console.print(f"  CDB:          {cdb_loc.path}")
        except OraclesNotBootstrapped as e:
            console.print(f"[red]bootstrap error:[/red]\n{e}")
            raise click.Abort()

    # Resolve target_sha for cache invalidation
    import subprocess as _sp
    try:
        target_sha = _sp.check_output(
            ["git", "-C", str(target_repo), "rev-parse", "HEAP"],
            text=True, stderr=_sp.DEVNULL,
        ).strip()
    except Exception:  # noqa: BLE001
        target_sha = None
    if not target_sha:
        try:
            target_sha = _sp.check_output(
                ["git", "-C", str(target_repo), "rev-parse", "HEAD"],
                text=True, stderr=_sp.DEVNULL,
            ).strip()
        except Exception:  # noqa: BLE001
            target_sha = None

    # ---- Phase 1: IDL exposure (always run) ----
    from .oracles.store import build_idl_only_facts
    payload = build_idl_only_facts(target_repo, out_path,
                                   target_sha=target_sha,
                                   cdb_path=str(cdb_loc.path) if cdb_loc else None)
    n = len(payload["methods"])
    n_worker = sum(1 for m in payload["methods"].values()
                   if m["idl_exposure"]["exposed_to_worker"])
    console.print(f"\n[bold]Phase 1 (IDL exposure)[/bold]: "
                  f"{n} methods indexed, {n_worker} worker-exposed")

    # ---- Phase 2: libclang AST pass ----
    if phase == "all":
        # Parse remap rules
        remap_dict: dict[str, str] = {}
        for r in remap:
            if "=" not in r:
                raise click.ClickException(f"--remap must be OLD=NEW, got {r!r}")
            old, new = r.split("=", 1)
            remap_dict[old] = new
        # Heuristic: if no --remap given but the CDB looks sandboxed
        # (/sdk/webkit/...), auto-remap to target_repo.
        if not remap_dict:
            import json as _json
            sample = _json.loads(cdb_loc.path.read_text())[:1]
            if sample and "/sdk/webkit" in sample[0].get("file", ""):
                remap_dict = {"/sdk/webkit": str(target_repo)}
                console.print(f"  [yellow]auto-remap:[/yellow] /sdk/webkit → {target_repo}")

        from .oracles.libclang_pass import run_phase2, merge_phase2_into_facts
        console.print(f"\n[bold]Phase 2 (libclang AST)[/bold]: "
                      f"scope={scope or '(all)'}, workers={workers}")
        # Restrict facts to methods declared under target_repo (not transitive headers)
        source_root = str(target_repo / "Source")
        p2 = run_phase2(cdb_loc.path, libclang_lib=libclang,
                        scope_pattern=scope, remap=remap_dict, workers=workers,
                        source_root=source_root)
        console.print(f"  walked {p2.tus_walked} TUs (failed: {p2.tus_failed})")
        console.print(f"  {len(p2.method_globals)} methods with mutable_globals")
        console.print(f"  {len(p2.callers_1hop)} methods with callers")
        console.print(f"  {len(p2.method_thread_asserts)} methods with thread asserts")

        merge_phase2_into_facts(out_path, p2)
        # Reload to refresh stats
        from .oracles.store import MethodFactsStore
        s = MethodFactsStore.from_file(out_path)
        n_globals = sum(1 for m in s.facts.values() if m["mutable_globals_touched"])
        n_callers = sum(1 for m in s.facts.values() if m["callers_1hop"])
        console.print(f"\n  total methods now indexed: {s.known_method_count()}")
        console.print(f"  with mutable_globals: {n_globals}")
        console.print(f"  with callers_1hop:    {n_callers}")

    console.print(f"\n[bold green]oracle build complete[/bold green]")
    console.print(f"  schema_version: 1")
    console.print(f"  target_sha:     {target_sha or '(unknown)'}")


if __name__ == "__main__":
    cli()
