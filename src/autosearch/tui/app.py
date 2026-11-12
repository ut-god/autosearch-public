"""Textual TUI for autosearch.

Read-only monitor. Polls findings.db, status.json, and tails the
autosearch.log. No writes anywhere — safe to run alongside `autosearch run`.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.reactive import reactive
from textual.widgets import (
    DataTable, Footer, Header, RichLog, Sparkline, Static,
)

from ..targets import split_qualified_target


def _utc_age(iso_str: str) -> str:
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return "—"
    now = datetime.now(timezone.utc)
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


class StatusPanel(Static):
    cycle = reactive(0)
    phase = reactive("idle")
    elapsed = reactive("—")
    last_update = reactive("—")
    pid_running = reactive(False)
    target_repo = reactive("")
    subagent_tally = reactive("—")
    coverage = reactive("—")
    cost = reactive("—")

    def render(self) -> str:
        running = "[green]● running[/green]" if self.pid_running else "[dim]○ idle[/dim]"
        return (
            f"[b]Cycle:[/b]    {self.cycle}\n"
            f"[b]Phase:[/b]    {self.phase}\n"
            f"[b]Subagents:[/b] {self.subagent_tally}\n"
            f"[b]Coverage:[/b] {self.coverage}\n"
            f"[b]Cost:[/b]     {self.cost}\n"
            f"[b]Elapsed:[/b]  {self.elapsed}\n"
            f"[b]Last upd:[/b] {self.last_update}\n"
            f"[b]Status:[/b]   {running}\n"
            f"[b]Target:[/b]   {self.target_repo}"
        )


class ScorePanel(Static):
    headline = reactive("(no cycles yet)")

    def render(self) -> str:
        return f"[b]{self.headline}[/b]"


class WallStatusPanel(Static):
    headline = reactive("(no completed cycles)")

    def render(self) -> str:
        return self.headline


class AutosearchApp(App):
    """Live read-only monitor for an autosearch workspace."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #top {
        layout: horizontal;
        height: 10;
    }
    #status, #score {
        border: solid $primary;
        padding: 0 1;
    }
    #status { width: 42; }
    #score { width: 1fr; layout: vertical; }
    #middle {
        layout: horizontal;
        height: 18;
    }
    #subagents {
        border: solid $primary;
        padding: 0 1;
        width: 1fr;
        layout: vertical;
    }
    #wall_status {
        height: 1;
    }
    #bottom {
        layout: horizontal;
        height: 12;
    }
    #findings {
        border: solid $primary;
        padding: 0 1;
        width: 2fr;
    }
    #bugclass {
        border: solid $primary;
        padding: 0 1;
        width: 1fr;
    }
    #log_panel {
        border: solid $primary;
        height: 1fr;
        padding: 0 1;
    }
    DataTable {
        height: 100%;
    }
    #score_spark {
        height: 4;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, workspace: Path) -> None:
        super().__init__()
        self.workspace = workspace
        self.db_path = workspace / "findings.db"
        self.status_path = workspace / "logs" / "status.json"
        self.log_path = workspace / "logs" / "autosearch.log"
        self._log_pos = 0
        # Cache the configured agent_timeout so the wall panel can flag
        # near-misses against the actual ceiling. Loaded lazily.
        self._agent_timeout_s: int = 0

    def compose(self) -> ComposeResult:
        yield Header(name="autosearch monitor")
        with Container(id="top"):
            yield StatusPanel(id="status")
            with Vertical(id="score"):
                yield Sparkline([], id="score_spark")
                yield ScorePanel(id="score_text")
        with Container(id="middle"):
            with Container(id="subagents"):
                yield Static("[b]Active subagents[/b]")
                yield WallStatusPanel(id="wall_status")
                yield DataTable(id="subagents_table", zebra_stripes=True)
        with Container(id="bottom"):
            with Container(id="findings"):
                yield Static("[b]Confirmed findings[/b]")
                yield DataTable(id="findings_table", zebra_stripes=True)
            with Container(id="bugclass"):
                yield Static("[b]Bug class breakdown[/b]")
                yield DataTable(id="bugclass_table", zebra_stripes=True)
        with Container(id="log_panel"):
            yield Static("[b]Live log (autosearch.log)[/b]")
            yield RichLog(id="log_view", highlight=True, markup=True, max_lines=500)
        yield Footer()

    def on_mount(self) -> None:
        # Initialize tables
        st: DataTable = self.query_one("#subagents_table", DataTable)
        st.add_columns("slot", "model", "target", "state", "outcome", "dur")
        st.cursor_type = "row"
        fg: DataTable = self.query_one("#findings_table", DataTable)
        fg.add_columns("id", "sev", "bug_class", "method")
        fg.cursor_type = "row"
        bg: DataTable = self.query_one("#bugclass_table", DataTable)
        bg.add_columns("bug_class", "count", "bar")
        bg.cursor_type = "row"
        # Try to load agent_timeout from workspace config (best-effort)
        self._agent_timeout_s = self._load_agent_timeout()
        self.set_interval(2.0, self._refresh)
        self._refresh()

    def _load_agent_timeout(self) -> int:
        """Read agent_timeout_seconds from workspace config.toml. Returns 0 on failure."""
        cfg_path = self.workspace / "config.toml"
        if not cfg_path.exists():
            return 0
        try:
            import sys
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib  # type: ignore
            with cfg_path.open("rb") as f:
                data = tomllib.load(f)
            return int(data.get("agent_timeout_seconds", 1500))
        except Exception:
            return 0

    def action_refresh(self) -> None:
        self._refresh()

    def action_quit(self) -> None:
        self.exit()

    # ---------- refresh ----------

    def _refresh(self) -> None:
        self._refresh_status()
        self._refresh_db()
        self._refresh_log()

    def _refresh_status(self) -> None:
        sp: StatusPanel = self.query_one("#status", StatusPanel)
        st_table: DataTable = self.query_one("#subagents_table", DataTable)
        if not self.status_path.exists():
            sp.cycle = 0
            sp.phase = "idle"
            sp.elapsed = "—"
            sp.last_update = "—"
            sp.pid_running = False
            sp.subagent_tally = "—"
            return
        try:
            data = json.loads(self.status_path.read_text())
        except Exception:
            return
        sp.cycle = data.get("cycle", 0) or 0
        phase = data.get("phase", "idle") or "idle"
        sp.phase = phase
        sp.elapsed = _utc_age(data.get("phase_started_at", "") or "")
        sp.last_update = _utc_age(data.get("last_heartbeat", "") or "")
        sp.target_repo = data.get("target_repo", "") or ""

        # Subagent tally for the Status panel
        subs = data.get("subagents", []) or []
        running = sum(1 for s in subs if s.get("state") == "running")
        completed = sum(1 for s in subs if s.get("state") == "completed")
        failed = sum(1 for s in subs if s.get("state") == "failed")
        pending = len(subs) - running - completed - failed
        if subs:
            parts = []
            if running:   parts.append(f"[yellow]{running} run[/yellow]")
            if completed: parts.append(f"[green]{completed} done[/green]")
            if failed:    parts.append(f"[red]{failed} fail[/red]")
            if pending:   parts.append(f"{pending} pend")
            sp.subagent_tally = "  ".join(parts) + f"  / {len(subs)}"
        else:
            sp.subagent_tally = "(none)"

        # Liveness: combine three signals so "running" is true whenever the
        # orchestrator is actually doing work — not just when status.json
        # was recently rewritten. The 30s-heartbeat heuristic alone is
        # wrong because status.json updates only on subagent state
        # transitions; during a long cohort dispatch, no updates happen
        # for many minutes even though every subagent is busy.
        phase_active = phase not in ("idle", "", None)
        any_running = running > 0
        heartbeat_ok = False
        try:
            last_hb = datetime.fromisoformat(
                (data.get("last_heartbeat") or "").replace("Z", "+00:00")
            )
            heartbeat_ok = (datetime.now(timezone.utc) - last_hb).total_seconds() < 600
        except Exception:
            pass
        sp.pid_running = phase_active or any_running or heartbeat_ok

        st_table.clear()
        for s in subs:
            # Duration: live for running, final for completed/failed
            dur = "—"
            try:
                started = s.get("started_at")
                ended = s.get("ended_at")
                if started:
                    st_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    if ended:
                        end_dt = datetime.fromisoformat(ended.replace("Z", "+00:00"))
                        secs = int((end_dt - st_dt).total_seconds())
                    else:
                        secs = int((datetime.now(timezone.utc) - st_dt).total_seconds())
                    if secs < 60:
                        dur = f"{secs}s"
                    else:
                        dur = f"{secs // 60}m{secs % 60:02d}s"
            except Exception:
                pass
            st_table.add_row(
                s.get("slot", ""),
                s.get("model", ""),
                (s.get("target") or "")[:48],
                s.get("state", ""),
                s.get("outcome", ""),
                dur,
            )

    def _refresh_db(self) -> None:
        if not self.db_path.exists():
            return
        try:
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.OperationalError:
            return
        try:
            self._refresh_score(conn)
            self._refresh_wall(conn)
            self._refresh_findings(conn)
            self._refresh_bugclass(conn)
            self._refresh_coverage(conn)
            self._refresh_cost(conn)
        finally:
            conn.close()

    def _refresh_score(self, conn: sqlite3.Connection) -> None:
        cycles = list(conn.execute(
            "SELECT score FROM cycles WHERE status='complete' ORDER BY n DESC LIMIT 40"
        ).fetchall())[::-1]
        scores = [c["score"] or 0.0 for c in cycles]
        spark: Sparkline = self.query_one("#score_spark", Sparkline)
        spark.data = scores
        text: ScorePanel = self.query_one("#score_text", ScorePanel)
        if not scores:
            text.headline = "(no completed cycles yet)"
            return
        confirmed = conn.execute(
            "SELECT COUNT(*) AS c FROM claims WHERE state IN ('confirmed','settled')"
        ).fetchone()["c"]
        reverted = conn.execute(
            "SELECT COUNT(*) AS c FROM claims WHERE state = 'reverted'"
        ).fetchone()["c"]
        contested = conn.execute(
            "SELECT COUNT(*) AS c FROM claims WHERE state = 'contested'"
        ).fetchone()["c"]
        srv = conn.execute(
            "SELECT COUNT(*) AS c FROM challenges WHERE verdict='survives'"
        ).fetchone()["c"]
        text.headline = (
            f"score now {scores[-1]:.1f}   median(40) {sorted(scores)[len(scores)//2]:.1f}   "
            f"best {max(scores):.1f}\n"
            f"confirmed: {confirmed}   reverted: {reverted}   "
            f"contested: {contested}   survived: {srv}"
        )

    def _refresh_wall(self, conn: sqlite3.Connection) -> None:
        """Per-cycle wall-time status line + timeout-risk indicator (no sparkline)."""
        rows = list(conn.execute(
            """SELECT n, status,
                      ROUND((julianday(COALESCE(ended_at, datetime('now')))
                             - julianday(started_at)) * 86400, 0) AS wall
               FROM cycles ORDER BY n DESC LIMIT 30"""
        ).fetchall())[::-1]
        status: WallStatusPanel = self.query_one("#wall_status", WallStatusPanel)
        if not rows:
            status.headline = "(no completed cycles)"
            return
        walls = [int(r["wall"] or 0) for r in rows]
        last = rows[-1]
        last_wall = walls[-1]
        last_n = last["n"]
        last_status = last["status"]
        latest_icon = {"complete": "✓", "running": "•", "aborted": "⚠"}.get(last_status, "?")
        max_wall = max(walls)
        agent_to = self._agent_timeout_s or 0
        aborts = sum(1 for r in rows if r["status"] == "aborted")
        risk_str = ""
        if agent_to > 0:
            non_abort_walls = [w for r, w in zip(rows, walls) if r["status"] == "complete"]
            if non_abort_walls:
                near = max(non_abort_walls)
                pct = int(near / agent_to * 100)
                if pct >= 80:
                    risk_str = f"  [yellow]nearest miss: {near}s ({pct}% of timeout)[/yellow]"
                else:
                    risk_str = f"  nearest miss: {near}s ({pct}% of {agent_to}s)"
        abort_str = ""
        if aborts > 0:
            abort_str = f"  [red]aborts: {aborts}[/red]"
        median_wall = sorted(walls)[len(walls) // 2]
        status.headline = (
            f"c{last_n}: {last_wall}s {latest_icon}{abort_str}  "
            f"median(30) {median_wall}s  max {max_wall}s{risk_str}"
        )

    def _refresh_findings(self, conn: sqlite3.Connection) -> None:
        rows = list(conn.execute(
            """SELECT id, severity, bug_class,
                  target_class || '::' || target_method AS method
               FROM claims
               WHERE state IN ('confirmed', 'settled')
               ORDER BY
                  CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                  id DESC
               LIMIT 15"""
        ).fetchall())
        fg: DataTable = self.query_one("#findings_table", DataTable)
        fg.clear()
        for r in rows:
            sev = r["severity"] or ""
            if sev == "High":
                sev = "[red]High[/red]"
            elif sev == "Medium":
                sev = "[yellow]Med[/yellow]"
            else:
                sev = f"[dim]{sev}[/dim]"
            split = split_qualified_target(r["method"] or "")
            short = split[1] if split else (r["method"] or "")
            fg.add_row(f"#{r['id']}", sev, r["bug_class"] or "", short[:40])

    def _refresh_bugclass(self, conn: sqlite3.Connection) -> None:
        rows = list(conn.execute(
            """SELECT bug_class, COUNT(*) AS cnt
               FROM claims
               WHERE state IN ('confirmed', 'settled')
               GROUP BY bug_class
               ORDER BY cnt DESC"""
        ).fetchall())
        bg: DataTable = self.query_one("#bugclass_table", DataTable)
        bg.clear()
        max_cnt = max((r["cnt"] for r in rows), default=1)
        for r in rows:
            cnt = r["cnt"]
            bar_len = int((cnt / max_cnt) * 12)
            bar = "█" * bar_len + "░" * (12 - bar_len)
            bg.add_row(r["bug_class"] or "?", str(cnt), bar)

    def _refresh_coverage(self, conn: sqlite3.Connection) -> None:
        """Coverage = how many in-scope targets have been audited at least once.

        Numerator: distinct (target_class, target_method) pairs that appear
        in either `claims` or `cleans` AND are also in the `targets` table.
        (Imported claims from a sibling git history don't count toward
        coverage of THIS workspace's targets.md scope.)
        Denominator: rows in `targets`.
        """
        sp: StatusPanel = self.query_one("#status", StatusPanel)
        total = conn.execute("SELECT COUNT(*) AS c FROM targets").fetchone()["c"]
        if total == 0:
            sp.coverage = "(no targets)"
            return
        # Distinct audited methods that intersect the targets table.
        # Use a single CTE-style query so we don't double-count methods that
        # appear in both claims and cleans.
        touched = conn.execute(
            """SELECT COUNT(*) AS c FROM targets t
               WHERE EXISTS (
                 SELECT 1 FROM claims cl
                  WHERE cl.target_method = t.target_method
                    AND (cl.target_class = t.target_class
                         OR cl.target_class LIKE '%' || t.target_class || '%'
                         OR t.target_class LIKE '%' || cl.target_class || '%')
               ) OR EXISTS (
                 SELECT 1 FROM cleans cn
                  WHERE cn.target_method = t.target_method
                    AND (cn.target_class = t.target_class
                         OR cn.target_class LIKE '%' || t.target_class || '%'
                         OR t.target_class LIKE '%' || cn.target_class || '%')
               )"""
        ).fetchone()["c"]
        # Methods touched ≥3 times by both vendors (mature audit signal):
        # used to show "settled" coverage as a secondary number.
        settled = conn.execute(
            """SELECT COUNT(*) AS c FROM targets t
               WHERE (
                 SELECT COUNT(DISTINCT cn.model) FROM cleans cn
                  WHERE cn.target_class = t.target_class
                    AND cn.target_method = t.target_method
               ) >= 2
               AND (
                 SELECT COUNT(*) FROM cleans cn
                  WHERE cn.target_class = t.target_class
                    AND cn.target_method = t.target_method
               ) >= 3"""
        ).fetchone()["c"]
        pct = (touched * 100) // total if total else 0
        # Render: "12/61 audited (19%)  3 settled"
        sp.coverage = (
            f"{touched}/{total} audited ([cyan]{pct}%[/cyan])"
            + (f"  [green]{settled} settled[/green]" if settled else "")
        )

    def _refresh_cost(self, conn: sqlite3.Connection) -> None:
        """Cost roll-up over the last 50 cycles + lifetime.

        Tolerant of legacy DBs that pre-date the cost columns: if the
        columns don't exist (workspace last touched on schema_v1),
        renders a hint instead of crashing.
        """
        sp: StatusPanel = self.query_one("#status", StatusPanel)
        try:
            row50 = conn.execute(
                """SELECT
                     COALESCE(SUM(cost_usd), 0.0) AS cost,
                     SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) AS unknown,
                     COUNT(*) AS n
                   FROM agent_runs
                   WHERE cycle_n IS NULL
                      OR cycle_n >= COALESCE(
                           (SELECT MAX(n) FROM cycles), 0) - 50"""
            ).fetchone()
            row_all = conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) AS cost FROM agent_runs"
            ).fetchone()
        except sqlite3.OperationalError:
            sp.cost = "[dim](pre-v2 schema; restart loop to migrate)[/dim]"
            return
        if row50["n"] == 0:
            sp.cost = "[dim](no agent runs)[/dim]"
            return
        c50 = row50["cost"] or 0.0
        c_all = row_all["cost"] or 0.0
        unknown_marker = (f" [dim]+{row50['unknown']} unpriced[/dim]"
                          if row50["unknown"] else "")
        sp.cost = (
            f"[green]${c50:.2f}[/green] last 50cy"
            f"  [dim]/[/dim]  ${c_all:.2f} lifetime"
            f"{unknown_marker}"
        )

    def _refresh_log(self) -> None:
        if not self.log_path.exists():
            return
        log_view: RichLog = self.query_one("#log_view", RichLog)
        try:
            with self.log_path.open("rb") as f:
                f.seek(self._log_pos)
                chunk = f.read()
                self._log_pos = f.tell()
        except OSError:
            return
        if not chunk:
            return
        for line in chunk.decode("utf-8", errors="replace").splitlines():
            if line:
                log_view.write(line)


def run_tui(workspace: Path) -> None:
    app = AutosearchApp(workspace)
    app.run()
