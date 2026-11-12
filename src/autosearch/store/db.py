"""SQLite store for autosearch findings.

Single writer model from the application's perspective, but the
orchestrator dispatches the auditor cohort and challenger pair in
worker threads. Each thread gets its OWN sqlite3 connection via
`threading.local`. SQLite WAL mode serializes writes natively;
no Python-side locking required.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from importlib import resources

SCHEMA_VERSION = 2  # bumped: agent_runs gained {prompt,completion}_tokens, cost_usd


def _load_schema() -> str:
    return resources.files("autosearch.store").joinpath("schema.sql").read_text()


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply forward-only schema migrations idempotently to an existing DB.

    SQLite's CREATE TABLE IF NOT EXISTS handles new tables but cannot add
    columns to existing ones. Each migration is a single ALTER guarded by
    a PRAGMA table_info check so re-running is a no-op.

    Bumps `workspace.schema_version` on success.
    """
    def _cols(table: str) -> set[str]:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}

    # v1 → v2: agent_runs gained cost telemetry
    ar_cols = _cols("agent_runs")
    needs_v2_backfill = "prompt_tokens" not in ar_cols
    if "prompt_tokens" not in ar_cols:
        conn.execute("ALTER TABLE agent_runs ADD COLUMN prompt_tokens INTEGER")
    if "completion_tokens" not in ar_cols:
        conn.execute("ALTER TABLE agent_runs ADD COLUMN completion_tokens INTEGER")
    if "cost_usd" not in ar_cols:
        conn.execute("ALTER TABLE agent_runs ADD COLUMN cost_usd REAL")

    if needs_v2_backfill:
        # Backfill token counts from char lengths so the cost dashboard
        # has historical data on first open. Cost is computed per-row
        # (pricing varies by model), so do it in Python rather than SQL.
        # Import lazily to avoid an import cycle (pricing → … → store).
        from .. import pricing as pricing_mod  # noqa: WPS433
        rows = list(conn.execute(
            "SELECT id, model, rendered_prompt, raw_response FROM agent_runs"
        ).fetchall())
        for r in rows:
            pt = pricing_mod.estimate_tokens(r["rendered_prompt"])
            ct = pricing_mod.estimate_tokens(r["raw_response"])
            cost = pricing_mod.estimate_cost_usd(r["model"], pt, ct)
            conn.execute(
                "UPDATE agent_runs SET prompt_tokens=?, completion_tokens=?, "
                "cost_usd=? WHERE id=?",
                (pt, ct, cost, r["id"]),
            )

    conn.execute(
        "UPDATE workspace SET schema_version = ? WHERE id = 1",
        (SCHEMA_VERSION,),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _canonical_key(target_class: str, target_method: str, bug_class: str,
                   file: str, line: int) -> str:
    """Stable identity for dedup + quorum.

    line is bucketed to a 5-line span so adjacent reports of the same
    bug collapse to one canonical key.
    """
    line_bucket = (line // 5) * 5
    raw = f"{target_class}|{target_method}|{bug_class}|{file}|{line_bucket}"
    return _sha256(raw)


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), isolation_level=None,  # autocommit; we manage txns
                           timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


class Store:
    """Workspace SQLite store. Thread-safe via per-thread connections.

    Open with `Store.open(workspace_path)`.
    """
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        self._tl = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._tl, "c", None)
        if c is None:
            c = _connect(self.path)
            self._tl.c = c
        return c

    @classmethod
    def open(cls, workspace_path: Path) -> "Store":
        db_path = workspace_path / "findings.db"
        is_new = not db_path.exists()
        store = cls(db_path)
        # Force connection on the calling thread, run schema if new.
        c = store.conn
        if is_new:
            c.executescript(_load_schema())
            c.execute(
                "INSERT OR IGNORE INTO workspace (id, name, target_repo, schema_version) VALUES (1, ?, ?, ?)",
                (workspace_path.name, "", SCHEMA_VERSION),
            )
        else:
            _migrate(c)
        return store

    def close(self) -> None:
        c = getattr(self._tl, "c", None)
        if c is not None:
            c.close()
            self._tl.c = None

    @contextmanager
    def tx(self):
        """Explicit transaction (autocommit mode otherwise).

        BEGIN IMMEDIATE acquires the SQLite write lock; concurrent threads
        from other connections wait via busy_timeout.
        """
        c = self.conn
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

    # ---------- workspace ----------

    def set_target_repo(self, target_repo: str) -> None:
        self.conn.execute("UPDATE workspace SET target_repo = ? WHERE id = 1", (target_repo,))

    def get_target_repo(self) -> str:
        row = self.conn.execute("SELECT target_repo FROM workspace WHERE id = 1").fetchone()
        return row["target_repo"] if row else ""

    # ---------- versioning ----------

    def upsert_catalog_version(self, body: str, rationale: str = "") -> int:
        h = _sha256(body)
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO catalog_versions (content_hash, body, rationale) VALUES (?, ?, ?)",
            (h, body, rationale),
        )
        if cur.rowcount:
            return cur.lastrowid
        return self.conn.execute(
            "SELECT id FROM catalog_versions WHERE content_hash = ?", (h,)
        ).fetchone()["id"]

    def upsert_mitigations_version(self, body: str, rationale: str = "") -> int:
        h = _sha256(body)
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO mitigations_versions (content_hash, body, rationale) VALUES (?, ?, ?)",
            (h, body, rationale),
        )
        if cur.rowcount:
            return cur.lastrowid
        return self.conn.execute(
            "SELECT id FROM mitigations_versions WHERE content_hash = ?", (h,)
        ).fetchone()["id"]

    def upsert_prompt_version(self, agent_name: str, template_text: str) -> int:
        h = _sha256(template_text)
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO prompt_versions (agent_name, template_hash) VALUES (?, ?)",
            (agent_name, h),
        )
        if cur.rowcount:
            return cur.lastrowid
        return self.conn.execute(
            "SELECT id FROM prompt_versions WHERE agent_name = ? AND template_hash = ?",
            (agent_name, h),
        ).fetchone()["id"]

    def latest_catalog(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM catalog_versions ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def latest_mitigations(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM mitigations_versions ORDER BY id DESC LIMIT 1"
        ).fetchone()

    # ---------- cycles ----------

    def start_cycle(self, catalog_id: int, mitigations_id: int, target_sha: str) -> int:
        # Mark any leftover 'running' rows as aborted (crash recovery).
        self.conn.execute(
            "UPDATE cycles SET status = 'aborted', ended_at = ? WHERE status = 'running'",
            (_utc_now(),),
        )
        nrow = self.conn.execute("SELECT COALESCE(MAX(n), 0) AS m FROM cycles").fetchone()
        n = nrow["m"] + 1
        self.conn.execute(
            "INSERT INTO cycles (n, status, catalog_version_id, mitigations_version_id, target_sha) "
            "VALUES (?, 'running', ?, ?, ?)",
            (n, catalog_id, mitigations_id, target_sha),
        )
        return n

    def finish_cycle(self, n: int, score: float, breakdown: dict, notes: str = "") -> None:
        self.conn.execute(
            "UPDATE cycles SET status='complete', ended_at=?, score=?, breakdown_json=?, notes=? WHERE n=?",
            (_utc_now(), score, json.dumps(breakdown), notes, n),
        )

    def latest_cycle(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM cycles ORDER BY n DESC LIMIT 1"
        ).fetchone()

    def cycle_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS c FROM cycles").fetchone()["c"]

    # ---------- agent runs ----------

    def record_agent_run(
        self,
        cycle_n: int,
        agent_name: str,
        slot: str,
        model: str,
        cli_version: str,
        prompt_version_id: int,
        rendered_prompt: str,
        raw_response: Optional[str],
        parse_status: str,
        parsed_json: Optional[dict],
        started_at: str,
        ended_at: str,
        duration_ms: int,
        exit_code: int,
        error_message: str = "",
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        cost_usd: Optional[float] = None,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO agent_runs (
                cycle_n, agent_name, slot, model, cli_version, prompt_version_id,
                rendered_prompt, prompt_hash, raw_response, response_hash,
                parse_status, parsed_json, started_at, ended_at, duration_ms,
                exit_code, error_message,
                prompt_tokens, completion_tokens, cost_usd
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cycle_n, agent_name, slot, model, cli_version, prompt_version_id,
                rendered_prompt, _sha256(rendered_prompt),
                raw_response, _sha256(raw_response) if raw_response else None,
                parse_status,
                json.dumps(parsed_json) if parsed_json else None,
                started_at, ended_at, duration_ms, exit_code, error_message,
                prompt_tokens, completion_tokens, cost_usd,
            ),
        )
        return cur.lastrowid

    # ---------- claims ----------

    def insert_claim(self, run_id: int, cycle_n: int, claim: dict,
                     catalog_id: int, mitigations_id: int, target_sha: str) -> int:
        cls = claim["target_class"]
        meth = claim["target_method"]
        bc = claim["bug_class"]
        op = claim.get("unchecked_op") or {}
        op_file = op.get("file", "")
        op_line = int(op.get("line") or 0)
        mc = claim.get("missing_check") or {}
        mc_file = mc.get("file")
        mc_line = mc.get("line")
        ck = _canonical_key(cls, meth, bc, op_file, op_line)
        cur = self.conn.execute(
            """INSERT INTO claims (
                agent_run_id, cycle_n, canonical_key, target_class, target_method,
                bug_class, unchecked_op_file, unchecked_op_line,
                missing_check_file, missing_check_line,
                claim_type, builds_on, trust_type, severity,
                reachability, primitive, patch_counterfactual,
                catalog_match, novel, body, state, state_reason,
                catalog_version_id, mitigations_version_id, target_sha
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', '', ?, ?, ?)""",
            (
                run_id, cycle_n, ck, cls, meth, bc, op_file, op_line,
                mc_file, mc_line,
                claim.get("type", "fresh"),
                claim.get("builds_on"),
                claim.get("trust_type"),
                claim.get("severity"),
                claim.get("reachability", ""),
                claim.get("primitive", ""),
                claim["patch_counterfactual"],
                claim.get("catalog_match"),
                1 if claim.get("novel") else 0,
                claim.get("body", ""),
                catalog_id, mitigations_id, target_sha,
            ),
        )
        return cur.lastrowid

    def find_duplicate_claim(self, canonical_key: str, exclude_id: Optional[int] = None) -> Optional[sqlite3.Row]:
        if exclude_id is None:
            return self.conn.execute(
                "SELECT * FROM claims WHERE canonical_key = ? AND state IN ('confirmed','settled') ORDER BY id LIMIT 1",
                (canonical_key,),
            ).fetchone()
        return self.conn.execute(
            "SELECT * FROM claims WHERE canonical_key = ? AND id != ? AND state IN ('confirmed','settled') ORDER BY id LIMIT 1",
            (canonical_key, exclude_id),
        ).fetchone()

    def update_claim_state(self, claim_id: int, state: str, reason: str = "") -> None:
        self.conn.execute(
            "UPDATE claims SET state = ?, state_reason = ?, updated_at = ? WHERE id = ?",
            (state, reason, _utc_now(), claim_id),
        )

    def get_claim_state_reason(self, claim_id: int) -> str:
        """Return the current ``state_reason`` for a claim (or '' if none)."""
        row = self.conn.execute(
            "SELECT state_reason FROM claims WHERE id = ?", (claim_id,),
        ).fetchone()
        return (row["state_reason"] if row else "") or ""

    def claims_in_cycle(self, cycle_n: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM claims WHERE cycle_n = ? ORDER BY id",
            (cycle_n,),
        ).fetchall())

    def cleans_in_cycle(self, cycle_n: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM cleans WHERE cycle_n = ? ORDER BY id",
            (cycle_n,),
        ).fetchall())

    def claims_by_state(self, state: str, limit: int = 100) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM claims WHERE state = ? ORDER BY id DESC LIMIT ?",
            (state, limit),
        ).fetchall())

    def claim_by_id(self, claim_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM claims WHERE id = ?", (claim_id,)
        ).fetchone()

    # ---------- validations ----------

    def record_validation(self, claim_id: int, run_id: int, model: str, parsed: dict) -> int:
        verdict = parsed["verdict"]
        cur = self.conn.execute(
            """INSERT INTO validations (
                claim_id, agent_run_id, model, verdict, code, rationale,
                literal_quote, patch_check
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                claim_id, run_id, model, verdict,
                parsed.get("code"),
                parsed.get("rationale", ""),
                json.dumps(parsed.get("literal_source_quote")) if parsed.get("literal_source_quote") else None,
                parsed.get("patch_check"),
            ),
        )
        return cur.lastrowid

    # ---------- challenges ----------

    def record_challenge(self, claim_id: int, run_id: int, model: str, phase: str,
                         parsed: dict, target_file_sha: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO challenges (
                claim_id, agent_run_id, model, phase, verdict, rationale,
                disproved_axis, evidence_json, target_file_sha
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                claim_id, run_id, model, phase,
                parsed["verdict"],
                parsed.get("rationale", ""),
                parsed.get("disproved_axis"),
                json.dumps(parsed.get("evidence", [])),
                target_file_sha,
            ),
        )
        return cur.lastrowid

    def survives_count(self, claim_id: int) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM challenges WHERE claim_id = ? AND verdict = 'survives'",
            (claim_id,),
        ).fetchone()["c"]

    # ---------- cleans ----------

    def insert_clean(self, run_id: int, cycle_n: int, parsed: dict, model: str,
                     catalog_id: int, mitigations_id: int, target_sha: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO cleans (
                agent_run_id, cycle_n, target_class, target_method, model,
                checks_verified_json, body,
                catalog_version_id, mitigations_version_id, target_sha
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, cycle_n,
                parsed["target_class"], parsed["target_method"], model,
                json.dumps(parsed.get("checks_verified", [])),
                parsed.get("body", ""),
                catalog_id, mitigations_id, target_sha,
            ),
        )
        return cur.lastrowid

    def update_clean_spot_check(self, clean_id: int, run_id: int, verdict: str) -> None:
        self.conn.execute(
            "UPDATE cleans SET spot_check_verdict = ?, spot_check_run_id = ? WHERE id = ?",
            (verdict, run_id, clean_id),
        )

    def mark_clean_quorum_skip(self, clean_id: int) -> None:
        """Mark a clean as having its spot-check skipped because the
        cross-vendor pair on the same method already returned CLEAN."""
        self.conn.execute(
            "UPDATE cleans SET spot_check_verdict = 'quorum_skip', spot_check_run_id = NULL WHERE id = ?",
            (clean_id,),
        )

    # ---------- cost telemetry ----------

    def cost_summary(self, since_cycles: Optional[int] = None) -> dict:
        """Aggregate cost + token + duration across agent_runs.

        If since_cycles is given, restrict to runs in the last N cycles
        (by cycle_n; out-of-band runs with cycle_n IS NULL are included).
        """
        where = ""
        params: tuple = ()
        if since_cycles is not None:
            where = "WHERE cycle_n IS NULL OR cycle_n >= COALESCE((SELECT MAX(n) FROM cycles), 0) - ?"
            params = (since_cycles,)
        rows = list(self.conn.execute(
            f"""SELECT
                  agent_name,
                  model,
                  COUNT(*)                           AS n_runs,
                  COALESCE(SUM(prompt_tokens), 0)    AS prompt_tokens,
                  COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                  COALESCE(SUM(cost_usd), 0.0)       AS cost_usd,
                  SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) AS n_unknown_cost,
                  COALESCE(SUM(duration_ms), 0)      AS duration_ms
                FROM agent_runs
                {where}
                GROUP BY agent_name, model
                ORDER BY cost_usd DESC, agent_name, model""",
            params,
        ).fetchall())
        total_cost = sum((r["cost_usd"] or 0.0) for r in rows)
        total_runs = sum(r["n_runs"] for r in rows)
        total_unknown = sum(r["n_unknown_cost"] for r in rows)
        return {
            "rows": rows,
            "total_cost_usd": total_cost,
            "total_runs": total_runs,
            "total_unknown_cost_runs": total_unknown,
        }

    # ---------- targets ----------

    def replace_targets(self, rows: Iterable[dict]) -> None:
        with self.tx():
            self.conn.execute("DELETE FROM targets")
            self.conn.executemany(
                """INSERT OR IGNORE INTO targets (
                    target_class, target_method, bug_class_hint, reason,
                    campaign, sub_area, source_path
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [(r["target_class"], r["target_method"],
                  r.get("bug_class_hint") or "",  # coerce NULL to empty string for PK safety
                  r.get("reason"), r.get("campaign"), r.get("sub_area"),
                  r.get("source_path")) for r in rows],
            )

    def all_targets(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM targets ORDER BY campaign, sub_area, target_method"
        ).fetchall())

    # ---------- per-method health (computed) ----------

    def method_health(self, target_class: str, target_method: str,
                      catalog_id: int, mitigations_id: int) -> dict:
        """Computed (not stored). Bound to current epoch."""
        confirmed = self.conn.execute(
            "SELECT COUNT(*) AS c FROM claims WHERE target_class=? AND target_method=? "
            "AND state IN ('confirmed','settled')",
            (target_class, target_method),
        ).fetchone()["c"]
        cleans_in_epoch = self.conn.execute(
            "SELECT COUNT(DISTINCT model) AS c, COUNT(*) AS total FROM cleans "
            "WHERE target_class=? AND target_method=? AND catalog_version_id=? "
            "AND mitigations_version_id=?",
            (target_class, target_method, catalog_id, mitigations_id),
        ).fetchone()
        last_audit = self.conn.execute(
            "SELECT MAX(cycle_n) AS m FROM cleans WHERE target_class=? AND target_method=?",
            (target_class, target_method),
        ).fetchone()["m"]
        last_finding = self.conn.execute(
            "SELECT MAX(cycle_n) AS m FROM claims WHERE target_class=? AND target_method=?",
            (target_class, target_method),
        ).fetchone()["m"]
        return {
            "confirmed": confirmed,
            "clean_count_epoch": cleans_in_epoch["total"] or 0,
            "distinct_clean_vendors_epoch": cleans_in_epoch["c"] or 0,
            "last_audit_cycle": last_audit,
            "last_finding_cycle": last_finding,
        }

    def least_recently_audited(self, limit: int,
                               catalog_id: Optional[int] = None,
                               mitigations_id: Optional[int] = None) -> list[sqlite3.Row]:
        """Return targets ordered by least-recently-audited. Used by the
        orchestrator for deterministic per-cycle target preselection.

        Match on target_method with flexible class matching to handle
        cases where targets.md has 'WebCore::StoreABL' but auditors
        output 'WebCore::CARingBuffer::StoreABL' as the class.

        When `catalog_id` and `mitigations_id` are passed, each row
        gains an `epoch_stale` column: 1 if the method's latest clean
        was recorded under a different `(catalog_version_id,
        mitigations_version_id)` epoch than the current one (meaning
        the catalog/mitigations have changed since this method was
        last cleaned and a re-audit is warranted under the new
        knowledge), 0 otherwise. Methods with no cleans yet have
        `epoch_stale=0` since they are already prioritized via
        `last_seen=0` (Phase 1 untouched).
        """
        if catalog_id is not None and mitigations_id is not None:
            return list(self.conn.execute(
                """SELECT t.*,
                      COALESCE((SELECT MAX(cycle_n) FROM cleans c
                                  WHERE c.target_method=t.target_method
                                    AND (c.target_class=t.target_class
                                         OR c.target_class LIKE '%' || t.target_class || '%'
                                         OR t.target_class LIKE '%' || c.target_class || '%')),
                               (SELECT MAX(cycle_n) FROM claims cl
                                  WHERE cl.target_method=t.target_method
                                    AND (cl.target_class=t.target_class
                                         OR cl.target_class LIKE '%' || t.target_class || '%'
                                         OR t.target_class LIKE '%' || cl.target_class || '%')),
                               0) AS last_seen,
                      CASE
                        WHEN EXISTS (
                          SELECT 1 FROM cleans c
                          WHERE c.target_method=t.target_method
                            AND (c.target_class=t.target_class
                                 OR c.target_class LIKE '%' || t.target_class || '%'
                                 OR t.target_class LIKE '%' || c.target_class || '%')
                            AND c.id = (
                              SELECT MAX(c2.id) FROM cleans c2
                              WHERE c2.target_method=t.target_method
                                AND (c2.target_class=t.target_class
                                     OR c2.target_class LIKE '%' || t.target_class || '%'
                                     OR t.target_class LIKE '%' || c2.target_class || '%')
                            )
                            AND (c.catalog_version_id != ?
                                 OR c.mitigations_version_id != ?)
                        ) THEN 1
                        ELSE 0
                      END AS epoch_stale
                    FROM targets t
                    ORDER BY last_seen ASC, t.target_method ASC
                    LIMIT ?""",
                (catalog_id, mitigations_id, limit),
            ).fetchall())

        return list(self.conn.execute(
            """SELECT t.*,
                  COALESCE((SELECT MAX(cycle_n) FROM cleans c
                              WHERE c.target_method=t.target_method
                                AND (c.target_class=t.target_class
                                     OR c.target_class LIKE '%' || t.target_class || '%'
                                     OR t.target_class LIKE '%' || c.target_class || '%')),
                           (SELECT MAX(cycle_n) FROM claims cl
                              WHERE cl.target_method=t.target_method
                                AND (cl.target_class=t.target_class
                                     OR cl.target_class LIKE '%' || t.target_class || '%'
                                     OR t.target_class LIKE '%' || cl.target_class || '%')),
                           0) AS last_seen
                FROM targets t
                ORDER BY last_seen ASC, t.target_method ASC
                LIMIT ?""",
            (limit,),
        ).fetchall())

    # ---------- raw_commits (legacy import) ----------

    def upsert_raw_commit(self, sha: str, subject: str, body: str,
                          author_date: str, parse_status: str,
                          parsed_fields: dict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO raw_commits
               (sha, subject, body, author_date, parse_status, parsed_fields_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (sha, subject, body, author_date, parse_status,
             json.dumps(parsed_fields)),
        )

    def raw_commit_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS c FROM raw_commits").fetchone()["c"]
