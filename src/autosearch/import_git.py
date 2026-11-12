"""Legacy `[autosearch] ...` git-commit importer.

Walks a target git branch (or HEAD), parses every commit whose subject
starts with `[autosearch] ...`, and writes raw rows to `raw_commits`.
Materialization queries on the workspace then derive structured
claims/cleans/challenges from the staging table.

Idempotent by SHA. Safe to re-run.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .store.db import Store, _canonical_key
from .targets import split_qualified_target


_SUBJECT_RE = re.compile(
    r"^\[autosearch\]\s+(?P<gate>confirmed|pruned|clean|challenge-survived|challenge-reverted|init|log)\b"
    r"(?:\s+(?P<target>\S+))?"
)

# Field lines look like:  type: fresh
_FIELD_RE = re.compile(r"^(?P<key>type|bug_class|trust|severity|builds_on|gate)\s*:\s*(?P<val>.+?)\s*$",
                       re.MULTILINE)
_FILE_LINE_RE = re.compile(
    r"\b(?:(Source/[\w/.-]+)|([A-Z][\w/.-]+\.(?:cpp|h|c|mm|hh|hpp|cc)))"
    r":(\d+)\b"
)


@dataclass
class ParsedCommit:
    sha: str
    subject: str
    body: str
    author_date: str
    gate: str
    target_class: str
    target_method: str
    fields: dict
    file_line: Optional[tuple[str, int]]


def _git_log(repo: Path, ref: str) -> list[tuple[str, str, str, str]]:
    """Return list of (sha, author_date, subject, body) tuples."""
    sep = "\x1e"
    field_sep = "\x1f"
    out = subprocess.run(
        ["git", "-C", str(repo), "log", "--no-merges",
         f"--format=%H{field_sep}%aI{field_sep}%s{field_sep}%b{sep}", ref],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        raise RuntimeError(f"git log failed: {out.stderr}")
    rows = []
    for raw in out.stdout.split(sep):
        raw = raw.strip("\n")
        if not raw:
            continue
        parts = raw.split(field_sep, 3)
        if len(parts) < 4:
            continue
        rows.append(tuple(parts))
    return rows


def parse_commit(sha: str, author_date: str, subject: str, body: str,
                 default_namespace: str = "WebCore") -> Optional[ParsedCommit]:
    m = _SUBJECT_RE.match(subject)
    if not m:
        return None
    gate = m.group("gate")
    target = (m.group("target") or "").strip()
    target_class = ""
    target_method = ""
    split = split_qualified_target(target)
    if split:
        target_class, target_method = split
        # Add namespace prefix if missing (legacy commits often omit it)
        if target_class and "::" not in target_class and default_namespace:
            target_class = f"{default_namespace}::{target_class}"
    fields = {fm.group("key"): fm.group("val").strip() for fm in _FIELD_RE.finditer(body)}
    file_line = None
    fl = _FILE_LINE_RE.search(body)
    if fl:
        # group(1) = Source/... path; group(2) = bare filename; group(3) = line
        file_path = fl.group(1) or fl.group(2)
        file_line = (file_path, int(fl.group(3)))
    return ParsedCommit(
        sha=sha,
        subject=subject,
        body=body,
        author_date=author_date,
        gate=gate,
        target_class=target_class,
        target_method=target_method,
        fields=fields,
        file_line=file_line,
    )


def import_branch(store: Store, repo: Path, ref: str = "HEAD",
                  progress_cb=None) -> dict:
    """Walk every commit in `repo` reachable from `ref`, write all
    `[autosearch]` commits to `raw_commits`. Returns counts.
    """
    rows = _git_log(repo, ref)
    counts = {"total_commits": len(rows), "matched": 0, "parsed": 0,
              "partial": 0, "unparseable": 0}

    with store.tx():
        for i, (sha, ad, subj, body) in enumerate(rows):
            if not subj.startswith("[autosearch]"):
                continue
            counts["matched"] += 1
            parsed = parse_commit(sha, ad, subj, body)
            if parsed is None:
                store.upsert_raw_commit(sha, subj, body, ad, "unparseable", {})
                counts["unparseable"] += 1
                continue
            status = "parsed"
            if not parsed.fields and not parsed.file_line:
                status = "partial"
            payload = {
                "gate": parsed.gate,
                "target_class": parsed.target_class,
                "target_method": parsed.target_method,
                "fields": parsed.fields,
                "file_line": parsed.file_line,
            }
            store.upsert_raw_commit(sha, subj, body, ad, status, payload)
            counts[status] += 1
            if progress_cb and i % 50 == 0:
                progress_cb(i, len(rows))
    return counts


# ---------- materialization (read-only on staging, writes to claims/etc.) ----------


def materialize(store: Store, dry_run: bool = False) -> dict:
    """Derive `claims`, `cleans`, `challenges` from `raw_commits`.

    Materialization is conservative: only `confirmed`, `clean`,
    `pruned`, `challenge-survived`, `challenge-reverted` gates are
    materialized. `init` and `log` rows are kept in raw_commits only.

    A synthetic catalog/mitigations version (id=0 means "imported
    from git, version unknown") is created on first import.
    """
    counts = {"claims_inserted": 0, "cleans_inserted": 0,
              "challenges_inserted": 0, "skipped": 0}
    catalog_id = store.upsert_catalog_version(
        body="# imported from git\n",
        rationale="synthetic version for legacy git-commit imports",
    )
    mitigations_id = store.upsert_mitigations_version(
        body="# imported from git\n",
        rationale="synthetic version for legacy git-commit imports",
    )
    # Synthetic cycle row that all imports map to.
    cycle_n = store.start_cycle(catalog_id, mitigations_id, "imported")
    rows = store.conn.execute(
        "SELECT * FROM raw_commits WHERE parse_status IN ('parsed','partial') ORDER BY author_date"
    ).fetchall()
    # build a sha → claim_id map for challenge linkage
    claim_by_sha: dict[str, int] = {}
    with store.tx():
        for r in rows:
            payload = json.loads(r["parsed_fields_json"]) if r["parsed_fields_json"] else {}
            gate = payload.get("gate")
            tc = payload.get("target_class") or ""
            tm = payload.get("target_method") or ""
            fields = payload.get("fields") or {}
            file_line = payload.get("file_line") or [None, None]
            file = file_line[0] if file_line else ""
            line = file_line[1] if file_line else 0
            bug_class = fields.get("bug_class", "")
            severity = fields.get("severity", "")
            trust = fields.get("trust", "")
            claim_type = fields.get("type", "fresh")
            builds_on = fields.get("builds_on", "")
            if not tc and not tm:
                counts["skipped"] += 1
                continue

            if gate == "confirmed":
                # synthesize a minimal claim row
                if dry_run:
                    counts["claims_inserted"] += 1
                    continue
                cur = store.conn.execute(
                    """INSERT INTO claims (
                        agent_run_id, cycle_n, canonical_key,
                        target_class, target_method, bug_class,
                        unchecked_op_file, unchecked_op_line,
                        missing_check_file, missing_check_line,
                        claim_type, builds_on, trust_type, severity,
                        reachability, primitive, patch_counterfactual,
                        catalog_match, novel, body, state, state_reason,
                        catalog_version_id, mitigations_version_id, target_sha
                       ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, '', '',
                                 '(imported from git; counterfactual unknown)',
                                 NULL, 0, ?, 'confirmed', 'imported from git',
                                 ?, ?, ?)""",
                    (
                        cycle_n,
                        _canonical_key(tc, tm, bug_class or "UNKNOWN", file or "", line or 0),
                        tc, tm, bug_class or "UNKNOWN",
                        file or "", line or 0,
                        None, None,
                        claim_type, trust, severity,
                        r["body"] or "",
                        catalog_id, mitigations_id, "imported",
                    ),
                )
                claim_by_sha[r["sha"]] = cur.lastrowid
                counts["claims_inserted"] += 1
            elif gate == "clean":
                if dry_run:
                    counts["cleans_inserted"] += 1
                    continue
                store.conn.execute(
                    """INSERT INTO cleans (
                        agent_run_id, cycle_n, target_class, target_method, model,
                        checks_verified_json, body,
                        catalog_version_id, mitigations_version_id, target_sha
                       ) VALUES (NULL, ?, ?, ?, 'imported', '[]', ?, ?, ?, ?)""",
                    (cycle_n, tc, tm, r["body"] or "",
                     catalog_id, mitigations_id, "imported"),
                )
                counts["cleans_inserted"] += 1
            elif gate in ("challenge-survived", "challenge-reverted"):
                # link to original claim if builds_on hash is known
                target_claim_id = None
                if builds_on:
                    target_claim_id = claim_by_sha.get(builds_on)
                if target_claim_id is None:
                    counts["skipped"] += 1
                    continue
                if dry_run:
                    counts["challenges_inserted"] += 1
                    continue
                verdict = "survives" if gate == "challenge-survived" else "reverted"
                store.conn.execute(
                    """INSERT INTO challenges (
                        claim_id, agent_run_id, model, phase, verdict, rationale,
                        disproved_axis, evidence_json, target_file_sha
                       ) VALUES (?, NULL, 'imported', 'post_commit', ?, ?, NULL, '[]', NULL)""",
                    (target_claim_id, verdict, r["body"] or ""),
                )
                if gate == "challenge-reverted":
                    store.conn.execute(
                        "UPDATE claims SET state='reverted', state_reason='imported challenge-reverted' WHERE id=?",
                        (target_claim_id,),
                    )
                counts["challenges_inserted"] += 1
            elif gate == "pruned":
                if dry_run:
                    counts["claims_inserted"] += 1
                    continue
                store.conn.execute(
                    """INSERT INTO claims (
                        agent_run_id, cycle_n, canonical_key,
                        target_class, target_method, bug_class,
                        unchecked_op_file, unchecked_op_line,
                        missing_check_file, missing_check_line,
                        claim_type, builds_on, trust_type, severity,
                        reachability, primitive, patch_counterfactual,
                        catalog_match, novel, body, state, state_reason,
                        catalog_version_id, mitigations_version_id, target_sha
                       ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, '', '',
                                 '(imported from git; counterfactual unknown)',
                                 NULL, 0, ?, 'rejected', 'imported pruned',
                                 ?, ?, ?)""",
                    (
                        cycle_n,
                        _canonical_key(tc, tm, bug_class or "UNKNOWN", file or "", line or 0),
                        tc, tm, bug_class or "UNKNOWN",
                        file or "", line or 0, None, None,
                        claim_type, trust, severity,
                        r["body"] or "", catalog_id, mitigations_id, "imported",
                    ),
                )
                counts["claims_inserted"] += 1
    store.finish_cycle(cycle_n, score=0.0,
                        breakdown={"imported": True, **counts})
    return counts
