"""Cycle orchestrator. Pure Python; LLM calls only at the leaves.

One cycle:
    1. begin_cycle: snapshot catalog/mitigations/target_sha, mark cycles row 'running'
    2. preselect_targets: deterministic least-recently-audited per slot
    3. dispatch auditor cohort in parallel
    4. for each CLAIM:
         a. validator (opposite vendor) — accept/reject
         b. if accept and pre_commit_challenge_enabled:
              dispatch BOTH challengers; either reverts → state=contested
              both survive → state=confirmed
            else: state=confirmed
       for each CLEAN:
         a. clean-check (opposite vendor) — confirm/found_claim
         b. found_claim → recurse into validator path
    5. post-commit challenger: re-challenge older confirmed/settled findings
       only if catalog/mitigations changed since their last challenge OR
       target file SHA changed
    6. refinement: produce new catalog.md / mitigations.md from cycle results
    7. score + finish_cycle
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import agent_invoke
from . import dispatch as dispatch_mod
from . import parse as parse_mod
from . import render
from . import score as score_mod
from . import status as status_mod
from .store.db import Store, _utc_now
from .store.workspace import (
    WorkspaceConfig,
    parse_targets,
    read_text,
    write_text,
)

log = logging.getLogger("autosearch.orchestrator")


# ---------- helpers ----------


def _git_sha(repo: Path, ref: str = "HEAD") -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", ref],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _git_file_sha(repo: Path, file_rel: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%H", "--", file_rel],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _source_path_slug(source_path: str) -> str:
    return source_path.strip("/").replace("/", "_")


def _brief(value: object, limit: int = 220) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[:limit - 3].rstrip() + "..."


def _line_ref(item: dict) -> str:
    file = str(item.get("file") or "").strip()
    line = str(item.get("line") or "").strip()
    if file and line and line != "0":
        return f"{file}:{line}"
    if file:
        return file
    if line and line != "0":
        return f"line {line}"
    return "unknown"


def _existing_check_ref(check: dict) -> str:
    line = str(check.get("line") or "").strip()
    if not check or not line or line == "0":
        return "none recorded"
    return _line_ref(check)


def _method_matches_target(method: str, target: dict) -> bool:
    target_method = str(target.get("target_method") or "").strip()
    target_class = str(target.get("target_class") or "").strip()
    if not method or not target_method:
        return False
    qualified = f"{target_class}::{target_method}" if target_class else target_method
    return (
        method == qualified
        or method.endswith(f"::{target_method}")
        or target_method in method
    )


def _append_threat_section(lines: list[str], title: str, items: list,
                           formatter, limit: int | None) -> None:
    if not items:
        return
    lines.append(f"{title}:")
    shown = items if limit is None else items[:limit]
    for item in shown:
        lines.append(f"  - {formatter(item)}")
    if limit is not None:
        omitted = len(items) - limit
        if omitted > 0:
            lines.append(f"  - ... {omitted} more omitted")


def _format_threat_model_context(tm: dict, target: dict) -> str:
    """Render per-file threat model JSON as target-focused prompt context."""
    lines: list[str] = []

    area = _brief(tm.get("area"), 260)
    if area:
        lines.append(f"Area: {area}")

    paths = [str(path) for path in tm.get("paths", []) if path]
    if paths:
        lines.append(f"Source files: {', '.join(paths[:3])}")

    entry_points = [
        entry for entry in tm.get("entry_points", [])
        if isinstance(entry, dict)
        and _method_matches_target(str(entry.get("method") or ""), target)
    ]
    _append_threat_section(
        lines,
        "Relevant entry-point note",
        entry_points,
        lambda entry: (
            f"{entry.get('method', '')} at {_line_ref(entry)} - "
            f"{_brief(entry.get('renderer_surface'), 180)}"
        ),
        2,
    )

    _append_threat_section(
        lines,
        "Context assets noted by threat model",
        [asset for asset in tm.get("assets", []) if isinstance(asset, dict)],
        lambda asset: (
            f"{asset.get('name', '')} - {_brief(asset.get('invariant'), 180)}"
        ),
        5,
    )

    def format_sink(sink: dict) -> str:
        check = sink.get("existing_check") if isinstance(sink.get("existing_check"), dict) else {}
        check_ref = _existing_check_ref(check) if check else "none recorded"
        return (
            f"{_line_ref(sink)} [{sink.get('bug_class', 'n/a')}] "
            f"possible {sink.get('op_kind', 'op')} on {sink.get('asset', 'asset')} | "
            f"value/lifetime noted: {_brief(sink.get('driven_by'), 180)} | "
            f"prepass safety note: {check_ref}"
        )

    _append_threat_section(
        lines,
        "Potential areas to inspect from threat model",
        [sink for sink in tm.get("corruption_sinks", []) if isinstance(sink, dict)],
        format_sink,
        None,
    )

    _append_threat_section(
        lines,
        "Values or state noted by threat model",
        [
            value for value in tm.get("attacker_controlled_values", [])
            if isinstance(value, dict)
        ],
        lambda value: (
            f"{_line_ref(value)} {value.get('name', '')} "
            f"({value.get('type', 'value')}; {value.get('range', 'unknown range')}) "
            f"-> {_brief(value.get('downstream_use'), 180)}"
        ),
        8,
    )

    def format_invariant(invariant: dict) -> str:
        held_by = invariant.get("held_by") if isinstance(invariant.get("held_by"), dict) else {}
        held_ref = _line_ref(held_by) if held_by else "unknown"
        return (
            f"{_brief(invariant.get('statement'), 180)} | "
            f"held by: {held_ref} | "
            f"breaks if: {_brief(invariant.get('broken_if'), 180)}"
        )

    _append_threat_section(
        lines,
        "Candidate safety notes from threat model",
        [
            invariant for invariant in tm.get("invariants", [])
            if isinstance(invariant, dict)
        ],
        format_invariant,
        5,
    )

    return "\n".join(lines)


def _threat_model_file_matches_target(tm_file: Path, target: dict) -> bool:
    """Return true when a per-file threat-model JSON belongs to target."""
    source_path = target.get("source_path", "") or ""
    target_class_leaf = (target.get("target_class", "") or "").split("::")[-1]
    stem = tm_file.stem

    if source_path:
        source_slug = _source_path_slug(source_path)
        if stem == source_slug:
            return True

        source_name = Path(source_path).name
        if Path(source_path).suffix and source_name and stem.endswith(f"_{source_name}"):
            return True

    # Fallback for older targets whose source_path only named a directory.
    if target_class_leaf and len(target_class_leaf) > 3 and target_class_leaf in stem:
        return True

    return False


def _normalise_entry_key(text: str) -> str:
    text = re.sub(r"\b[MR]-\d+\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\bcited by cleans?[^.]*\.", "", text, flags=re.IGNORECASE)
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _extract_markdown_entries(markdown: str, prefix: str) -> list[str]:
    """Extract existing `- M-001 ...` / `- R-001 ...` markdown entries."""
    entries: list[str] = []
    current: list[str] = []
    marker = re.compile(rf"^\s*-\s+{re.escape(prefix)}-\d+\b", re.IGNORECASE)
    for line in markdown.splitlines():
        if marker.match(line):
            if current:
                entries.append("\n".join(current).rstrip())
            current = [line.rstrip()]
        elif current and (line.startswith("  ") or not line.strip()):
            if line.strip():
                current.append(line.rstrip())
        elif current:
            entries.append("\n".join(current).rstrip())
            current = []
    if current:
        entries.append("\n".join(current).rstrip())
    return entries


def _entry_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _string_list(value: object, limit: int = 4) -> list[str]:
    if isinstance(value, list):
        values = value
    elif value:
        values = [value]
    else:
        values = []
    result = []
    for item in values:
        text = _brief(item, 100)
        if text:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _format_catalog_entry(entry: dict, idx: int) -> str:
    bug_class = _brief(entry.get("bug_class") or "n/a", 40)
    pattern = _brief(entry.get("pattern") or entry.get("summary"), 180)
    evidence = ", ".join(_string_list(entry.get("evidence") or entry.get("witnesses"), 3))
    applies_when = _brief(entry.get("applies_when"), 140)

    parts = [f"- R-{idx:03d} ({bug_class}): {pattern or 'reusable confirmed-bug pattern'}."]
    if evidence:
        parts.append(f"Evidence: {evidence}.")
    if applies_when:
        parts.append(f"Applies when: {applies_when}.")
    return " ".join(parts)


def _format_mitigation_entry(entry: dict, idx: int) -> str:
    guard_kind = _brief(entry.get("guard_kind") or entry.get("kind") or "guard", 50)
    pattern = _brief(entry.get("pattern") or entry.get("summary") or entry.get("guard"), 190)
    if not pattern:
        return ""
    examples = ", ".join(_string_list(entry.get("witnesses") or entry.get("evidence"), 3))
    applies_when = _brief(entry.get("applies_when"), 130)
    do_not_flag = _brief(entry.get("do_not_flag_unless"), 150)

    parts = [f"- M-{idx:03d} ({guard_kind}) Pattern: {pattern}."]
    if examples:
        parts.append(f"Examples: {examples}.")
    if applies_when:
        parts.append(f"Applies when: {applies_when}.")
    if do_not_flag:
        parts.append(f"Do not flag unless: {do_not_flag}.")
    return " ".join(parts)


def _catalog_candidate_key(entry: dict) -> str:
    return _normalise_entry_key(
        " ".join([
            str(entry.get("bug_class") or ""),
            str(entry.get("pattern") or entry.get("summary") or ""),
            str(entry.get("applies_when") or ""),
        ])
    )


def _mitigation_candidate_key(entry: dict) -> str:
    return _normalise_entry_key(
        " ".join([
            str(entry.get("guard_kind") or entry.get("kind") or ""),
            str(entry.get("pattern") or entry.get("summary") or entry.get("guard") or ""),
            str(entry.get("applies_when") or ""),
            str(entry.get("do_not_flag_unless") or ""),
        ])
    )


def _merge_refinement_entries(current_md: str, prefix: str, title: str,
                              intro: str, new_entries: list,
                              formatter, max_entries: int, keyer=None) -> str:
    entries = _extract_markdown_entries(current_md, prefix)
    seen = {_normalise_entry_key(entry) for entry in entries}
    for candidate in new_entries:
        if not isinstance(candidate, dict):
            continue
        formatted = formatter(candidate, len(entries) + 1)
        if not formatted:
            continue
        candidate_keys = {
            _normalise_entry_key(formatted),
        }
        if keyer is not None:
            candidate_keys.add(keyer(candidate))
        candidate_keys = {key for key in candidate_keys if key}
        if not candidate_keys or candidate_keys & seen:
            continue
        entries.append(formatted)
        seen.update(candidate_keys)
        if len(entries) >= max_entries:
            break

    entries = entries[:max_entries]
    renumbered = [
        re.sub(rf"^(\s*-\s+){re.escape(prefix)}-\d+\b",
               rf"\1{prefix}-{idx:03d}", entry, count=1, flags=re.IGNORECASE)
        for idx, entry in enumerate(entries, start=1)
    ]
    body = "\n\n".join(renumbered)
    return f"# {title}\n\n{intro}\n\n{body}\n" if body else f"# {title}\n\n{intro}\n"


MAX_MITIGATION_GROUPS = 16
MAX_MITIGATION_CHARS = 6500
MAX_MITIGATION_GROWTH_CHARS = 800
MIN_INITIAL_MITIGATION_CHARS = 4000


def _renumber_entries(entries: list[str], prefix: str) -> list[str]:
    return [
        re.sub(rf"^(\s*-\s+){re.escape(prefix)}-\d+\b",
               rf"\1{prefix}-{idx:03d}", entry, count=1, flags=re.IGNORECASE)
        for idx, entry in enumerate(entries, start=1)
    ]


def _render_mitigation_entries(entries: list[str], max_chars: int) -> str:
    header = (
        "# Mitigations\n\n"
        "Pattern-based reusable guards that repeatedly refute speculative "
        "memory-corruption hypotheses. File:line evidence is only an example "
        "of the pattern.\n"
    )
    selected: list[str] = []
    for entry in _renumber_entries(entries, "M"):
        candidate = header + "\n" + "\n\n".join(selected + [entry]) + "\n"
        if len(candidate) > max_chars and selected:
            break
        if len(candidate) > max_chars:
            continue
        selected.append(entry)
    if not selected:
        return header
    return header + "\n" + "\n\n".join(selected) + "\n"


def _cap_grouped_mitigations_md(new_md: str, current_md: str) -> str:
    """Enforce grouped, pattern-based mitigation size limits."""
    new_md = (new_md or "").strip()
    if not new_md:
        return current_md.strip()

    entries = [
        entry for entry in _extract_markdown_entries(new_md, "M")
        if re.search(r"\bPattern\s*:", entry)
    ]
    if not entries:
        return current_md.strip()

    allowed_chars = min(
        MAX_MITIGATION_CHARS,
        max(len(current_md.strip()), MIN_INITIAL_MITIGATION_CHARS) + MAX_MITIGATION_GROWTH_CHARS,
    )
    if len(current_md.strip()) > MAX_MITIGATION_CHARS:
        allowed_chars = MAX_MITIGATION_CHARS

    if (
        len(entries) <= MAX_MITIGATION_GROUPS
        and len(new_md) <= allowed_chars
        and new_md.lower().startswith("# mitigations")
    ):
        return "\n".join(new_md.splitlines()).strip()

    capped_entries = entries[:MAX_MITIGATION_GROUPS]
    return _render_mitigation_entries(capped_entries, allowed_chars).strip()


def _apply_structured_refinement(catalog_md: str, mitigations_md: str,
                                 parsed: dict) -> tuple[str, str]:
    catalog_entries = _entry_list(parsed.get("catalog_entries"))
    mitigation_entries = _entry_list(parsed.get("mitigation_entries"))

    new_catalog = _merge_refinement_entries(
        catalog_md,
        "R",
        "Catalog",
        "Reusable confirmed memory-corruption patterns. Keep only broad patterns with source evidence.",
        catalog_entries,
        _format_catalog_entry,
        max_entries=20,
        keyer=_catalog_candidate_key,
    )
    new_mitigations = _merge_refinement_entries(
        mitigations_md,
        "M",
        "Mitigations",
        "Pattern-based reusable guards that repeatedly refute speculative memory-corruption hypotheses. File:line evidence is only an example of the pattern.",
        mitigation_entries,
        _format_mitigation_entry,
        max_entries=24,
        keyer=_mitigation_candidate_key,
    )
    return new_catalog.strip(), new_mitigations.strip()


def _opposite_vendor(model: str, available: list[str]) -> str:
    """Pick a model from a different vendor family than `model`."""
    is_opus = "opus" in model.lower() or "claude" in model.lower()
    for m in available:
        is_other = ("opus" in m.lower() or "claude" in m.lower()) != is_opus
        if is_other:
            return m
    return available[0] if available else model


# ---------- orchestrator ----------


@dataclass
class Orchestrator:
    workspace: Path
    config: WorkspaceConfig
    store: Store
    dispatcher: dispatch_mod.Dispatcher
    status_writer: status_mod.StatusWriter
    force_targets: Optional[list[dict]] = None  # debug: force preselection

    # ---------- top-level ----------

    def run_cycle(self) -> dict:
        """Run one full audit cycle. Returns the breakdown dict."""
        # Make the workspace dir discoverable to the dispatcher (oracle lookup
        # and any other code that needs the workspace but receives target_repo
        # as cwd). Idempotent — set on every cycle in case env was cleared.
        import os as _os
        _os.environ["AUTOSEARCH_WORKSPACE"] = str(self.workspace)

        # 1. snapshot epoch
        catalog_md = read_text(self.workspace / "rules" / "catalog.md")
        mitigations_md = read_text(self.workspace / "rules" / "mitigations.md")
        targets_md = read_text(self.workspace / "targets.md")

        catalog_id = self.store.upsert_catalog_version(catalog_md)
        mitigations_id = self.store.upsert_mitigations_version(mitigations_md)

        # refresh targets table from targets.md
        target_rows = parse_targets(targets_md)
        if target_rows:
            self.store.replace_targets(target_rows)

        target_sha = _git_sha(self.config.target_repo)
        cycle_n = self.store.start_cycle(catalog_id, mitigations_id, target_sha)
        log.info("cycle %d started (catalog=%d mitigations=%d target_sha=%s)",
                 cycle_n, catalog_id, mitigations_id, target_sha[:12])

        # Per-cycle log directory: every agent run mirrored as a JSON file.
        self._cycle_log_dir = self.workspace / "logs" / "cycles" / f"{cycle_n:06d}"
        self._cycle_log_dir.mkdir(parents=True, exist_ok=True)
        # Drop a manifest of cycle metadata.
        import json as _json
        (self._cycle_log_dir / "manifest.json").write_text(_json.dumps({
            "cycle_n": cycle_n,
            "started_at": _utc_now(),
            "catalog_version_id": catalog_id,
            "mitigations_version_id": mitigations_id,
            "target_sha": target_sha,
            "config": {
                "cohort_size": self.config.cohort_size,
                "cohort_models": self.config.cohort_models,
                "challenger_models": self.config.challenger_models,
                "refinement_model": self.config.refinement_model,
                "pre_commit_challenge_enabled": self.config.pre_commit_challenge_enabled,
            },
        }, indent=2))

        self.status_writer.update(
            cycle=cycle_n,
            workspace=str(self.workspace),
            target_repo=str(self.config.target_repo),
        )
        # Drop completed/failed entries from the prior cycle so the
        # "Active subagents" panel doesn't accumulate dozens of stale
        # rows. In-flight (pending/running) entries are preserved
        # (defensive: they shouldn't exist at cycle start, but if a
        # subagent leaked through it stays visible).
        self.status_writer.clear_completed_subagents()
        self.status_writer.set_phase("audit")

        breakdown = score_mod.CycleBreakdown()

        # 2. preselect targets — one per "method slot"
        slots = self._preselect_targets(
            self.config.cohort_methods,
            catalog_id=catalog_id,
            mitigations_id=mitigations_id,
        )
        if not slots:
            log.warning("no targets in workspace; cycle %d will be empty", cycle_n)

        # 3. dispatch auditor cohort (methods × models_per_method, parallel)
        cohort_results = self._run_auditor_cohort(
            cycle_n, slots, catalog_id, mitigations_id, target_sha,
            catalog_md, mitigations_md, targets_md,
        )

        # 3b. quorum detection: claims by canonical_key (≥2 distinct vendors)
        quorum_keys = self._detect_quorum(cohort_results)
        if quorum_keys:
            log.info("cycle %d: claim quorum reached on %d canonical key(s): %s",
                     cycle_n, len(quorum_keys), list(quorum_keys))

        # 3b'. mirror for cleans: methods where ≥2 distinct vendors agreed CLEAN.
        # Used to skip the redundant cross-vendor clean-check (the agreement IS it).
        clean_quorum_methods = self._detect_clean_quorum(cohort_results)
        if clean_quorum_methods:
            log.info("cycle %d: clean quorum on %d method(s); skipping their clean-check",
                     cycle_n, len(clean_quorum_methods))

        # 3c. pre-compute per-result flags (is_dup, is_quorum, is_clean_quorum)
        # so the parallel fan-out has no shared mutable state to race on.
        from .store.db import _canonical_key
        dispatch_flags: list[dict] = []
        seen_for_dispatch: set[str] = set()
        for r in cohort_results:
            parsed = r.get("parsed")
            is_dup = False
            is_quorum = False
            is_clean_quorum = False
            if parsed and parsed.get("kind") == "claim":
                try:
                    op = parsed.get("unchecked_op") or {}
                    ck = _canonical_key(
                        parsed.get("target_class", ""),
                        parsed.get("target_method", ""),
                        parsed.get("bug_class", ""),
                        op.get("file", "") or "",
                        int(op.get("line") or 0),
                    )
                    is_quorum = ck in quorum_keys
                    is_dup = ck in seen_for_dispatch
                    if not is_dup:
                        seen_for_dispatch.add(ck)
                except Exception:
                    pass
            elif parsed and parsed.get("kind") == "clean":
                try:
                    key = (parsed["target_class"], parsed["target_method"])
                    is_clean_quorum = key in clean_quorum_methods
                except (KeyError, TypeError):
                    pass
            dispatch_flags.append({
                "is_dup": is_dup,
                "is_quorum": is_quorum,
                "is_clean_quorum": is_clean_quorum,
            })

        # 4. parallel per-result processing
        # Each worker returns a CycleBreakdown delta — no shared mutables.
        # Per-thread DB connections handle SQLite safety natively.
        self.status_writer.set_phase("post_audit")
        deltas: list[score_mod.CycleBreakdown] = []
        if cohort_results:
            def work(idx_res: tuple[int, dict]) -> score_mod.CycleBreakdown:
                idx, res = idx_res
                # bug_class_hint comes from the target row (set by threat-modeler).
                # Used by Phase 3 oracle citation enforcement on cleans.
                tgt = res.get("target") or {}
                bug_class_hint = (tgt.get("bug_class_hint") or "").strip() or None
                return self._process_audit_result(
                    cycle_n, res, catalog_id, mitigations_id, target_sha,
                    catalog_md, mitigations_md, targets_md,
                    is_dup=dispatch_flags[idx]["is_dup"],
                    is_quorum=dispatch_flags[idx]["is_quorum"],
                    is_clean_quorum=dispatch_flags[idx]["is_clean_quorum"],
                    bug_class_hint=bug_class_hint,
                )
            with cf.ThreadPoolExecutor(max_workers=max(1, len(cohort_results))) as ex:
                futures = [ex.submit(work, (i, r)) for i, r in enumerate(cohort_results)]
                deltas = [f.result() for f in futures]
            for d in deltas:
                breakdown += d

        # 5. (removed) — post-commit challenger phase merged into the
        # in-cycle challenger gate inside _process_claim. Each new claim now
        # passes a single adversarial-review round; rerunning the same
        # `challenger.md` prompt later didn't catch anything we couldn't
        # have caught the first time.

        # 6. refinement
        self.status_writer.set_phase("learn")
        self._refinement(cycle_n, catalog_id, mitigations_id, target_sha)

        # 7. score
        score = score_mod.compute_score(breakdown)
        self.store.finish_cycle(cycle_n, score, score_mod.to_dict(breakdown))
        self.status_writer.set_phase("idle")

        log.info("cycle %d complete: score=%.2f breakdown=%s",
                 cycle_n, score, score_mod.to_dict(breakdown))
        return {"cycle": cycle_n, "score": score, "breakdown": score_mod.to_dict(breakdown)}

    # ---------- target selection ----------

    def _preselect_targets(self, n_slots: int,
                           catalog_id: Optional[int] = None,
                           mitigations_id: Optional[int] = None) -> list[dict]:
        if self.force_targets:
            return self.force_targets[:n_slots] or self.force_targets
        # Fetch a wider pool when epoch-aware boost is active so we can
        # surface stale-epoch methods that may sit deep in the LRA queue.
        # Without epoch context, keep the historical 3× cap.
        if catalog_id is not None and mitigations_id is not None:
            rows = self.store.least_recently_audited(
                limit=10_000,
                catalog_id=catalog_id,
                mitigations_id=mitigations_id,
            )
        else:
            rows = self.store.least_recently_audited(limit=n_slots * 3)
        if not rows:
            return []
        ranked = sorted(rows, key=lambda r: (r["last_seen"] or 0, r["target_method"]))

        # Phase 1: untouched targets get unconditional priority (no sub_area cap).
        # This guarantees 100% coverage within ceil(targets / n_slots) cycles.
        chosen: list[dict] = []
        for r in ranked:
            if not r["last_seen"] or r["last_seen"] == 0:
                chosen.append(dict(r))
                if len(chosen) >= n_slots:
                    break

        # Phase 1.5: epoch-stale boost. Methods whose latest clean was
        # recorded under a different (catalog_version_id,
        # mitigations_version_id) than the current epoch get prioritized
        # over plain LRA. Rationale: refinement may have added a new
        # R-NN catalog rule or M-NN mitigation pattern since this method
        # was last cleaned; the prior CLEAN was issued without that
        # knowledge, so a re-audit under the current epoch is warranted.
        # Capped 2 per sub_area (same as Phase 2) so a catalog edit
        # affecting one area doesn't starve the rest of the cohort.
        if (catalog_id is not None and mitigations_id is not None
                and len(chosen) < n_slots):
            seen_areas: dict[str, int] = {}
            chosen_keys = {(c["target_class"], c["target_method"]) for c in chosen}
            stale_count = 0
            for r in ranked:
                if not r["epoch_stale"]:
                    continue
                key = (r["target_class"], r["target_method"])
                if key in chosen_keys:
                    continue
                area = r["sub_area"] or ""
                seen_areas.setdefault(area, 0)
                if seen_areas[area] >= 2:
                    continue
                chosen.append(dict(r))
                chosen_keys.add(key)
                seen_areas[area] += 1
                stale_count += 1
                if len(chosen) >= n_slots:
                    break
            if stale_count:
                log.info("epoch-stale boost: re-auditing %d method(s) under "
                         "current catalog=%d mitigations=%d",
                         stale_count, catalog_id, mitigations_id)

        # Phase 2: fill remaining slots with least-recently-audited,
        # round-robin across sub_areas for variety (cap 2 per area).
        if len(chosen) < n_slots:
            seen_areas = {}
            chosen_keys = {(c["target_class"], c["target_method"]) for c in chosen}
            for r in ranked:
                key = (r["target_class"], r["target_method"])
                if key in chosen_keys:
                    continue
                area = r["sub_area"] or ""
                seen_areas.setdefault(area, 0)
                if seen_areas[area] >= 2:
                    continue
                chosen.append(dict(r))
                chosen_keys.add(key)
                seen_areas[area] += 1
                if len(chosen) >= n_slots:
                    break

        # Phase 3: if still not full, take anything remaining
        if len(chosen) < n_slots:
            chosen_keys = {(c["target_class"], c["target_method"]) for c in chosen}
            for r in ranked:
                key = (r["target_class"], r["target_method"])
                if key not in chosen_keys:
                    chosen.append(dict(r))
                    chosen_keys.add(key)
                if len(chosen) >= n_slots:
                    break

        return chosen[:n_slots]

    # ---------- cohort dispatch ----------

    def _vendor_of(self, model: str) -> str:
        """Coarse vendor classification used for pairing / opposite-vendor."""
        m = model.lower()
        if "opus" in m or "claude" in m:
            return "anthropic"
        if "gpt" in m:
            return "openai"
        return "other"

    def _models_for_method(self, method_idx: int) -> list[str]:
        """Pick `cohort_models_per_method` models from cohort_models for this
        method, preferring DIFFERENT vendors. Rotates the start position by
        method_idx so the per-vendor load is balanced across the cohort."""
        pool = self.config.cohort_models
        k = max(1, self.config.cohort_models_per_method)
        if not pool:
            return []
        # Group pool by vendor, then pick round-robin across vendors.
        by_vendor: dict[str, list[str]] = {}
        order: list[str] = []
        for m in pool:
            v = self._vendor_of(m)
            if v not in by_vendor:
                by_vendor[v] = []
                order.append(v)
            by_vendor[v].append(m)
        # Rotate vendor order by method_idx so methods get balanced primary vendors.
        order = order[method_idx % len(order):] + order[: method_idx % len(order)]
        chosen: list[str] = []
        v_pos = {v: 0 for v in order}
        i = 0
        while len(chosen) < k:
            v = order[i % len(order)]
            bucket = by_vendor[v]
            if v_pos[v] < len(bucket):
                chosen.append(bucket[v_pos[v]])
                v_pos[v] += 1
            i += 1
            if i > k * 8:  # safety
                # not enough distinct models in the pool; pad by reusing
                while len(chosen) < k and pool:
                    chosen.append(pool[len(chosen) % len(pool)])
                break
        return chosen[:k]

    def _run_auditor_cohort(self, cycle_n: int, slots: list[dict],
                            catalog_id: int, mitigations_id: int, target_sha: str,
                            catalog_md: str, mitigations_md: str,
                            targets_md: str) -> list[dict]:
        """Dispatch (cohort_methods × cohort_models_per_method) auditors in parallel.

        Each method gets `cohort_models_per_method` models from the vendor
        pool, preferring distinct vendors. Slot label encodes both the
        method index and the vendor.
        """
        if not slots:
            return []

        # Build (slot_label, target, model) tuples
        triples: list[tuple[str, dict, str]] = []
        for mi, target in enumerate(slots):
            models = self._models_for_method(mi)
            for vi, model in enumerate(models):
                vendor_short = self._vendor_of(model).split("openai")[0] or "v"
                # short tag for slot: a=anthropic, o=openai, x=other
                vtag = {"anthropic": "a", "openai": "o"}.get(self._vendor_of(model), "x")
                slot_label = f"auditor/m{mi+1}#{vtag}"
                triples.append((slot_label, target, model))

        # status
        sub_status = [
            status_mod.SubagentStatus(
                slot=slot_label,
                agent="auditor",
                model=model,
                target=f"{target['target_class']}::{target['target_method']}",
                state="pending",
            )
            for slot_label, target, model in triples
        ]
        self.status_writer.set_subagents(sub_status)

        confirmed = self._confirmed_findings_digest(limit=50)

        # Build per-file threat model lookup for context enrichment
        threat_model_context_cache: dict[str, str] = {}
        def _get_threat_model_context(target: dict) -> str:
            """Look up per-file threat model context for a target's source file."""
            source_path = target.get("source_path", "") or ""
            if not source_path:
                # Try to derive from target_class
                cls = target.get("target_class", "")
                if cls:
                    source_path = cls.replace("WebCore::", "")
            cache_key = f"{source_path}|{target.get('target_class', '')}"
            if cache_key in threat_model_context_cache:
                return threat_model_context_cache[cache_key]

            # Search for matching per-file threat model
            import glob as _glob
            tm_dirs = sorted(_glob.glob(str(self.workspace / "threat-models" / "*")))
            for tm_dir in reversed(tm_dirs):  # newest first
                if not Path(tm_dir).is_dir():
                    continue
                for tm_file in Path(tm_dir).glob("*.json"):
                    # Match by source path component in filename
                    if _threat_model_file_matches_target(tm_file, target):
                        try:
                            tm = json.loads(tm_file.read_text())
                            if tm.get("kind") != "threat_model":
                                continue
                            result = _format_threat_model_context(tm, target)
                            threat_model_context_cache[cache_key] = result
                            return result
                        except Exception:
                            continue
            threat_model_context_cache[cache_key] = ""
            return ""

        def work(triple) -> dict:
            slot_label, target, model = triple
            tm_context = _get_threat_model_context(target)
            hint_class = (target.get("bug_class_hint") or "").strip()
            hint_reason = (target.get("reason") or "").strip()
            if hint_class and hint_reason:
                target_hint = f"[{hint_class}] {hint_reason}"
            else:
                target_hint = hint_class or hint_reason or "none"
            ctx = {
                "TARGET_REPO": str(self.config.target_repo),
                "TARGET_METHOD": f"{target['target_class']}::{target['target_method']}",
                "TARGET_FILE_HINTS": target.get("source_path", "") or "",
                "TARGET_HINT": target_hint,
                "THREAT_MODEL_CONTEXT": tm_context,
                "CATALOG": catalog_md,
                "MITIGATIONS": mitigations_md,
                "CONFIRMED": confirmed,
                **self.config.overlay_ctx_for_target(
                    target["target_class"], target.get("source_path", "")),
            }
            res = self._invoke_agent(
                cycle_n=cycle_n, agent_name="auditor", slot=slot_label,
                model=model, ctx=ctx,
                catalog_id=catalog_id, mitigations_id=mitigations_id,
                target_sha=target_sha,
                target_label=f"{target['target_class']}::{target['target_method']}",
            )
            return {"slot": slot_label, "model": model, "target": target, **res}

        with cf.ThreadPoolExecutor(max_workers=max(1, len(triples))) as ex:
            futures = [ex.submit(work, t) for t in triples]
            results = [f.result() for f in futures]
        return results

    # ---------- quorum ----------

    def _detect_quorum(self, cohort_results: list[dict]) -> set[str]:
        """Return the set of canonical_keys flagged by ≥2 distinct vendors as CLAIM."""
        from .store.db import _canonical_key
        per_key_vendors: dict[str, set[str]] = {}
        for r in cohort_results:
            parsed = r.get("parsed")
            if not parsed or parsed.get("kind") != "claim":
                continue
            try:
                op = parsed.get("unchecked_op") or {}
                ck = _canonical_key(
                    parsed["target_class"], parsed["target_method"],
                    parsed["bug_class"],
                    op.get("file", "") or "",
                    int(op.get("line") or 0),
                )
            except Exception:
                continue
            v = self._vendor_of(r["model"])
            per_key_vendors.setdefault(ck, set()).add(v)
        return {ck for ck, vendors in per_key_vendors.items() if len(vendors) >= 2}

    def _detect_clean_quorum(self, cohort_results: list[dict]) -> set[tuple[str, str]]:
        """Return the set of (target_class, target_method) pairs where ≥2
        distinct vendors emitted a parseable CLEAN.

        Symmetric to `_detect_quorum` for claims. Used by `_process_clean`
        to skip the redundant clean-check call when both vendors already
        agreed CLEAN on the same method (the agreement IS the cross-vendor
        verification — same logic as quorum-skip on the CLAIM path).
        """
        per_method_vendors: dict[tuple[str, str], set[str]] = {}
        for r in cohort_results:
            parsed = r.get("parsed")
            if not parsed or parsed.get("kind") != "clean":
                continue
            try:
                key = (parsed["target_class"], parsed["target_method"])
            except (KeyError, TypeError):
                continue
            v = self._vendor_of(r["model"])
            per_method_vendors.setdefault(key, set()).add(v)
        return {key for key, vendors in per_method_vendors.items() if len(vendors) >= 2}

    # ---------- per-result handling ----------

    def _process_audit_result(self, cycle_n: int, res: dict,
                              catalog_id: int, mitigations_id: int, target_sha: str,
                              catalog_md: str, mitigations_md: str, targets_md: str,
                              is_dup: bool, is_quorum: bool,
                              is_clean_quorum: bool,
                              bug_class_hint: Optional[str] = None) -> score_mod.CycleBreakdown:
        """Pure: returns the breakdown delta for one cohort result.

        No shared mutable state — safe to call concurrently from a thread pool.
        """
        bd = score_mod.CycleBreakdown()
        parsed = res["parsed"]
        if not parsed:
            bd.parse_failed += 1
            return bd
        kind = parsed.get("kind")
        if kind == "claim":
            bd += self._process_claim(
                cycle_n, res, parsed,
                catalog_id, mitigations_id, target_sha,
                catalog_md, mitigations_md, targets_md,
                is_dup=is_dup, is_quorum=is_quorum,
            )
        elif kind == "clean":
            bd += self._process_clean(
                cycle_n, res, parsed,
                catalog_id, mitigations_id, target_sha,
                catalog_md, mitigations_md, targets_md,
                is_clean_quorum=is_clean_quorum,
                bug_class_hint=bug_class_hint,
            )
        else:
            log.warning("auditor %s emitted unexpected kind=%s; skipping",
                        res["slot"], kind)
        return bd

    def _process_claim(self, cycle_n: int, res: dict, claim: dict,
                       catalog_id: int, mitigations_id: int, target_sha: str,
                       catalog_md: str, mitigations_md: str, targets_md: str,
                       is_dup: bool, is_quorum: bool) -> score_mod.CycleBreakdown:
        """Pure: returns CycleBreakdown delta. No shared state mutated."""
        bd = score_mod.CycleBreakdown()

        if is_dup:
            # Quorum dup: record as a 'superseded' claim so the corpus is
            # honest about the second vendor's evidence. Don't validate or
            # challenge it (the primary claim handles those phases).
            dup_id = self.store.insert_claim(
                run_id=res["agent_run_id"], cycle_n=cycle_n, claim=claim,
                catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
            )
            self.store.update_claim_state(
                dup_id, "superseded",
                f"quorum dup (cycle {cycle_n})",
            )
            return bd

        # Insert the claim in 'proposed' state.
        claim_id = self.store.insert_claim(
            run_id=res["agent_run_id"], cycle_n=cycle_n, claim=claim,
            catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
        )

        # Validator (opposite vendor) — SKIPPED on quorum.
        # The second auditor (different vendor) emitting the same canonical
        # claim IS an independent cross-vendor verification; running another
        # opposite-vendor pass against the same code is redundant.
        if is_quorum:
            self.store.update_claim_state(
                claim_id, "validated", "skipped (quorum: 2 vendors agreed at audit time)",
            )
        else:
            validator_model = _opposite_vendor(res["model"], self.config.cohort_models)
            v_ctx = {
                "TARGET_REPO": str(self.config.target_repo),
                "CLAIM_JSON": json.dumps(claim, indent=2),
                "CATALOG": catalog_md,
                "MITIGATIONS": mitigations_md,
                "CONFIRMED": self._confirmed_findings_digest(limit=50),
                "TARGETS": targets_md,
                **self.config.overlay_ctx_for_target(
                    claim.get("target_class", ""), claim.get("unchecked_op_file", "")),
            }
            v_res = self._invoke_agent(
                cycle_n=cycle_n, agent_name="validator", slot=f"validator/{res['slot']}",
                model=validator_model, ctx=v_ctx,
                catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
                target_label=f"{claim.get('target_class','?')}::{claim.get('target_method','?')} [{claim.get('bug_class','?')}]",
            )
            if not v_res["parsed"]:
                self.store.update_claim_state(claim_id, "rejected", "validator parse_failed")
                bd.pruned += 1
                return bd
            v_parsed = v_res["parsed"]
            self.store.record_validation(claim_id, v_res["agent_run_id"],
                                          validator_model, v_parsed)
            if v_parsed.get("verdict") == "reject":
                code = v_parsed.get("code", "UNKNOWN")
                # Special case: WRONG_BUG_CLASS means the validator agrees the
                # underlying op exists and is unchecked, but disputes the bug-class
                # label the auditor chose. The bug is real; the taxonomy is wrong.
                # Treat it as "validated" (don't reject), proceed to challenger
                # gate, and the final state_reason will preserve the dispute via
                # `confirmed-class-disputed` so manual triage can re-classify.
                if code == "WRONG_BUG_CLASS":
                    log.info(
                        "claim #%d: validator says WRONG_BUG_CLASS (op real, "
                        "label disputed); proceeding to challenger as validated",
                        claim_id,
                    )
                    self.store.update_claim_state(
                        claim_id, "validated",
                        "validator:WRONG_BUG_CLASS (op real, class label disputed)",
                    )
                else:
                    self.store.update_claim_state(claim_id, "rejected", f"validator:{code}")
                    if code == "OFF_TARGET":
                        bd.off_target += 1
                    else:
                        bd.pruned += 1
                    return bd
            else:
                # Validated normally
                self.store.update_claim_state(claim_id, "validated", "validator accepted")

        # Challenger gate (single round, both vendors in parallel).
        # Phase is recorded as "pre_commit" in the challenges table for
        # schema compatibility (the CHECK constraint only allows
        # 'pre_commit' or 'post_commit'). Semantically it IS the
        # pre-commit-style adversarial review — we just removed the
        # redundant post-commit pass that ran the same prompt later.
        if self.config.pre_commit_challenge_enabled:
            survives_count, reverter = self._run_challengers(
                cycle_n, claim_id, claim, "pre_commit",
                catalog_id, mitigations_id, target_sha,
                catalog_md, mitigations_md, targets_md,
            )
            if reverter:
                self.store.update_claim_state(
                    claim_id, "contested",
                    f"challenger {reverter} reverted",
                )
                bd.contested += 1
                return bd

        # Confirmed (terminal state for new claims; "settled" is a historical
        # state from when post-commit challenger was a separate phase).
        # If the validator OR challenger earlier flagged WRONG_BUG_CLASS,
        # preserve that signal in the confirm reason so manual triage knows
        # the bug-class label is disputed even though the underlying bug
        # is real.
        last_state = self.store.get_claim_state_reason(claim_id) or ""
        validator_disputed = "WRONG_BUG_CLASS" in last_state
        challenger_disputed = "challenger:wrong_bug_class" in last_state.lower()
        class_disputed = validator_disputed or challenger_disputed
        if is_quorum:
            confirm_reason = "quorum (2 vendors) + challenger survived"
        else:
            confirm_reason = "validator + challenger survived"
        if class_disputed:
            who = []
            if validator_disputed: who.append("validator")
            if challenger_disputed: who.append("challenger")
            confirm_reason += f" (class label disputed by {' & '.join(who)})"
        self.store.update_claim_state(claim_id, "confirmed", confirm_reason)
        sev_bucket = score_mod.classify_severity(claim)
        if sev_bucket == "high":
            bd.mem_high += 1
        elif sev_bucket == "medium":
            bd.mem_medium += 1
        else:
            bd.mem_low += 1
        if claim.get("type") == "deepen":
            bd.deepened += 1
        elif claim.get("type") == "chain":
            bd.chained += 1
        return bd

    def _process_clean(self, cycle_n: int, res: dict, clean: dict,
                       catalog_id: int, mitigations_id: int, target_sha: str,
                       catalog_md: str, mitigations_md: str, targets_md: str,
                       is_clean_quorum: bool = False,
                       bug_class_hint: Optional[str] = None) -> score_mod.CycleBreakdown:
        """Pure: returns CycleBreakdown delta. No shared state mutated.

        If `is_clean_quorum=True`, both vendors on this method already returned
        CLEAN — skip the cross-vendor clean-check call (the agreement IS the
        cross-vendor verification). The clean is still recorded with
        spot_check_verdict='quorum_skip' so the corpus is honest about why
        no spot-check ran.

        ``bug_class_hint``: from the target row. If set to a high-risk
        bug class (RACE_*, UAF, ...), Phase 3 oracle citation enforcement
        runs on this clean; missing/insufficient citations cause the
        clean to be marked ``unverified_citation`` and the cross-vendor
        clean-check is forced to run regardless of quorum.
        """
        bd = score_mod.CycleBreakdown()

        # ---- Phase 3: factsheet citation enforcement on cleans ----
        citation_error: Optional[str] = None
        if bug_class_hint:
            try:
                from .oracles import validate_factsheet_citations
                check = validate_factsheet_citations(
                    {**clean, "kind": "clean"}, bug_class_hint=bug_class_hint,
                )
                if not check.ok:
                    citation_error = check.error
                    log.warning(
                        "phase3 citation gap on clean for %s::%s [hint=%s]: %s",
                        clean.get("target_class"), clean.get("target_method"),
                        bug_class_hint, check.error,
                    )
            except Exception as e:  # noqa: BLE001
                log.debug("phase3 citation check skipped: %s", e)

        clean_id = self.store.insert_clean(
            run_id=res["agent_run_id"], cycle_n=cycle_n, parsed=clean,
            model=res["model"],
            catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
        )

        # If citations are missing on a high-risk bug-class hint, force
        # the clean-check to run even on quorum, so a second vendor
        # independently re-verifies rather than relying on a shared,
        # unsupported assumption.
        if citation_error and is_clean_quorum:
            log.info("phase3: forcing clean-check on %s::%s despite quorum "
                     "(missing citations for hint=%s)",
                     clean.get("target_class"), clean.get("target_method"),
                     bug_class_hint)
            is_clean_quorum = False

        if is_clean_quorum:
            # Skip the redundant cross-vendor clean-check; the cross-vendor
            # CLEAN agreement already provides the verification.
            self.store.mark_clean_quorum_skip(clean_id)
            bd.clean += 1
            return bd

        # Cross-model spot-check
        check_model = _opposite_vendor(res["model"], self.config.cohort_models)
        ctx = {
            "TARGET_REPO": str(self.config.target_repo),
            "CLAIM_JSON": json.dumps(clean, indent=2),
            "TARGETS": targets_md,
            "CATALOG": catalog_md,
            "MITIGATIONS": mitigations_md,
            **self.config.overlay_ctx_for_target(
                clean.get("target_class", ""), clean.get("unchecked_op_file", "")),
        }
        cc_res = self._invoke_agent(
            cycle_n=cycle_n, agent_name="clean-check",
            slot=f"clean-check/{res['slot']}", model=check_model, ctx=ctx,
            catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
            target_label=f"{clean.get('target_class','?')}::{clean.get('target_method','?')}",
        )
        if not cc_res["parsed"]:
            bd.clean += 1
            return bd
        cc_parsed = cc_res["parsed"]
        verdict = cc_parsed.get("verdict", "confirm")
        self.store.update_clean_spot_check(clean_id, cc_res["agent_run_id"], verdict)
        if verdict == "found_claim" and cc_parsed.get("claim"):
            # Recurse: process the discovered claim as a single fresh claim.
            embedded = cc_parsed["claim"]
            embedded_res = {
                "slot": cc_res.get("slot", "clean-check"),
                "model": check_model,
                "agent_run_id": cc_res["agent_run_id"],
                "parsed": embedded,
            }
            bd += self._process_claim(
                cycle_n, embedded_res, embedded,
                catalog_id, mitigations_id, target_sha,
                catalog_md, mitigations_md, targets_md,
                is_dup=False, is_quorum=False,
            )
        else:
            bd.clean += 1
        return bd

    # ---------- challengers ----------

    def _run_challengers(self, cycle_n: int, claim_id: int, claim: dict, phase: str,
                          catalog_id: int, mitigations_id: int, target_sha: str,
                          catalog_md: str, mitigations_md: str, targets_md: str) -> tuple[int, Optional[str]]:
        """Returns (survives_count, first_reverter_model_or_None)."""
        models = self.config.challenger_models
        if not models:
            return 0, None
        ctx_base = {
            "TARGET_REPO": str(self.config.target_repo),
            "HASH": str(claim_id),
            "FULL_FINDING_JSON": json.dumps(claim, indent=2),
            "TARGETS": targets_md,
            "CATALOG": catalog_md,
            "MITIGATIONS": mitigations_md,
            **self.config.overlay_ctx_for_target(
                claim.get("target_class", ""), claim.get("unchecked_op_file", "")),
        }
        results = []

        def work(i: int, model: str) -> tuple[str, dict]:
            slot = f"challenger/{phase}#{i+1}"
            res = self._invoke_agent(
                cycle_n=cycle_n, agent_name="challenger", slot=slot,
                model=model, ctx=ctx_base,
                catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
                target_label=f"#{claim_id} {claim.get('target_class','?')}::{claim.get('target_method','?')} [{claim.get('bug_class','?')}]",
            )
            return model, res

        with cf.ThreadPoolExecutor(max_workers=len(models)) as ex:
            for model, res in ex.map(lambda im: work(im[0], im[1]), enumerate(models)):
                results.append((model, res))

        survives = 0
        reverter = None
        # Track whether any reverter only disputed the bug-class label rather
        # than the underlying op. Symmetric with the validator-side
        # WRONG_BUG_CLASS branch in _process_claim: when the challenger
        # acknowledges the unchecked op exists but only quibbles about the
        # taxonomy label, that's NOT a real disproof — preserve the bug.
        class_disputed = False
        for model, res in results:
            if not res["parsed"]:
                # Ambiguous; treat as survives (don't kill the finding on parse failure)
                survives += 1
                continue
            verdict = res["parsed"].get("verdict", "survives")
            target_file_sha = _git_file_sha(
                self.config.target_repo, claim.get("unchecked_op", {}).get("file", ""),
            )
            self.store.record_challenge(
                claim_id=claim_id, run_id=res["agent_run_id"],
                model=model, phase=phase, parsed=res["parsed"],
                target_file_sha=target_file_sha,
            )
            if verdict == "reverted":
                axis = (res["parsed"].get("disproved_axis") or "").strip().lower()
                if axis == "wrong_bug_class":
                    # Challenger admits the unchecked op exists; only the
                    # bug-class label is wrong. Treat as survives so the bug
                    # is preserved, and flag for the final-confirm reason
                    # to carry the "(class label disputed by ...)" marker.
                    log.info(
                        "claim #%d: challenger %s revert axis=wrong_bug_class "
                        "(op real, label disputed); treating as survives",
                        claim_id, model,
                    )
                    survives += 1
                    class_disputed = True
                elif reverter is None:
                    reverter = model
            elif verdict == "survives":
                survives += 1

        # Annotate the claim row so the final-confirm logic in _process_claim
        # picks up the dispute marker. Idempotent: append-only marker, never
        # overrides an existing validator-side dispute.
        if class_disputed and not reverter:
            existing = self.store.get_claim_state_reason(claim_id) or ""
            if "WRONG_BUG_CLASS" not in existing:
                self.store.update_claim_state(
                    claim_id,
                    "validated",
                    (existing + " | challenger:wrong_bug_class").strip(" |"),
                )

        return survives, reverter

    # ---------- refinement ----------

    def _refinement(self, cycle_n: int, catalog_id: int, mitigations_id: int,
                     target_sha: str) -> None:
        # Process BOTH claims and cleans. Refinement on cleans-only cycles
        # harvests file:line guards from `checks_verified` into mitigations.md;
        # no R-NN catalog rules are added without at least one confirmed claim.
        claims_payload = []
        for c in self.store.claims_in_cycle(cycle_n):
            claims_payload.append({
                "id": c["id"],
                "target_class": c["target_class"],
                "target_method": c["target_method"],
                "bug_class": c["bug_class"],
                "state": c["state"],
                "state_reason": c["state_reason"],
                "claim_type": c["claim_type"],
                "severity": c["severity"],
            })
        cleans_payload = []
        for c in self.store.cleans_in_cycle(cycle_n):
            checks = []
            try:
                checks = json.loads(c["checks_verified_json"] or "[]")
            except Exception:
                pass
            cleans_payload.append({
                "id": c["id"],
                "target_class": c["target_class"],
                "target_method": c["target_method"],
                "model": c["model"],
                "spot_check_verdict": c["spot_check_verdict"],
                "checks_verified": checks,
            })
        if not claims_payload and not cleans_payload:
            log.info("cycle %d: no audit results — skipping refinement", cycle_n)
            return

        # No-new-signal short-circuit: refinement is the cycle's longest
        # synchronous step (~10-12 min on a saturated mitigations.md), and on
        # all-trivial-clean cycles it produces verbatim output. Skip when
        # there's nothing actionable: no claim moved past the auditor stage,
        # AND every clean is trivial-shape (no checks_verified guards to
        # harvest into mitigations.md).
        SIGNAL_STATES = {"validated", "contested", "confirmed",
                         "settled", "reverted", "rejected"}
        has_claim_signal = any(
            c["state"] in SIGNAL_STATES for c in claims_payload
        )
        has_verified_clean = any(
            c["checks_verified"] for c in cleans_payload
        )
        if not has_claim_signal and not has_verified_clean:
            log.info(
                "cycle %d: no new signal (0 claims past auditor, 0 verified "
                "cleans) — skipping refinement (saved ~12min wall)",
                cycle_n,
            )
            return

        log.info("cycle %d: running refinement (%d claims, %d cleans, "
                 "%d verified)",
                  cycle_n, len(claims_payload), len(cleans_payload),
                  sum(1 for c in cleans_payload if c["checks_verified"]))
        catalog_md = read_text(self.workspace / "rules" / "catalog.md")
        mitigations_md = read_text(self.workspace / "rules" / "mitigations.md")
        ctx = {
            "TARGET_REPO": str(self.config.target_repo),
            "LAST_CYCLE_RESULTS": json.dumps(claims_payload, indent=2),
            "LAST_CYCLE_CLEANS": json.dumps(cleans_payload, indent=2),
            "CATALOG": catalog_md,
            "MITIGATIONS": mitigations_md,
            **self.config.overlay_ctx(),
        }
        res = self._invoke_agent(
            cycle_n=cycle_n, agent_name="refinement", slot="refinement",
            model=self.config.refinement_model, ctx=ctx,
            catalog_id=catalog_id, mitigations_id=mitigations_id, target_sha=target_sha,
            target_label=f"cycle {cycle_n} learn ({len(claims_payload)}c/{len(cleans_payload)}cl)",
        )
        if not res["parsed"]:
            log.warning("cycle %d: refinement parse_failed", cycle_n)
            return
        parsed = res["parsed"]
        if "catalog_entries" in parsed:
            new_catalog, _ = _apply_structured_refinement(
                catalog_md,
                mitigations_md,
                {
                    "catalog_entries": parsed.get("catalog_entries", []),
                    "mitigation_entries": [],
                },
            )
        else:
            new_catalog = parsed.get("catalog_md", "").strip()

        if parsed.get("mitigations_md"):
            new_mitigations = _cap_grouped_mitigations_md(
                parsed.get("mitigations_md", ""),
                mitigations_md,
            )
        elif "mitigation_entries" in parsed:
            # Backward compatibility for structured-entry refinement outputs.
            _, new_mitigations = _apply_structured_refinement(
                catalog_md,
                mitigations_md,
                {
                    "catalog_entries": [],
                    "mitigation_entries": parsed.get("mitigation_entries", []),
                },
            )
            new_mitigations = _cap_grouped_mitigations_md(new_mitigations, mitigations_md)
        else:
            # Backward compatibility for older full-file refinement outputs.
            new_mitigations = _cap_grouped_mitigations_md(
                parsed.get("mitigations_md", ""),
                mitigations_md,
            )
        if new_catalog and new_catalog != catalog_md.strip():
            write_text(self.workspace / "rules" / "catalog.md", new_catalog + "\n")
            self.store.upsert_catalog_version(new_catalog + "\n",
                                                rationale=parsed.get("rationale", ""))
        if new_mitigations and new_mitigations != mitigations_md.strip():
            write_text(self.workspace / "rules" / "mitigations.md", new_mitigations + "\n")
            self.store.upsert_mitigations_version(new_mitigations + "\n",
                                                    rationale=parsed.get("rationale", ""))

    # ---------- generic agent invocation with parse + repair ----------

    def _invoke_agent(self, cycle_n: int, agent_name: str, slot: str,
                       model: str, ctx: dict,
                       catalog_id: int, mitigations_id: int, target_sha: str,
                       target_label: str = "") -> dict:
        # Central status-writer registration: every agent dispatch
        # (auditor, validator, challenger, clean-check, refinement) shows
        # up in the TUI's "Active subagents" panel.
        #
        # Auditor cohort pre-registers slots as state="pending" via
        # set_subagents() so the panel shows what's about to run; for
        # those, this just transitions to "running". Everyone else
        # (validator/challenger/clean-check/refinement) is dispatched
        # ad-hoc — we add_subagent() on entry.
        sw = self.status_writer
        if sw.has_subagent(slot):
            sw.update_subagent(slot, state="running",
                                started_at=_utc_now(),
                                target=target_label or None)
        else:
            sw.add_subagent(status_mod.SubagentStatus(
                slot=slot, agent=agent_name, model=model,
                target=target_label, state="running",
                started_at=_utc_now(),
            ))

        res = agent_invoke.invoke(
            store=self.store,
            dispatcher=self.dispatcher,
            agent_name=agent_name,
            slot=slot,
            model=model,
            ctx=ctx,
            cycle_n=cycle_n,
            target_repo=self.config.target_repo,
            agent_timeout_s=self.config.agent_timeout_seconds,
            log_dir=getattr(self, "_cycle_log_dir", None),
        )

        # Derive a short outcome string for the panel from the parsed
        # JSON. Different agent kinds expose verdicts on different keys.
        outcome = ""
        if res["parsed"]:
            p = res["parsed"]
            kind = p.get("kind", "")
            verdict = p.get("verdict", "")
            code = p.get("code", "")
            decision = p.get("decision", "")
            if verdict:
                outcome = (verdict.upper() + (f"({code})" if code else ""))[:18]
            elif decision:
                outcome = decision.upper()[:18]
            elif kind == "claim":
                outcome = "CLAIM"
            elif kind == "clean":
                outcome = "CLEAN"
            else:
                outcome = (kind or "OK").upper()[:18]
        else:
            outcome = "PARSE_FAIL"
        sw.update_subagent(
            slot,
            state="completed" if res["parsed"] else "failed",
            ended_at=_utc_now(),
            outcome=outcome,
        )
        return res

    # ---------- digests ----------

    def _recent_findings_digest(self, limit: int) -> str:
        rows = self.store.conn.execute(
            "SELECT cycle_n, target_class, target_method, bug_class, state "
            "FROM claims ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if not rows:
            return "(no prior findings)"
        return "\n".join(
            f"c{r['cycle_n']} {r['state']:>10} {r['target_class']}::{r['target_method']} [{r['bug_class']}]"
            for r in rows
        )

    def _confirmed_findings_digest(self, limit: int) -> str:
        rows = self.store.conn.execute(
            "SELECT id, cycle_n, target_class, target_method, bug_class "
            "FROM claims WHERE state IN ('confirmed','settled') ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if not rows:
            return "(none yet)"
        return "\n".join(
            f"c{r['cycle_n']} #{r['id']} {r['target_class']}::{r['target_method']} [{r['bug_class']}]"
            for r in rows
        )
