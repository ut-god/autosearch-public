"""Heartbeat status writer for TUI.

Single JSON file the orchestrator atomically rewrites at known phase
transitions. The TUI polls this for live state. Falls back to log
parsing when missing.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class SubagentStatus:
    slot: str
    agent: str
    model: str
    target: str = ""
    state: str = "pending"  # pending | running | completed | failed
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    outcome: str = ""        # CLAIM | CLEAN | ACCEPT | REJECT(...) | SURVIVES | REVERTED


@dataclass
class StatusSnapshot:
    cycle: int = 0
    phase: str = "idle"               # idle | scope | audit | learn | aborted
    phase_started_at: Optional[str] = None
    last_heartbeat: str = field(default_factory=_now)
    subagents: list[SubagentStatus] = field(default_factory=list)
    pid: int = field(default_factory=os.getpid)
    workspace: str = ""
    target_repo: str = ""

    def to_dict(self) -> dict:
        return {
            "cycle": self.cycle,
            "phase": self.phase,
            "phase_started_at": self.phase_started_at,
            "last_heartbeat": _now(),
            "subagents": [asdict(s) for s in self.subagents],
            "pid": self.pid,
            "workspace": self.workspace,
            "target_repo": self.target_repo,
        }


class StatusWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot = StatusSnapshot()
        # Guards subagents list mutations against the threadpool: auditor
        # cohort + validator + challenger + clean-check + refinement can
        # all call into update_subagent / add_subagent concurrently.
        self._lock = threading.Lock()

    def update(self, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(self.snapshot, k, v)
        self._write()

    def set_phase(self, phase: str) -> None:
        self.snapshot.phase = phase
        self.snapshot.phase_started_at = _now()
        self._write()

    def set_subagents(self, subagents: list[SubagentStatus]) -> None:
        with self._lock:
            self.snapshot.subagents = subagents
        self._write()

    def add_subagent(self, sub: SubagentStatus) -> None:
        """Append a dynamically-spawned subagent (validator, challenger,
        clean-check, refinement) that wasn't pre-registered as part of
        a cohort. Auditor pre-registration still goes through
        set_subagents."""
        with self._lock:
            self.snapshot.subagents.append(sub)
        self._write()

    def update_subagent(self, slot: str, **kwargs) -> None:
        with self._lock:
            for s in self.snapshot.subagents:
                if s.slot == slot:
                    for k, v in kwargs.items():
                        setattr(s, k, v)
                    break
        self._write()

    def has_subagent(self, slot: str) -> bool:
        """True iff a subagent with this slot is already registered.
        Used by _invoke_agent to decide between add_subagent (new) and
        update_subagent (auditor pre-registered the slot)."""
        with self._lock:
            return any(s.slot == slot for s in self.snapshot.subagents)

    def clear_completed_subagents(self) -> None:
        """Drop completed/failed entries; keep pending/running. Called
        at cycle start so the panel doesn't accumulate dozens of
        finished entries from prior cycles."""
        with self._lock:
            self.snapshot.subagents = [
                s for s in self.snapshot.subagents
                if s.state in ("pending", "running")
            ]
        self._write()

    def heartbeat(self) -> None:
        self._write()

    def _write(self) -> None:
        # atomic write
        d = self.snapshot.to_dict()
        tmp = tempfile.NamedTemporaryFile(
            "w", delete=False, dir=str(self.path.parent), prefix=".status.", suffix=".tmp"
        )
        try:
            json.dump(d, tmp, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, self.path)
        except Exception:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
            raise
