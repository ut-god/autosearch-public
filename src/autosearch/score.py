"""Per-cycle scoring formula. Pure function over a breakdown dict."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict, fields


SEVERITY_HIGH = {"Critical", "High"}
SEVERITY_MEDIUM = {"Medium"}
SEVERITY_LOW = {"Low"}

# Bug classes that count as "high-impact" memcorr regardless of severity tag
HIGH_IMPACT_CLASSES = {
    "OOB_WRITE", "HEAP_OVERFLOW", "UAF", "DOUBLE_FREE",
    "TYPE_CONFUSION", "ARBITRARY_RW",
}
MEDIUM_IMPACT_CLASSES = {
    "OOB_READ", "INT_OVERFLOW_TO_OOB", "UNINIT_READ",
}
LOW_IMPACT_CLASSES = {
    "RACE_TO_OOB", "RACE_TO_UAF",
}


@dataclass
class CycleBreakdown:
    mem_high: int = 0
    mem_medium: int = 0
    mem_low: int = 0
    deepened: int = 0
    chained: int = 0
    pruned: int = 0
    clean: int = 0
    survived: int = 0
    reverted: int = 0
    contested: int = 0
    off_target: int = 0
    parse_failed: int = 0

    def __iadd__(self, other: "CycleBreakdown") -> "CycleBreakdown":
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name))
        return self

    def __add__(self, other: "CycleBreakdown") -> "CycleBreakdown":
        out = CycleBreakdown()
        for f in fields(self):
            setattr(out, f.name, getattr(self, f.name) + getattr(other, f.name))
        return out


def classify_severity(claim: dict) -> str:
    """Map a claim row to a severity bucket: 'high' | 'medium' | 'low'."""
    bc = claim.get("bug_class") or claim.get("bug_class_hint") or ""
    if bc in HIGH_IMPACT_CLASSES:
        return "high"
    if bc in MEDIUM_IMPACT_CLASSES:
        return "medium"
    if bc in LOW_IMPACT_CLASSES:
        return "low"
    sev = claim.get("severity") or ""
    if sev in SEVERITY_HIGH:
        return "high"
    if sev in SEVERITY_MEDIUM:
        return "medium"
    return "low"


def compute_score(breakdown: CycleBreakdown) -> float:
    score = (
        breakdown.mem_high * 5.0
        + breakdown.mem_medium * 3.0
        + breakdown.mem_low * 1.0
        + breakdown.deepened * 4.0
        + breakdown.chained * 5.0
        + breakdown.pruned * 0.1
        + breakdown.clean * 0.1
        + breakdown.survived * 0.5
        - breakdown.reverted * 2.0
        - breakdown.off_target * 1.0
    )
    return round(score, 2)


def to_dict(breakdown: CycleBreakdown) -> dict:
    return asdict(breakdown)
