"""The SSVC-style decision tree: signals -> remediation category.

A pure lookup over the three inputs (``exploitation`` x ``exposure`` x
``severity``) from ``signals``. The table is the one agreed in
``archive/notes/PLANO_PRIORIZACAO.md`` — deterministic and auditable, no LLM.

Categories, most to least urgent: Act > Attend > Track* > Track.
"""
from __future__ import annotations

ACT = "Act"
ATTEND = "Attend"
TRACK_STAR = "Track*"
TRACK = "Track"

# Sort key: lower = more urgent (drives within-queue ordering by category).
CATEGORY_ORDER = {ACT: 0, ATTEND: 1, TRACK_STAR: 2, TRACK: 3}

# (exploitation, exposure, severity) -> category. See PLANO_PRIORIZACAO.md §tree.
_TREE: dict[tuple[str, str, str], str] = {
    ("active", "exposed", "high"): ACT,
    ("active", "exposed", "medium"): ACT,
    ("active", "exposed", "low"): ATTEND,
    ("active", "internal", "high"): ACT,
    ("active", "internal", "medium"): ATTEND,
    ("active", "internal", "low"): TRACK_STAR,
    ("likely", "exposed", "high"): ACT,
    ("likely", "exposed", "medium"): ATTEND,
    ("likely", "exposed", "low"): TRACK_STAR,
    ("likely", "internal", "high"): ATTEND,
    ("likely", "internal", "medium"): TRACK_STAR,
    ("likely", "internal", "low"): TRACK,
    ("none", "exposed", "high"): ATTEND,
    ("none", "exposed", "medium"): TRACK_STAR,
    ("none", "exposed", "low"): TRACK,
    ("none", "internal", "high"): TRACK_STAR,
    ("none", "internal", "medium"): TRACK,
    ("none", "internal", "low"): TRACK,
    # "unknown" = no CVE, so exploitation can't be assessed. Treated one notch
    # above "none" (same row as "likely"): we don't get to discount it as safe.
    ("unknown", "exposed", "high"): ACT,
    ("unknown", "exposed", "medium"): ATTEND,
    ("unknown", "exposed", "low"): TRACK_STAR,
    ("unknown", "internal", "high"): ATTEND,
    ("unknown", "internal", "medium"): TRACK_STAR,
    ("unknown", "internal", "low"): TRACK,
}


def decide(exploitation: str, exposure: str, severity: str) -> str:
    """Map the three signals to a category. Raises ``KeyError`` on bad input
    (a missing combination is a bug, not a value to swallow)."""
    return _TREE[(exploitation, exposure, severity)]
