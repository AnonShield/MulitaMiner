"""Binary presence/absence indicator.

``score`` returns 1.0 when both ``pred`` and ``ref`` are populated, or both
empty; 0.0 on asymmetric presence. Use ``classify`` for downstream
P/R/F1 aggregation that needs to distinguish TP/FP/FN/TN.

Use case: detects field-level omission (pred empty, ref populated) and
field-level hallucination (pred populated, ref empty), independent of
content quality. See metrics.md §3.4.
"""
from __future__ import annotations

NAME = "presence"


def is_populated(value) -> bool:
    """True when ``value`` carries information.

    Strings count when non-blank after strip. Containers (list, tuple, set)
    count when at least one element is itself populated, so a list of empty
    strings does not count as content. Dicts count when non-empty.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set)):
        return any(is_populated(x) for x in value)
    if isinstance(value, dict):
        return bool(value)
    return True  # numerics and other primitives count as populated


def score(pred, ref) -> float:
    return 1.0 if is_populated(pred) == is_populated(ref) else 0.0


def classify(pred, ref) -> str:
    """Return ``'TP'``, ``'FP'``, ``'FN'`` or ``'TN'`` for confusion counting."""
    p, r = is_populated(pred), is_populated(ref)
    if p and r:
        return "TP"
    if p and not r:
        return "FP"
    if not p and r:
        return "FN"
    return "TN"
