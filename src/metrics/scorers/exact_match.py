"""Exact match after default normalization (lowercase + collapsed whitespace).

Use for categorical fields (severity, protocol, source) and identifiers
(Name). Numeric fields should be canonicalized by the caller before scoring,
since equality on Python types is sensitive to int/float/str differences.
"""
from __future__ import annotations

import re

NAME = "exact_match"

_WS = re.compile(r"\s+")


def normalize(value) -> str:
    """Lowercase, strip, collapse internal whitespace. ``None`` → ``''``."""
    if value is None:
        return ""
    return _WS.sub(" ", str(value).strip().lower())


def score(pred, ref) -> float:
    return 1.0 if normalize(pred) == normalize(ref) else 0.0
