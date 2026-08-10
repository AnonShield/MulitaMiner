"""Set-based F1 over normalized identifiers.

Default normalizer: lowercase + strip, applied per element. For CVE-bearing
fields, pass ``normalizer=extract_cve_ids`` so the comparison happens at the
CVE-ID level, not at the URL/string level — see metrics.md §3.5.
"""
from __future__ import annotations

import re
from typing import Callable, Iterable

NAME = "set_f1"

# Canonical CVE format. Case-insensitive on input; we always emit upper case.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_ids(value) -> set[str]:
    """Extract canonical CVE-IDs from a string, list of strings, or dict values."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        flat = " ".join(str(x) for x in value)
    elif isinstance(value, dict):
        flat = " ".join(str(v) for v in value.values())
    else:
        flat = str(value)
    return {m.group().upper() for m in CVE_PATTERN.finditer(flat)}


def _default_normalizer(value) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(x).strip().lower() for x in value if str(x).strip()}
    if isinstance(value, dict):
        return {str(k).strip().lower() for k in value if str(k).strip()}
    s = str(value).strip().lower()
    return {s} if s else set()


def score(
    pred,
    ref,
    normalizer: Callable[[object], Iterable[str]] | None = None,
) -> float:
    norm = normalizer or _default_normalizer
    p, r = set(norm(pred)), set(norm(ref))
    if not p and not r:
        return 1.0
    if not p or not r:
        return 0.0
    tp = len(p & r)
    if tp == 0:
        return 0.0
    prec = tp / len(p)
    rec = tp / len(r)
    return 2 * prec * rec / (prec + rec)
