"""Canonicalize records to the V3 schema (see metrics.md §0).

Records — chiefly the human baselines, which carry PDF-extraction artifacts —
differ from the V3 schema in Python types:
    - cvss            list[str] / list      →  float | None
    - plugin_details  list                  →  dict
    - severity        mixed case            →  upper case
    - port            str (e.g. "9,390\\n")  →  int | None (when castable)

The number of coercions applied is itself a metric — type-coercion rate —
reportable as the *cost* of normalising legacy/dirty records. See §0.

This module is pure (no I/O); pipelines call it as a pre-processor
(e.g. coverage's Exact Record Match). Idempotent: applying
``canonicalize_to_v3`` to an already-V3 record is a no-op.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

# Fields whose **type** differs between legacy/dirty records and the V3 schema. Used as the
# denominator for ``type_coercion_rate``: rate = n_coercions / (n_records · |this|).
#
# This list is deliberately distinct from ``coverage.ERM_FIELDS`` —
#   - ``protocol`` is in ERM but never coerced (str in both versions)
#   - ``plugin_details`` is coerced (list→dict) but excluded from ERM
#     (dict structure is too noisy for byte equality)
# Each list answers a different question; see the docstring at the top of
# ``coverage.py`` for the full mapping.
V2_TO_V3_COERCIBLE_FIELDS: tuple[str, ...] = ("cvss", "plugin_details", "severity", "port")
# Backwards-compat alias.
COERCIBLE_FIELDS = V2_TO_V3_COERCIBLE_FIELDS


def _coerce_cvss(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, list):
        if not value:
            return None, "cvss:list→None"
        try:
            return float(value[0]), "cvss:list→float"
        except (TypeError, ValueError):
            return None, "cvss:list→None"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None, "cvss:str→None"
        try:
            return float(s), "cvss:str→float"
        except ValueError:
            return None, "cvss:str→None"
    return value, None


def _coerce_plugin_details(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, list):
        # Empty list maps to {}. Non-empty preserves content under "items"
        # so no information is lost — downstream metrics decide what to do.
        new_value = {} if not value else {"items": value}
        return new_value, "plugin_details:list→dict"
    return value, None


def _coerce_severity(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, str) and value and value != value.upper():
        return value.upper(), "severity:case"
    return value, None


def _coerce_port(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, str):
        s = value.replace(",", "").strip()
        if s.isdigit():
            return int(s), "port:str→int"
    return value, None


_COERCERS = {
    "cvss": _coerce_cvss,
    "plugin_details": _coerce_plugin_details,
    "severity": _coerce_severity,
    "port": _coerce_port,
}


def canonicalize_to_v3(record: dict) -> tuple[dict, list[str]]:
    """Normalize a single record to the V3 canonical schema.

    Returns:
        ``(canonical, coercions)`` where ``coercions`` is a list of label
        strings (e.g. ``"cvss:list→float"``). An empty list means the record
        was already V3-canonical.
    """
    out = dict(record)
    coercions: list[str] = []
    for field, coercer in _COERCERS.items():
        if field not in out:
            continue
        new_value, label = coercer(out[field])
        if label is not None:
            out[field] = new_value
            coercions.append(label)
    return out, coercions


def canonicalize_records(records: list[dict]) -> tuple[list[dict], dict]:
    """Apply :func:`canonicalize_to_v3` to a list of records.

    Returns:
        ``(canonical_records, stats)`` with ``stats`` containing
        ``n_records``, ``n_coercions``, ``type_coercion_rate``
        (= n_coercions / (n_records · |COERCIBLE_FIELDS|)) and
        ``coercion_breakdown`` (Counter of labels).
    """
    canonical: list[dict] = []
    breakdown: Counter[str] = Counter()
    for r in records:
        norm, labels = canonicalize_to_v3(r)
        canonical.append(norm)
        breakdown.update(labels)

    n_records = len(records)
    denom = max(1, n_records * len(COERCIBLE_FIELDS))
    n_coercions = sum(breakdown.values())

    return canonical, {
        "n_records": n_records,
        "n_coercions": n_coercions,
        "type_coercion_rate": n_coercions / denom,
        "coercion_breakdown": dict(breakdown),
    }
