"""Canonicalize legacy V1/V2 records to the V3 schema (see metrics.md §0).

V1, V2 and V3 emit the same logical fields but differ in Python types:
    - cvss            V2 list[str] / V1 list[7]   →  float | None
    - plugin_details  V2 list                     →  dict  (absent in V1)
    - severity        mixed case                  →  upper case (LLM-side bug)
    - port            str | int                   →  int | None (when castable)
    - plugin          V1 list                     →  None  (V3 expects str|None)
    - identification  V1 only                     →  dropped (not in V3 schema)
    - http_info       V1 only                     →  dropped (not in V3 schema)

The number of coercions applied is itself a metric — type-coercion rate —
reportable as the *cost* of operating with the legacy pipeline. See §0.

NOTE: V1 support is TEMPORARY for the paper's cross-version comparison
figure. After the paper ships, this module returns to V2→V3 only —
delete the V1-only coercers (``_coerce_plugin``, ``_drop_v1_only_fields``)
and remove them from ``_COERCERS``. See ``TODO.md`` post-paper section.

This module is pure (no I/O); pipelines call it as a pre-processor.
Idempotent: applying ``canonicalize_to_v3`` to a V3 record is a no-op.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

# Fields whose **type** differs between the V2 and V3 schemas. Used as the
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

# V1-only fields. Listed here so denominators stay honest when normalising
# a V1 record (the LLM had no V3 prompt to comply with; these are just
# extra fields it was asked to emit). Dropped during canonicalisation.
# TEMPORARY — remove with the rest of V1 support post-paper.
V1_ONLY_FIELDS: tuple[str, ...] = ("identification", "http_info")


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


def _coerce_plugin(value: Any) -> tuple[Any, str | None]:
    """V1 emits ``plugin`` as a list (almost always ``[]``); V3 expects
    ``str | None``. Map empty list to ``None`` and non-empty to its first
    element coerced to str. TEMPORARY — V1-only path.
    """
    if isinstance(value, list):
        if not value:
            return None, "plugin:list→None"
        return str(value[0]), "plugin:list→str"
    return value, None


_COERCERS = {
    "cvss": _coerce_cvss,
    "plugin_details": _coerce_plugin_details,
    "severity": _coerce_severity,
    "port": _coerce_port,
    # V1-only — no-op on V2/V3 since their ``plugin`` is already str|None.
    "plugin": _coerce_plugin,
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
    # Drop V1-only fields silently. They aren't "coercions" in the type
    # sense (no V3 home), so they're NOT appended to ``coercions`` — that
    # would inflate type_coercion_rate. ``extra_fields_rate`` already
    # captures structural divergence; dropping here just keeps the V3
    # schema validator happy.
    # TEMPORARY — remove the block below post-paper.
    for v1_field in V1_ONLY_FIELDS:
        out.pop(v1_field, None)
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
