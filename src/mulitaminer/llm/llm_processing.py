"""
Vulnerability validation and normalization (post-LLM, pre-storage).

Used by ``main.py`` for non-CAIS extraction profiles (OpenVAS / TenableWAS).
The CAIS profile has its own validator at ``src/utils/cais_validator.py``.

Schema source of truth: ``configs/vuln_schema.py`` (the Pydantic model) —
the same definition the schema-check pipeline validates against. Keeping the
validator consistent with that model prevents the silent drift the previous
implementation suffered from (it forced ``plugin: list`` when the schema says
``plugin: null``, and inserted phantom CAIS-only fields into OpenVAS records).
"""

import re
from typing import Optional, Dict, Any

from ..configs.vuln_schema import expected_fields, validation_types


def _v3_schema(source: Optional[str] = None) -> Dict[str, tuple]:
    """The field → allowed-types map for normalization, from the single source
    of truth. Restricted to LLM-produced fields (host / scanner_specific are
    filled by the pipeline, not normalized here), matching the old field set."""
    types = validation_types(source)
    return {f: types[f] for f in expected_fields(source)}


def _default_for(allowed: tuple):
    """Pick a sensible default value for a field given its allowed types.

    Order matters:
        1. ``list`` / ``dict``   → empty container (most schemas treat these
           as required collections that may be empty)
        2. ``type(None)``        → ``None`` when explicitly allowed (signals
           "optional field"); preferred over ``""``/``0`` defaults that
           silently invent a non-null value
        3. ``str`` / ``int``     → empty/zero scalar
    """
    if list in allowed:
        return []
    if dict in allowed:
        return {}
    if type(None) in allowed:
        return None
    if str in allowed:
        return ""
    if int in allowed or float in allowed:
        return 0
    return None


def _coerce_to_allowed(value: Any, allowed: tuple) -> Any:
    """Best-effort coercion of ``value`` into one of ``allowed`` types.

    Conservative — only converts when the target type is unambiguous:
        - list expected, scalar given → wrap in single-element list (or [] if empty/None)
        - str expected, non-str given → ``str(value)``
        - dict expected, anything else → leave untouched (let the schema check flag it)
    Otherwise returns the value unchanged.
    """
    if isinstance(value, allowed):
        return value
    if list in allowed:
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value.strip() else []
        return [value]
    if str in allowed and not isinstance(value, str):
        return str(value) if value is not None else ""
    # For other type mismatches, leave the value alone — schema_check will
    # flag it and we won't silently corrupt it.
    return value


def validate_and_normalize_vulnerability(vuln) -> Optional[Dict[str, Any]]:
    """
    Validate and normalize a single vulnerability object.

    Drops vulnerabilities with invalid Name (metadata, headings) or marker
    patterns that aren't real vulnerability names. Coerces fields to their
    schema-allowed types where unambiguous; otherwise leaves them for the
    schema-check pipeline to flag.

    Returns the normalized vulnerability dict, or ``None`` if the record
    should be discarded entirely.
    """
    if not isinstance(vuln, dict):
        return None

    # Reject "VULNERABILITY ... PLUGIN ID ..." pattern — these are Tenable
    # section headers that occasionally end up in extracted output.
    name = vuln.get("Name", "").strip()
    if re.match(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO|LOG)\s+PLUGIN\s+ID\s+\d+',
                name, re.IGNORECASE):
        return None
    if not name:
        return None

    schema = _v3_schema(vuln.get("source"))

    # Fill missing fields with type-appropriate defaults; coerce mismatches
    # only when the conversion is unambiguous.
    for field, allowed in schema.items():
        if field not in vuln:
            vuln[field] = _default_for(allowed)
        else:
            vuln[field] = _coerce_to_allowed(vuln[field], allowed)

    # Map "Info" severity to "LOG" — different scanners label informational
    # findings differently; we normalise to the V3 vocabulary.
    sev = vuln.get("severity", "")
    if isinstance(sev, str) and sev.upper() == "INFO":
        vuln["severity"] = "LOG"

    return vuln
