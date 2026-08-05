"""Vulnerability validation and normalization (post-LLM, pre-storage).

Used by main.py for non-CAIS profiles; the CAIS profile has its own validator.
Schema source of truth: metrics/pipelines/schema_check.V3_SCHEMA, so this
validator cannot drift from what the schema-check pipeline enforces.
"""

import re
from typing import Optional, Dict, Any


def _v3_schema() -> Dict[str, tuple]:
    # Imported lazily so contexts without the metrics package still load this module
    try:
        from metrics.pipelines.schema_check import V3_SCHEMA
        return V3_SCHEMA
    except ImportError:
        # Minimal fallback: only the fields acted on below
        return {
            "Name": (str,),
            "description": (list,),
            "detection_result": (list,),
            "detection_method": (list,),
            "product_detection_result": (list,),
            "impact": (list,),
            "solution": (list,),
            "insight": (list,),
            "log_method": (list,),
            "cvss": (float, int, list, type(None)),
            "port": (int, str, type(None)),
            "protocol": (str, type(None)),
            "severity": (str,),
            "references": (list,),
            "plugin": (str, int, type(None)),
            "plugin_details": (dict,),
            "instances": (list,),
            "source": (str,),
        }


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

    Conservative: only converts when the target type is unambiguous:
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
    # For other type mismatches, leave the value alone; schema_check will
    # flag it and we won't silently corrupt it.
    return value


def validate_and_normalize_vulnerability(vuln) -> Optional[Dict[str, Any]]:
    """Normalize one vulnerability dict; returns None when it should be dropped."""
    if not isinstance(vuln, dict):
        return None

    # "VULNERABILITY ... PLUGIN ID ..." lines are Tenable section headers,
    # not real vulnerability names
    name = vuln.get("Name", "").strip()
    if re.match(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO|LOG)\s+PLUGIN\s+ID\s+\d+',
                name, re.IGNORECASE):
        return None
    if not name:
        return None

    schema = _v3_schema()

    for field, allowed in schema.items():
        if field not in vuln:
            vuln[field] = _default_for(allowed)
        else:
            vuln[field] = _coerce_to_allowed(vuln[field], allowed)

    # Scanners label informational findings differently; normalize to V3's "LOG"
    sev = vuln.get("severity", "")
    if isinstance(sev, str) and sev.upper() == "INFO":
        vuln["severity"] = "LOG"

    return vuln
