"""Schema-level metrics for a single run JSON (native validation only).

Operates on the *raw* LLM output (JSON) — not the post-processed XLSX —
because schema fidelity is exactly what we want to measure *before* any
normalization performed by the conversion step.

Each run is auto-detected as V1/V2/V3 and validated against the SCHEMA
OF THAT VERSION (i.e., the contract the LLM was actually given). Cross-
version "canon → V3" metrics were dropped because they are tautological:
they reward V3 by definition (V3 = the canonical schema). What remains
is evaluative — "did the LLM follow the prompt it received?".

Reports:

    json_valid                    — file parses as JSON
    schema_conformance_rate       — fraction of records with all native fields, valid types
    schema_field_conformance_rate — field-level fraction (softer than record-binary)
    extra_fields_rate             — fraction of records carrying keys outside the native schema
    missing_field_counts          — Counter of fields missing across records
    type_error_field_counts       — Counter of fields failing type check
    field_failure_counts          — combined missing + type-error counts per field
    extra_field_counts            — Counter of unexpected keys

Version detection: presence of ``identification``/``http_info`` → V1;
``cvss`` as list or ``plugin_details`` as list → V2; otherwise V3.

CLI is the project-standard ``parse_arguments_common``: when invoked via
``main.py`` it receives ``--baseline-file`` / ``--extraction-file`` /
``--output-dir`` like any other metric. The original JSON is located by
swapping the ``.xlsx`` extension on ``--extraction-file`` for ``.json``.

Usage::

    python -m metrics.pipelines.schema_check --baseline-file <baseline.xlsx>
        --extraction-file <extraction.xlsx-or-.json>
        --output-dir <run_dir> [--llm <model>]
"""
from __future__ import annotations

import io
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Force UTF-8 stdout on Windows so coercion labels (which carry U+2192 →)
# do not raise UnicodeEncodeError under cp1252.
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# Allow execution as ``python -m`` *or* as a direct script.
sys.path.insert(0, str(Path(__file__).parents[2]))

from metrics.common.cli import parse_arguments_common  # noqa: E402

# V3 canonical schema. Lists for ``plugin_details`` are intentionally not
# accepted here — that is precisely what V2 emits, and we want it flagged
# as a coercion (caught by the canonicalizer) rather than silently allowed.
V3_SCHEMA: dict[str, tuple[type, ...]] = {
    "Name": (str,),
    "description": (list,),
    "detection_result": (list,),
    "detection_method": (list,),
    "product_detection_result": (list,),
    "impact": (list,),
    "solution": (list,),
    "insight": (list,),
    "log_method": (list,),
    "cvss": (float, int, type(None)),
    "port": (int, str, type(None)),
    "protocol": (str, type(None)),
    "severity": (str,),
    "references": (list,),
    "plugin": (str, type(None)),
    "plugin_details": (dict,),
    "instances": (list,),
    "source": (str,),
}

# V2 canonical schema — what the V2 prompt actually contracted the LLM to emit
# AT THE TIME OF THE EXPERIMENTS. Verified against the historical prompt:
#
#   - ``cvss``     → "ALWAYS return as array, never empty"   → list
#   - ``severity`` → "MUST be UPPERCASE"                     → str
#   - ``port``     → "scalar, null when unknown"             → int|str|None
#
# Fields added POST-HOC to the V2 extraction outputs (after the experiments
# already ran, by an external script) are listed below. They were never part
# of the V2 prompt the LLM saw, so penalising V2 for getting their types
# wrong would conflate "LLM compliance with prompt" (what schema-native is
# meant to measure) with "manual post-processing bug". They are excluded
# from V2_SCHEMA so V2 native conformance reflects only what the LLM was
# actually asked to produce.
#
# The ONLY intentional schema difference V2→V3 that the LLM is responsible for
# is ``cvss`` (list → float).
V2_POST_HOC_FIELDS: set[str] = {"plugin_details", "instances"}

V2_SCHEMA: dict[str, tuple[type, ...]] = {
    field: types for field, types in V3_SCHEMA.items()
    if field not in V2_POST_HOC_FIELDS
}
V2_SCHEMA["cvss"] = (list,)  # only intentional V2→V3 type difference

# V1 canonical schema — the legacy "openvas" profile (main.py).
# Source of truth: ``v1_output.schema.json`` at the repo root. Differences
# from V3 the V1 prompt explicitly asked the LLM to emit:
#   - ``cvss``        list[7] with score at index 0, six nulls after
#   - ``plugin``      empty list (placeholder; never populated in V1)
#   - ``identification`` / ``http_info``  empty lists (V1-only placeholders)
#   - no ``plugin_details`` / ``instances`` (V2+ additions)
# TEMPORARY — V1 ships with the paper, then this block + V1_POST_HOC_FIELDS
# come out alongside the V1 canonicalizer rules.
V1_ONLY_FIELDS: set[str] = {"identification", "http_info"}
V1_SCHEMA: dict[str, tuple[type, ...]] = {
    field: types for field, types in V3_SCHEMA.items()
    if field not in {"plugin_details", "instances"}
}
V1_SCHEMA["cvss"] = (list,)  # 7-position array
V1_SCHEMA["plugin"] = (list,)  # always empty in V1
V1_SCHEMA["identification"] = (list,)
V1_SCHEMA["http_info"] = (list,)


# ---------------------------------------------------------------------------
# Pure functions — no I/O, easy to test.
# ---------------------------------------------------------------------------

def _validate_record(record: dict, schema: dict[str, tuple[type, ...]]) -> tuple[list[str], list[str]]:
    """Return ``(missing_fields, type_errors)`` for one record vs. ``schema``."""
    missing: list[str] = []
    type_errors: list[str] = []
    for field, allowed in schema.items():
        if field not in record:
            missing.append(field)
            continue
        if not isinstance(record[field], allowed):
            actual = type(record[field]).__name__
            expected = "|".join(t.__name__ for t in allowed)
            type_errors.append(f"{field}: expected {expected}, got {actual}")
    return missing, type_errors


def _extra_fields(record: dict, schema: dict[str, tuple[type, ...]],
                  ignore: set[str] | None = None) -> list[str]:
    """Fields present in the record but not in the schema. ``ignore`` lists
    fields known to have been added post-hoc (outside the prompt) — those
    are not really "extras" the LLM invented, just artefacts of later
    pipeline steps. Excluding them keeps ``extra_fields_rate`` honest.
    """
    ignored = ignore or set()
    return [k for k in record if k not in schema and k not in ignored]


def detect_version(records: list[dict]) -> str:
    """Auto-detect pipeline version from raw records.

    Priority: V1 wins over V2 if V1-only fields are present (``identification``
    or ``http_info``), since V1 also has ``cvss`` as a list. V2 wins over V3
    if ``cvss`` is list or ``plugin_details`` is list. Default: V3.
    """
    has_v1_marker = any(("identification" in r) or ("http_info" in r) for r in records)
    if has_v1_marker:
        return "v1"
    for r in records:
        if isinstance(r.get("cvss"), list) or isinstance(r.get("plugin_details"), list):
            return "v2"
    return "v3"


def assess(json_path: Path, version: str | None = None) -> dict[str, Any]:
    """Compute schema-level metrics for one run file (native-only).

    The function auto-detects the pipeline version of the file (V1/V2/V3)
    and validates the raw records against the SCHEMA OF THAT VERSION — i.e.,
    "did the LLM follow the prompt it received?". Output metrics:

        - ``json_valid``                     — file parses as JSON
        - ``schema_conformance_rate``        — record-level binary (all fields ok)
        - ``schema_field_conformance_rate``  — field-level fraction
        - ``missing_field_counts``           — per-field missing counts
        - ``type_error_field_counts``        — per-field type-error counts
        - ``extra_fields_rate``              — records carrying keys outside the
          native schema (penalises LLM-invented fields, ignoring known
          post-hoc additions like V2's ``plugin_details``/``instances``).

    Cross-version "canonicalised-to-V3" metrics (type-coercion rate, canon
    conformance) were removed as tautological: they reward V3 by definition.
    The canonicaliser itself still exists as a preprocessor for downstream
    scoring (see ``metrics/common/schema_canonicalizer.py`` /
    ``metrics/pipelines/coverage.py``); it is just no longer reported here.
    """
    raw = json_path.read_text(encoding="utf-8")
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "version": version or "unknown",
            "file": str(json_path),
            "json_valid": False,
            "json_error": str(exc),
        }
    if not isinstance(records, list):
        records = [records]

    if version is None:
        version = detect_version(records)

    if version == "v1":
        schema = V1_SCHEMA
    elif version == "v2":
        schema = V2_SCHEMA
    else:
        schema = V3_SCHEMA
    records_to_check = records

    missing_total: list[str] = []
    type_error_total: list[str] = []
    type_error_field_counts: Counter = Counter()
    extra_total: list[str] = []
    n_conformant = 0
    n_with_extras = 0

    # When validating against V2_SCHEMA, ignore the post-hoc fields when
    # counting "extras" — they weren't in the V2 prompt, so reporting them
    # as "LLM invented" would be wrong.
    extras_ignore = V2_POST_HOC_FIELDS if version == "v2" else set()

    for record in records_to_check:
        missing, type_errors = _validate_record(record, schema)
        extras = _extra_fields(record, schema, ignore=extras_ignore)
        missing_total.extend(missing)
        type_error_total.extend(type_errors)
        for msg in type_errors:
            # "field: expected X, got Y" — split off the field name.
            type_error_field_counts[msg.split(":", 1)[0]] += 1
        extra_total.extend(extras)
        if not missing and not type_errors:
            n_conformant += 1
        if extras:
            n_with_extras += 1

    n = max(1, len(records_to_check))
    missing_counts = dict(Counter(missing_total))
    # Per-field conformance: # field-checks passing / total field-checks.
    # Softer than record-level all-or-nothing — one bad field across all records
    # (e.g. V2's plugin_details) doesn't collapse the metric to 0%.
    field_failures = sum(missing_counts.values()) + sum(type_error_field_counts.values())
    field_checks = n * len(schema)
    field_conformance = 1 - (field_failures / field_checks) if field_checks else 0.0
    field_failure_counts = {
        f: missing_counts.get(f, 0) + type_error_field_counts.get(f, 0)
        for f in set(missing_counts) | set(type_error_field_counts)
    }
    return {
        "version": version,
        "file": str(json_path),
        "json_valid": True,
        "n_records": len(records_to_check),
        "schema_conformance_rate": n_conformant / n,
        "schema_field_conformance_rate": field_conformance,
        "extra_fields_rate": n_with_extras / n,
        "missing_field_counts": missing_counts,
        "type_error_examples": type_error_total[:20],
        "type_error_field_counts": dict(type_error_field_counts),
        "field_failure_counts": field_failure_counts,
        "extra_field_counts": dict(Counter(extra_total)),
    }


# ---------------------------------------------------------------------------
# Helpers to integrate with the project's standard ``parse_arguments_common``.
# ---------------------------------------------------------------------------

def _resolve_json_path(extraction_file: str) -> Path | None:
    """Locate the raw JSON for a given extraction file.

    Accepts ``.json`` directly or derives the path from a sibling XLSX
    (drops the ``.xlsx`` extension and tries ``.json``).
    """
    p = Path(extraction_file)
    if p.suffix.lower() == ".json":
        return p if p.is_file() else None
    candidate = p.with_suffix(".json")
    if candidate.is_file():
        return candidate
    # XLSX produced by main.py sits next to the JSON in the run folder;
    # try any *.json in the same directory as a last resort.
    json_siblings = sorted(p.parent.glob("*.json"))
    return json_siblings[0] if json_siblings else None


def _print_summary(report: dict) -> None:
    name = Path(report["file"]).name
    if not report.get("json_valid", False):
        print(f"[SCHEMA] {name}: INVALID JSON — {report.get('json_error')}")
        return
    print(
        f"[SCHEMA] {name} ({report['version']}): "
        f"n={report['n_records']}, "
        f"conformance={report['schema_conformance_rate']:.3f}, "
        f"field_conformance={report['schema_field_conformance_rate']:.3f}, "
        f"extras={report['extra_fields_rate']:.3f}"
    )


def main() -> None:
    args = parse_arguments_common(require_model=False)

    json_path = _resolve_json_path(args.extraction_file)
    if json_path is None:
        print(
            f"[SCHEMA] No JSON found alongside {args.extraction_file}. "
            "Schema metrics require the raw LLM output."
        )
        return

    report = assess(json_path)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_suffix = f"_{args.llm}" if args.llm else ""
    out_path = out_dir / f"schema_report_{json_path.stem}{model_suffix}.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    _print_summary(report)
    print(f"[SCHEMA] report → {out_path}")


if __name__ == "__main__":
    main()
