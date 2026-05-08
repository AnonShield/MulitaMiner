"""Schema-level metrics for a single run JSON (metrics.md §0 + §1).

Operates on the *raw* LLM output (JSON) — not the post-processed XLSX —
because schema fidelity is exactly what we want to measure *before* any
normalization performed by the conversion step.

Reports:

    json_valid              — file parses as JSON
    schema_conformance_rate — fraction of records with all V3 fields, valid types
    type_coercion_rate      — coercions applied per coercible field, per record
    coercion_breakdown      — count of each coercion label
    extra_fields_rate       — fraction of records with keys outside V3 schema
    missing_field_counts    — Counter of fields missing across records
    type_error_examples     — first 20 type-mismatch messages
    extra_field_counts      — Counter of unexpected keys

Pipeline version is auto-detected from the data: if any record carries
``cvss`` as a list or ``plugin_details`` as a list, it is V2; otherwise V3.

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
from metrics.common.schema_canonicalizer import canonicalize_records  # noqa: E402

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
    "protocol": (str,),
    "severity": (str,),
    "references": (list,),
    "plugin": (str, type(None)),
    "plugin_details": (dict,),
    "instances": (list,),
    "source": (str,),
}


# ---------------------------------------------------------------------------
# Pure functions — no I/O, easy to test.
# ---------------------------------------------------------------------------

def _validate_record(record: dict) -> tuple[list[str], list[str]]:
    """Return ``(missing_fields, type_errors)`` for one record vs. V3 schema."""
    missing: list[str] = []
    type_errors: list[str] = []
    for field, allowed in V3_SCHEMA.items():
        if field not in record:
            missing.append(field)
            continue
        if not isinstance(record[field], allowed):
            actual = type(record[field]).__name__
            expected = "|".join(t.__name__ for t in allowed)
            type_errors.append(f"{field}: expected {expected}, got {actual}")
    return missing, type_errors


def _extra_fields(record: dict) -> list[str]:
    return [k for k in record if k not in V3_SCHEMA]


def detect_version(records: list[dict]) -> str:
    """Auto-detect pipeline version from raw records.

    Returns ``"v2"`` if any record exhibits the V2 type signatures
    (``cvss`` as list, ``plugin_details`` as list); otherwise ``"v3"``.
    """
    for r in records:
        if isinstance(r.get("cvss"), list) or isinstance(r.get("plugin_details"), list):
            return "v2"
    return "v3"


def assess(json_path: Path, version: str | None = None) -> dict[str, Any]:
    """Compute schema-level metrics for one run file.

    Args:
        json_path: path to raw run JSON.
        version: pipeline label. ``None`` triggers auto-detection.
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

    canonical, coercion_stats = canonicalize_records(records)

    missing_total: list[str] = []
    type_error_total: list[str] = []
    extra_total: list[str] = []
    n_conformant = 0
    n_with_extras = 0

    for record in canonical:
        missing, type_errors = _validate_record(record)
        extras = _extra_fields(record)
        missing_total.extend(missing)
        type_error_total.extend(type_errors)
        extra_total.extend(extras)
        if not missing and not type_errors:
            n_conformant += 1
        if extras:
            n_with_extras += 1

    n = max(1, len(canonical))
    return {
        "version": version,
        "file": str(json_path),
        "json_valid": True,
        "n_records": len(canonical),
        "schema_conformance_rate": n_conformant / n,
        "type_coercion_rate": coercion_stats["type_coercion_rate"],
        "coercion_breakdown": coercion_stats["coercion_breakdown"],
        "extra_fields_rate": n_with_extras / n,
        "missing_field_counts": dict(Counter(missing_total)),
        "type_error_examples": type_error_total[:20],
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
        f"coercion={report['type_coercion_rate']:.3f}, "
        f"extras={report['extra_fields_rate']:.3f}"
    )
    for label, count in sorted(report["coercion_breakdown"].items()):
        print(f"          coercion {label}: {count}")


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
