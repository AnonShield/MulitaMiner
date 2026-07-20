"""Coverage metrics for a single run (metrics.md §4).

Computes three record/field-level coverage metrics:

    exact_record_match  — fraction of matched (extraction ↔ baseline) pairs
                          in which **every deterministic field** is identical
                          after canonicalization. Strictest single number.
    hallucination_rate  — fraction of extraction fields that are populated
                          while the corresponding baseline field is empty
                          or the entire vulnerability has no baseline match.
    omission_rate       — symmetrical: fraction of baseline fields populated
                          while the extraction is empty (or whole vuln
                          missing from extraction).

Reads matched pairs from a BERT or ROUGE comparison XLSX (Mapping_Debug
sheet — same convention as field_f1/severity). Reloads baseline + extraction
XLSX to walk field presence record-by-record.

Why not part of field_f1:
    field_f1 reports per-field exact-match P/R/F1 for deterministic fields.
    Coverage aggregates across *all* fields and accounts for *unmatched*
    vulnerabilities (field_f1 skips them).

CLI is the project-standard ``parse_arguments_common`` so the pipeline
runs through ``main.py --evaluation-methods coverage`` (or ``all``).
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

# UTF-8 stdout on Windows for the U+2192 → labels we propagate from canon.
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"


import pandas as pd  # noqa: E402

from metrics.common.cli import parse_arguments_common  # noqa: E402
from metrics.common.schema_canonicalizer import canonicalize_to_v3  # noqa: E402
from metrics.common.sheet_resolver import resolve_baseline_sheet  # noqa: E402
from metrics.field_f1.field_f1 import (  # noqa: E402
    find_metric_comparison_file,
)
from metrics.scorers.exact_match import normalize as norm_exact  # noqa: E402
from metrics.scorers.presence import is_populated  # noqa: E402

# All canonical V3 fields that participate in halluc/omission rates.
CANONICAL_FIELDS: tuple[str, ...] = (
    "Name", "description", "detection_result", "detection_method",
    "product_detection_result", "impact", "solution", "insight", "log_method",
    "cvss", "port", "protocol", "severity", "references",
    "plugin", "plugin_details", "instances", "source",
)

# Subset compared exactly for ERM. Free-text and list fields are excluded
# because byte-equality on those is too noisy to be meaningful.
#
# Note: this list intentionally differs from
# ``metrics.common.schema_canonicalizer.V2_TO_V3_COERCIBLE_FIELDS`` and from
# ``src/mulitaminer/configs/schema/field_categories.json``. Each list answers a different
# question:
#   - ``ERM_FIELDS``                  → fields whose exact equality counts in ERM
#   - ``V2_TO_V3_COERCIBLE_FIELDS``  → fields whose *type* differs between V2 and V3
#   - ``field_categories.json``       → general semantic/deterministic categorisation
# ``protocol`` is in ERM but not coercible (str in both versions); ``plugin_details``
# is coercible but not in ERM (dict structure too noisy for byte equality).
ERM_FIELDS: tuple[str, ...] = (
    "cvss", "port", "protocol", "severity", "source",
)
# Backwards-compat alias (other modules / tests may still import the old name).
DETERMINISTIC_FIELDS = ERM_FIELDS


# ---------------------------------------------------------------------------
# Pure helpers — work on plain dicts/values, no I/O.
# ---------------------------------------------------------------------------

def _canonical_field_value(record: dict, field: str):
    """Apply V2→V3 canonicalization once, then return the field value."""
    canon, _ = canonicalize_to_v3(record)
    return canon.get(field)


def _exact_eq(a, b) -> bool:
    """Equality after normalization. Used for deterministic fields only."""
    if a is None and b is None:
        return True
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    return norm_exact(a) == norm_exact(b)


def compute_erm(pairs: list[tuple[dict, dict]]) -> tuple[int, int]:
    """Return ``(exact_records, total_pairs)``.

    A record is "exact" when every deterministic field (after canonicalization)
    exactly matches between extraction and baseline.
    """
    exact = 0
    for ext, base in pairs:
        if all(_exact_eq(_canonical_field_value(ext, f),
                         _canonical_field_value(base, f))
               for f in ERM_FIELDS):
            exact += 1
    return exact, len(pairs)


def compute_field_presence_rates(
    matched_pairs: list[tuple[dict, dict]],
    unmatched_extraction: list[dict],
    unmatched_baseline: list[dict],
) -> dict[str, float]:
    """Hallucination + omission rates over all canonical fields.

    Hallucination counts:
        - matched pair: extraction field populated, baseline field empty
        - unmatched extraction vuln: every populated extraction field
    Omission counts:
        - matched pair: baseline field populated, extraction field empty
        - unmatched baseline vuln: every populated baseline field

    Denominators: total extraction-side cells / total baseline-side cells.
    """
    halluc = 0
    omit = 0
    ext_cells = 0
    base_cells = 0

    for ext, base in matched_pairs:
        for f in CANONICAL_FIELDS:
            ext_pop = is_populated(ext.get(f))
            base_pop = is_populated(base.get(f))
            ext_cells += 1
            base_cells += 1
            if ext_pop and not base_pop:
                halluc += 1
            if base_pop and not ext_pop:
                omit += 1

    for ext in unmatched_extraction:
        for f in CANONICAL_FIELDS:
            ext_cells += 1
            if is_populated(ext.get(f)):
                halluc += 1

    for base in unmatched_baseline:
        for f in CANONICAL_FIELDS:
            base_cells += 1
            if is_populated(base.get(f)):
                omit += 1

    return {
        "hallucination_rate": halluc / ext_cells if ext_cells else 0.0,
        "omission_rate": omit / base_cells if base_cells else 0.0,
        "n_extraction_cells": ext_cells,
        "n_baseline_cells": base_cells,
        "n_hallucinated_cells": halluc,
        "n_omitted_cells": omit,
    }


# ---------------------------------------------------------------------------
# Adapters — load XLSX, build pair lists.
# ---------------------------------------------------------------------------

def _read_first_sheet(xlsx_path: Path) -> pd.DataFrame:
    return pd.read_excel(
        xlsx_path,
        sheet_name=resolve_baseline_sheet(pd.ExcelFile(xlsx_path, engine="openpyxl")),
        engine="openpyxl",
    )


def _row_to_dict(row: pd.Series) -> dict:
    """Convert a DataFrame row to a plain dict, dropping NaN to ``None``."""
    out = {}
    for k, v in row.items():
        if isinstance(v, float) and pd.isna(v):
            out[k] = None
        else:
            out[k] = v
    return out


def _build_lists(
    mapping_df: pd.DataFrame | None,
    baseline_df: pd.DataFrame,
    extraction_df: pd.DataFrame,
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Return ``(matched_pairs, unmatched_extraction, unmatched_baseline)``."""
    matched: list[tuple[dict, dict]] = []
    matched_ext_idx: set[int] = set()
    matched_base_idx: set[int] = set()

    if (mapping_df is not None
            and "extraction_row_id" in mapping_df.columns
            and "baseline_row_id" in mapping_df.columns):
        for _, row in mapping_df.iterrows():
            ei, bi = row.get("extraction_row_id"), row.get("baseline_row_id")
            if pd.isna(ei) or pd.isna(bi):
                continue
            try:
                ext = _row_to_dict(extraction_df.iloc[int(ei)])
                base = _row_to_dict(baseline_df.iloc[int(bi)])
            except IndexError:
                continue
            matched.append((ext, base))
            matched_ext_idx.add(int(ei))
            matched_base_idx.add(int(bi))

    unmatched_ext = [
        _row_to_dict(extraction_df.iloc[i])
        for i in range(len(extraction_df)) if i not in matched_ext_idx
    ]
    unmatched_base = [
        _row_to_dict(baseline_df.iloc[i])
        for i in range(len(baseline_df)) if i not in matched_base_idx
    ]
    return matched, unmatched_ext, unmatched_base


def assess(
    comparison_xlsx: Path,
    baseline_xlsx: Path,
    extraction_xlsx: Path,
) -> dict[str, pd.DataFrame]:
    """Compute paper-level metrics for one run, returned as DataFrames."""
    try:
        mapping_df = pd.read_excel(comparison_xlsx, sheet_name="Mapping_Debug",
                                   engine="openpyxl")
    except (ValueError, FileNotFoundError):
        mapping_df = None

    from metrics.common.io import load_baseline, load_extraction
    baseline_df = load_baseline(baseline_xlsx)
    extraction_df = load_extraction(extraction_xlsx)

    matched, ext_only, base_only = _build_lists(mapping_df, baseline_df, extraction_df)

    erm, n_pairs = compute_erm(matched)
    presence = compute_field_presence_rates(matched, ext_only, base_only)

    n_ext_total = n_pairs + len(ext_only)
    n_base_total = n_pairs + len(base_only)
    summary = pd.DataFrame([{
        "n_matched_pairs": n_pairs,
        "n_extraction_unmatched": len(ext_only),
        "n_baseline_unmatched": len(base_only),
        "exact_record_match": (erm / n_pairs) if n_pairs else 0.0,
        "n_exact_records": erm,
        # Vuln-level rates: normalized per run by baseline/extracted size, so they
        # don't get biased by baselines of different sizes when aggregated.
        "vuln_hallucination_rate": (len(ext_only) / n_ext_total) if n_ext_total else 0.0,
        "vuln_omission_rate": (len(base_only) / n_base_total) if n_base_total else 0.0,
        **presence,
    }])

    # Per-field presence rates — useful for diagnostic plots / tables.
    # Omission is conditional on presence and restricted to MATCHED pairs: among
    # matched vulns whose baseline populates field f, the fraction where the
    # extraction left f empty. This isolates field fidelity from vuln-level
    # omission (a whole missed vuln counts only in vuln_omission_rate, never here).
    # When no matched vuln has f populated, there was no opportunity to omit, so
    # the rate is undefined (NaN) — rendered neutral downstream, not 0.
    per_field_rows = []
    for f in CANONICAL_FIELDS:
        h = sum(1 for ext, base in matched
                if is_populated(ext.get(f)) and not is_populated(base.get(f)))
        h += sum(1 for ext in ext_only if is_populated(ext.get(f)))
        denom_ext = len(matched) + len(ext_only)
        n_present = sum(1 for ext, base in matched if is_populated(base.get(f)))
        o = sum(1 for ext, base in matched
                if is_populated(base.get(f)) and not is_populated(ext.get(f)))
        per_field_rows.append({
            "Field": f,
            "Hallucination_Rate": h / denom_ext if denom_ext else 0.0,
            "Omission_Rate": (o / n_present) if n_present else float("nan"),
        })
    per_field = pd.DataFrame(per_field_rows)

    return {"summary": summary, "per_field": per_field}


def main() -> None:
    args = parse_arguments_common(require_model=False)
    output_dir = Path(args.output_dir)
    model_name = args.llm or "model"

    comparison_xlsx, metric_type = find_metric_comparison_file(output_dir, model_name)
    if comparison_xlsx is None:
        print(
            f"[COVERAGE] No bert/rouge comparison file found in {output_dir}. "
            "Run BERT or ROUGE before this pipeline."
        )
        return

    print(f"[COVERAGE] Using {metric_type.upper()} comparison: {comparison_xlsx.name}")

    result = assess(
        comparison_xlsx,
        Path(args.baseline_file),
        Path(args.extraction_file),
    )

    baseline_name = Path(args.baseline_file).stem.replace(" ", "_").lower()
    output_xlsx = output_dir / f"coverage_{baseline_name}_{model_name}.xlsx"
    output_dir.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(output_xlsx) as writer:
        result["summary"].to_excel(writer, sheet_name="Summary", index=False)
        result["per_field"].to_excel(writer, sheet_name="Per_Field", index=False)

    s = result["summary"].iloc[0]
    print(
        f"[COVERAGE] pairs={int(s['n_matched_pairs'])}, "
        f"ERM={s['exact_record_match']:.3f}, "
        f"halluc={s['hallucination_rate']:.3f}, "
        f"omit={s['omission_rate']:.3f}"
    )
    print(f"[COVERAGE] saved → {output_xlsx}")


if __name__ == "__main__":
    main()
