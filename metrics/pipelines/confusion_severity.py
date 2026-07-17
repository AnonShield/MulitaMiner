"""Macro-F1 + confusion matrix for the ``severity`` field (metrics.md §3.1).

Reads matched pairs from a BERT or ROUGE comparison XLSX (the same
``Per_Vulnerability`` + ``Mapping_Debug`` convention used by
``field_f1.py``), then re-loads the *original*
baseline/extraction XLSX to recover the canonical severity values.

Outputs an XLSX with three sheets:
    Confusion  — labels × labels matrix (rows = baseline, cols = extraction)
    Per_Class  — precision/recall/F1/support per severity class
    Summary    — macro-F1 (over classes with non-zero support) and accuracy

Why a separate pipeline (not extending field_f1):
    field_f1 computes binary exact-match F1 per field — useful, but blind to
    *which* class confuses with which. The confusion matrix is the figure
    a tier-1 reviewer will ask for if missing.

CLI is the project-standard ``parse_arguments_common`` so the pipeline can
be invoked through ``main.py`` exactly like ``bert``/``rouge``/``field_f1``.
The BERT/ROUGE comparison XLSX is auto-located in ``--output-dir`` (BERT
preferred, ROUGE as fallback) using the same lookup as ``field_f1``.
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

# Force UTF-8 stdout on Windows (consistency with bert/rouge/field_f1 scripts).
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"


import pandas as pd  # noqa: E402

from metrics.common.cli import parse_arguments_common  # noqa: E402
from metrics.common.sheet_resolver import resolve_baseline_sheet  # noqa: E402
from metrics.field_f1.field_f1 import (  # noqa: E402
    find_metric_comparison_file,
)

# Canonical severity labels in OpenVAS / Tenable. Order matters for plotting.
SEVERITY_LABELS: list[str] = ["LOG", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# Pseudo-labels for values that escape the canonical vocabulary.
OTHER, EMPTY = "__OTHER__", "__EMPTY__"
# Pseudo-label for the coverage-aware variant: marks "no counterpart"
# (omitted baseline row OR hallucinated extraction row). Lets the
# confusion matrix carry FN/FP information from unmatched records.
MISSING = "__MISSING__"


# ---------------------------------------------------------------------------
# Pure helpers — no I/O, easy to test.
# ---------------------------------------------------------------------------

def _normalize_severity(value) -> str:
    """Canonicalize to upper case; map blanks to ``__EMPTY__`` and unknowns
    to ``__OTHER__``. Pseudo-labels are excluded from macro-F1 unless the
    caller passes ``--include-other``.
    """
    if value is None:
        return EMPTY
    s = str(value).strip().upper()
    if not s:
        return EMPTY
    return s if s in SEVERITY_LABELS else OTHER


def _build_pairs(
    mapping_df: pd.DataFrame | None,
    baseline_df: pd.DataFrame,
    extraction_df: pd.DataFrame,
) -> list[tuple[str, str]]:
    """Reconstruct ``(baseline_severity, extraction_severity)`` for matched rows.

    Mirrors the row-id logic in ``field_f1.py`` so duplicate
    Names at different ports (e.g. "Services") are not collapsed.
    """
    if (
        mapping_df is None
        or "extraction_row_id" not in mapping_df.columns
        or "baseline_row_id" not in mapping_df.columns
    ):
        return []

    pairs: list[tuple[str, str]] = []
    for _, row in mapping_df.iterrows():
        ext_id, base_id = row.get("extraction_row_id"), row.get("baseline_row_id")
        if pd.isna(ext_id) or pd.isna(base_id):
            continue
        try:
            base_sev = baseline_df.iloc[int(base_id)].get("severity")
            ext_sev = extraction_df.iloc[int(ext_id)].get("severity")
        except (IndexError, KeyError):
            continue
        pairs.append((_normalize_severity(base_sev), _normalize_severity(ext_sev)))
    return pairs


def _build_coverage_aware_pairs(
    mapping_df: pd.DataFrame | None,
    baseline_df: pd.DataFrame,
    extraction_df: pd.DataFrame,
) -> list[tuple[str, str]]:
    """Same as ``_build_pairs`` plus the unmatched records.

    Omitted baseline records contribute (base_sev, __MISSING__) — they
    count as FN for ``base_sev``. Hallucinated extractions contribute
    (__MISSING__, ext_sev) — FP for ``ext_sev``. Together with the
    matched pairs this yields a confusion matrix that honestly reflects
    pipelines that silently skip findings (the selection bias that
    plagues the matched-only F1).
    """
    matched_ext: set[int] = set()
    matched_base: set[int] = set()
    pairs: list[tuple[str, str]] = []

    if (mapping_df is not None
            and "extraction_row_id" in mapping_df.columns
            and "baseline_row_id" in mapping_df.columns):
        for _, row in mapping_df.iterrows():
            ext_id, base_id = row.get("extraction_row_id"), row.get("baseline_row_id")
            if pd.isna(ext_id) or pd.isna(base_id):
                continue
            try:
                base_sev = baseline_df.iloc[int(base_id)].get("severity")
                ext_sev = extraction_df.iloc[int(ext_id)].get("severity")
            except (IndexError, KeyError):
                continue
            pairs.append((_normalize_severity(base_sev), _normalize_severity(ext_sev)))
            matched_ext.add(int(ext_id))
            matched_base.add(int(base_id))

    # Omitted baseline rows — FN for whatever class the baseline says.
    if "severity" in baseline_df.columns:
        for i in range(len(baseline_df)):
            if i in matched_base:
                continue
            pairs.append((_normalize_severity(baseline_df.iloc[i].get("severity")),
                          MISSING))

    # Hallucinated extraction rows — FP for whatever class the LLM emitted.
    if "severity" in extraction_df.columns:
        for i in range(len(extraction_df)):
            if i in matched_ext:
                continue
            pairs.append((MISSING,
                          _normalize_severity(extraction_df.iloc[i].get("severity"))))
    return pairs


def _confusion_matrix(pairs: list[tuple[str, str]], labels: list[str]) -> pd.DataFrame:
    matrix = pd.DataFrame(0, index=labels, columns=labels, dtype=int)
    matrix.index.name = "baseline\\extraction"
    for base, ext in pairs:
        if base in labels and ext in labels:
            matrix.loc[base, ext] += 1
    return matrix


def _per_class_metrics(matrix: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for label in matrix.index:
        tp = int(matrix.loc[label, label])
        fp = int(matrix[label].sum() - tp)      # column sum minus TP = predicted-but-wrong
        fn = int(matrix.loc[label].sum() - tp)  # row sum minus TP = was-this-but-missed
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        rows.append({
            "Class": label,
            "Support": tp + fn,
            "Precision": prec,
            "Recall": rec,
            "F1": f1,
        })
    return pd.DataFrame(rows)


def _read_first_sheet(xlsx_path: Path) -> pd.DataFrame:
    return pd.read_excel(
        xlsx_path,
        sheet_name=resolve_baseline_sheet(pd.ExcelFile(xlsx_path, engine="openpyxl")),
        engine="openpyxl",
    )


def assess(
    comparison_xlsx: Path,
    baseline_xlsx: Path,
    extraction_xlsx: Path,
    include_other: bool = False,
) -> dict[str, pd.DataFrame]:
    """Compute the confusion matrix + per-class metrics."""
    try:
        mapping_df = pd.read_excel(comparison_xlsx, sheet_name="Mapping_Debug", engine="openpyxl")
    except (ValueError, FileNotFoundError):
        mapping_df = None

    from metrics.common.io import load_baseline, load_extraction
    baseline_df = load_baseline(baseline_xlsx)
    extraction_df = load_extraction(extraction_xlsx)

    pairs = _build_pairs(mapping_df, baseline_df, extraction_df)
    cov_pairs = _build_coverage_aware_pairs(mapping_df, baseline_df, extraction_df)

    labels = list(SEVERITY_LABELS)
    if include_other:
        labels += [OTHER, EMPTY]

    matrix = _confusion_matrix(pairs, labels)
    per_class = _per_class_metrics(matrix)

    # Legacy: macro over classes with non-zero support among matched pairs.
    # Same selection bias as F1 — a pipeline that omits hard findings can
    # score artificially high here.
    supported = per_class[per_class["Support"] > 0]
    macro_f1 = float(supported["F1"].mean()) if not supported.empty else 0.0
    micro_tp = int(sum(matrix.loc[lbl, lbl] for lbl in labels))
    micro_total = int(matrix.values.sum())
    accuracy = micro_tp / micro_total if micro_total else 0.0

    # Coverage-aware: include omitted (→ FN) and hallucinated (→ FP) so
    # pipelines that silently skip findings get penalised. Uses the 5 real
    # severity labels for macro (MISSING is a pseudo-label, not a real class).
    cov_matrix = _confusion_matrix(cov_pairs, labels + [MISSING])
    cov_per_class = _per_class_metrics(cov_matrix.loc[labels + [MISSING], labels + [MISSING]])
    cov_real = cov_per_class[cov_per_class["Class"].isin(labels)]
    cov_supported = cov_real[cov_real["Support"] > 0]
    coverage_aware_macro_f1 = (
        float(cov_supported["F1"].mean()) if not cov_supported.empty else 0.0
    )

    summary = pd.DataFrame([{
        "n_pairs": len(pairs),
        "macro_F1": macro_f1,
        "coverage_aware_macro_F1": coverage_aware_macro_f1,
        "accuracy": accuracy,
    }])

    return {"matrix": matrix, "per_class": per_class, "summary": summary,
            "coverage_aware_matrix": cov_matrix,
            "coverage_aware_per_class": cov_per_class}


# ---------------------------------------------------------------------------
# Standard-CLI entry point.
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_arguments_common(require_model=False)
    output_dir = Path(args.output_dir)
    model_name = args.llm or "model"

    comparison_xlsx, metric_type = find_metric_comparison_file(output_dir, model_name)
    if comparison_xlsx is None:
        print(
            f"[SEVERITY] No bert/rouge comparison file found in {output_dir}. "
            "Run BERT or ROUGE before this pipeline."
        )
        return

    print(f"[SEVERITY] Using {metric_type.upper()} comparison: {comparison_xlsx.name}")

    result = assess(
        comparison_xlsx,
        Path(args.baseline_file),
        Path(args.extraction_file),
        include_other=False,
    )

    baseline_name = Path(args.baseline_file).stem.replace(" ", "_").lower()
    output_xlsx = output_dir / f"severity_confusion_{baseline_name}_{model_name}.xlsx"
    output_dir.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(output_xlsx) as writer:
        result["matrix"].to_excel(writer, sheet_name="Confusion")
        result["per_class"].to_excel(writer, sheet_name="Per_Class", index=False)
        result["summary"].to_excel(writer, sheet_name="Summary", index=False)
        result["coverage_aware_matrix"].to_excel(writer, sheet_name="Confusion_CovAware")
        result["coverage_aware_per_class"].to_excel(writer, sheet_name="Per_Class_CovAware",
                                                    index=False)

    s = result["summary"].iloc[0]
    print(
        f"[SEVERITY] pairs={int(s['n_pairs'])}, "
        f"macro_F1={s['macro_F1']:.3f}, "
        f"cov_macro_F1={s['coverage_aware_macro_F1']:.3f}, "
        f"accuracy={s['accuracy']:.3f}"
    )
    print(f"[SEVERITY] saved → {output_xlsx}")


if __name__ == "__main__":
    main()
