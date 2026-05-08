"""Macro-F1 + confusion matrix for the ``severity`` field (metrics.md §3.1).

Reads matched pairs from a BERT or ROUGE comparison XLSX (the same
``Per_Vulnerability`` + ``Mapping_Debug`` convention used by
``compare_extractions_entity.py``), then re-loads the *original*
baseline/extraction XLSX to recover the canonical severity values.

Outputs an XLSX with three sheets:
    Confusion  — labels × labels matrix (rows = baseline, cols = extraction)
    Per_Class  — precision/recall/F1/support per severity class
    Summary    — macro-F1 (over classes with non-zero support) and accuracy

Why a separate pipeline (not extending entity):
    Entity computes binary exact-match F1 per field — useful, but blind to
    *which* class confuses with which. The confusion matrix is the figure
    a tier-1 reviewer will ask for if missing.

CLI is the project-standard ``parse_arguments_common`` so the pipeline can
be invoked through ``main.py`` exactly like ``bert``/``rouge``/``entity``.
The BERT/ROUGE comparison XLSX is auto-located in ``--output-dir`` (BERT
preferred, ROUGE as fallback) using the same lookup as ``entity``.
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

# Force UTF-8 stdout on Windows (consistency with bert/rouge/entity scripts).
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# Allow execution as ``python -m`` *or* as a direct script.
sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd  # noqa: E402

from metrics.common.cli import parse_arguments_common  # noqa: E402
from metrics.common.sheet_resolver import resolve_baseline_sheet  # noqa: E402
from metrics.entity.compare_extractions_entity import (  # noqa: E402
    find_metric_comparison_file,
)

# Canonical severity labels in OpenVAS / Tenable. Order matters for plotting.
SEVERITY_LABELS: list[str] = ["LOG", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# Pseudo-labels for values that escape the canonical vocabulary.
OTHER, EMPTY = "__OTHER__", "__EMPTY__"


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

    Mirrors the row-id logic in ``compare_extractions_entity.py`` so duplicate
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

    baseline_df = _read_first_sheet(baseline_xlsx)
    extraction_df = _read_first_sheet(extraction_xlsx)

    pairs = _build_pairs(mapping_df, baseline_df, extraction_df)

    labels = list(SEVERITY_LABELS)
    if include_other:
        labels += [OTHER, EMPTY]

    matrix = _confusion_matrix(pairs, labels)
    per_class = _per_class_metrics(matrix)

    # Macro-F1 over classes with non-zero support — including zero-support
    # classes inflates the average artificially.
    supported = per_class[per_class["Support"] > 0]
    macro_f1 = float(supported["F1"].mean()) if not supported.empty else 0.0
    micro_tp = int(sum(matrix.loc[lbl, lbl] for lbl in labels))
    micro_total = int(matrix.values.sum())
    accuracy = micro_tp / micro_total if micro_total else 0.0

    summary = pd.DataFrame([{
        "n_pairs": len(pairs),
        "macro_F1": macro_f1,
        "accuracy": accuracy,
    }])

    return {"matrix": matrix, "per_class": per_class, "summary": summary}


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

    s = result["summary"].iloc[0]
    print(
        f"[SEVERITY] pairs={int(s['n_pairs'])}, "
        f"macro_F1={s['macro_F1']:.3f}, accuracy={s['accuracy']:.3f}"
    )
    print(f"[SEVERITY] saved → {output_xlsx}")


if __name__ == "__main__":
    main()
