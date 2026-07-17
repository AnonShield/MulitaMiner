"""Inter-rater agreement metrics (metrics.md §6).

Compares two human-annotated baselines (annotator A vs annotator B) and
reports per-field agreement scaled to the field's nature:

    Categorical fields  → Cohen's κ
    Numeric fields      → exact agreement %
    Free-text fields    → Token-F1 between annotators (paper ceiling)

Records are aligned with the same composite-key + fuzzy aligner used by
the extraction pipelines, so duplicate Names at different ports are not
collapsed. Pairs that fail to align contribute to ``coverage`` but not
to per-field metrics — disagreement on *which* vulnerabilities exist
is reported separately from disagreement on *what they say*.

CLI::

    python -m metrics.interrater.kappa
        --annotator-a <baseline_A.xlsx>
        --annotator-b <baseline_B.xlsx>
        --output      <kappa_report.xlsx>
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from pathlib import Path
from typing import Callable

if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"


import pandas as pd  # noqa: E402
from sklearn.metrics import cohen_kappa_score  # noqa: E402

from metrics.common.aligner import align  # noqa: E402
from metrics.common.io import load_baseline, write_xlsx  # noqa: E402
from metrics.scorers.exact_match import normalize as exact_normalize  # noqa: E402
from metrics.scorers.token_f1 import score as token_f1_score  # noqa: E402

# Field grouping by nature — mirrors the per-field strategy in metrics.md §3.
CATEGORICAL_FIELDS: tuple[str, ...] = ("severity", "protocol", "source")
NUMERIC_FIELDS: tuple[str, ...] = ("cvss", "port")
TEXT_FIELDS: tuple[str, ...] = (
    "description", "impact", "solution", "insight",
    "detection_result", "detection_method",
    "log_method", "product_detection_result",
)


# ---------------------------------------------------------------------------
# Per-field agreement helpers — pure functions over paired value lists.
# ---------------------------------------------------------------------------

def _cohen_kappa(values_a: list, values_b: list) -> float | None:
    """Cohen's κ on already-normalized categorical labels.

    Returns ``None`` for inputs with fewer than two categories (κ undefined),
    or for empty lists.
    """
    if len(values_a) < 2:
        return None
    if len(set(values_a) | set(values_b)) < 2:
        return None
    return float(cohen_kappa_score(values_a, values_b))


def _exact_agreement(values_a: list, values_b: list) -> float | None:
    if not values_a:
        return None
    matches = sum(1 for a, b in zip(values_a, values_b) if a == b)
    return matches / len(values_a)


def _mean_text_similarity(values_a: list, values_b: list,
                          scorer: Callable[[object, object], float]) -> float | None:
    if not values_a:
        return None
    scores = [scorer(a, b) for a, b in zip(values_a, values_b)]
    return sum(scores) / len(scores)


# ---------------------------------------------------------------------------
# Field collection — walk aligned pairs once per group.
# ---------------------------------------------------------------------------

def _collect(field: str, pairs: list[tuple[int, int]],
             a: pd.DataFrame, b: pd.DataFrame,
             transform: Callable[[object], object] = lambda x: x) -> tuple[list, list]:
    """Pull paired values for ``field``, applying ``transform`` to each."""
    if field not in a.columns or field not in b.columns:
        return [], []
    va, vb = [], []
    for ai, bi in pairs:
        try:
            va.append(transform(a.iloc[ai][field]))
            vb.append(transform(b.iloc[bi][field]))
        except (IndexError, KeyError):
            continue
    return va, vb


def assess(annotator_a_xlsx: Path, annotator_b_xlsx: Path) -> dict[str, pd.DataFrame]:
    """Run the full inter-rater assessment and return summary DataFrames."""
    a = load_baseline(annotator_a_xlsx)
    b = load_baseline(annotator_b_xlsx)

    # Both inputs are baselines, so each row is a canonical observation —
    # legitimate-duplicates mode (no dedup, no row gets collapsed).
    res = align(a, b, method="hungarian", allow_duplicates=True)
    pairs = res.pairs

    rows: list[dict] = []
    for field in CATEGORICAL_FIELDS:
        va, vb = _collect(field, pairs, a, b, transform=exact_normalize)
        rows.append({
            "Field": field, "Type": "categorical", "Metric": "Cohen's κ",
            "N_pairs": len(va), "Value": _cohen_kappa(va, vb),
        })
    for field in NUMERIC_FIELDS:
        va, vb = _collect(field, pairs, a, b)
        rows.append({
            "Field": field, "Type": "numeric", "Metric": "Exact agreement",
            "N_pairs": len(va), "Value": _exact_agreement(va, vb),
        })
    for field in TEXT_FIELDS:
        va, vb = _collect(field, pairs, a, b)
        rows.append({
            "Field": field, "Type": "text", "Metric": "Token-F1",
            "N_pairs": len(va), "Value": _mean_text_similarity(va, vb, token_f1_score),
        })

    summary = pd.DataFrame([{
        "n_annotator_a": len(a),
        "n_annotator_b": len(b),
        "n_aligned_pairs": len(pairs),
        "coverage_a": len(pairs) / max(len(a), 1),
        "coverage_b": len(pairs) / max(len(b), 1),
        "n_unmatched_a": len(res.unmatched_baseline),
        "n_unmatched_b": len(res.unmatched_extraction),
    }])

    return {"summary": summary, "per_field": pd.DataFrame(rows)}


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _print_summary(result: dict[str, pd.DataFrame]) -> None:
    s = result["summary"].iloc[0]
    print(
        f"[KAPPA] N_a={int(s['n_annotator_a'])}, N_b={int(s['n_annotator_b'])}, "
        f"aligned={int(s['n_aligned_pairs'])} "
        f"(coverage A={s['coverage_a']:.1%}, B={s['coverage_b']:.1%})"
    )
    for _, r in result["per_field"].iterrows():
        v = r["Value"]
        v_str = "n/a" if v is None or pd.isna(v) else f"{v:.3f}"
        print(f"          {r['Field']:<28} ({r['Metric']:<16}): {v_str}  [n={int(r['N_pairs'])}]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inter-rater agreement (Cohen's κ + agreement) between two annotators.",
    )
    parser.add_argument("--annotator-a", type=Path, required=True,
                        help="First annotator's baseline XLSX")
    parser.add_argument("--annotator-b", type=Path, required=True,
                        help="Second annotator's baseline XLSX")
    parser.add_argument("--output", type=Path, required=True, help="Output XLSX path")
    args = parser.parse_args()

    if not args.annotator_a.is_file():
        print(f"[KAPPA] file not found: {args.annotator_a}")
        return
    if not args.annotator_b.is_file():
        print(f"[KAPPA] file not found: {args.annotator_b}")
        return

    result = assess(args.annotator_a, args.annotator_b)

    write_xlsx(args.output, {
        "Summary": result["summary"],
        "Per_Field": result["per_field"],
    })

    _print_summary(result)
    print(f"[KAPPA] saved → {args.output}")


if __name__ == "__main__":
    main()
