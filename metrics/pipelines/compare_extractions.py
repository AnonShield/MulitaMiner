"""Unified extraction-vs-baseline comparison.

Single entry point that consumes any registered scorer (BERTScore, ROUGE-L,
Token-F1, …). Replaces the duplicated logic that historically lived in
``compare_extractions_bert.py`` and ``compare_extractions_rouge.py`` for
all *new* scorers — the legacy two-script setup is preserved for back-compat
and bit-equivalence with prior outputs.

Pipeline:
    1. Load baseline + extraction (XLSX) via ``metrics.common.io``
    2. Align via ``metrics.common.aligner``
    3. Score per common field via ``metrics.scorers``
    4. Build Per_Vulnerability + Summary + Categorization + Mapping_Debug
    5. Write a single XLSX

CLI is the project-standard ``parse_arguments_common`` plus ``--scorer NAME``.
Output filename adopts legacy prefixes when the scorer is ``bertscore`` or
``rouge_l`` so downstream consumers (entity, severity, paper, aggregator)
keep working without modification.

Usage::

    python -m metrics.pipelines.compare_extractions
        --baseline-file <baseline.xlsx>
        --extraction-file <extraction.xlsx>
        --output-dir <run_dir>
        --llm <model>
        --scorer token_f1
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd  # noqa: E402

from metrics.common.aligner import AlignmentResult, align  # noqa: E402
from metrics.common.field_mapper import get_semantic_fields  # noqa: E402
from metrics.common.io import load_baseline, load_extraction, write_xlsx  # noqa: E402
from metrics.common.normalization import normalize_field_data  # noqa: E402
from metrics.scorers import SCORERS, list_scorers  # noqa: E402

# Per-scorer cosmetic conventions: column suffixes, summary prefixes, file
# prefixes. Legacy scorers preserve the names already produced by bert/rouge
# so aggregator and entity pipelines keep finding the files they expect.
_CONFIG: dict[str, dict[str, str]] = {
    "bertscore": {"suffix": "_bertscore_f1", "stat_prefix": "BERTScore_F1", "file_prefix": "bert_comparison"},
    "rouge_l":   {"suffix": "_rouge_l",      "stat_prefix": "ROUGE_L",      "file_prefix": "rouge_comparison"},
    "token_f1":  {"suffix": "_token_f1",     "stat_prefix": "Token_F1",     "file_prefix": "token_f1_comparison"},
    "presence":  {"suffix": "_presence",     "stat_prefix": "Presence",     "file_prefix": "presence_comparison"},
    "exact_match":{"suffix": "_exact",       "stat_prefix": "Exact",        "file_prefix": "exact_comparison"},
    "set_f1":    {"suffix": "_set_f1",       "stat_prefix": "Set_F1",       "file_prefix": "set_f1_comparison"},
}

# Categorization thresholds — preserved from bert/rouge so the
# Categorization sheet is comparable across pipelines.
_CAT_HIGH, _CAT_MOD, _CAT_LOW = 0.7, 0.6, 0.4


# ---------------------------------------------------------------------------
# Core pipeline.
# ---------------------------------------------------------------------------

def _pair_score(scorer, ext_val, base_val) -> float:
    """Empty-vs-empty counts as 1.0 — vacuous match. Mismatch in presence
    counts as 0.0. Otherwise delegate to the scorer.
    """
    e, b = normalize_field_data(ext_val), normalize_field_data(base_val)
    if e.strip() and b.strip():
        return float(scorer(e, b))
    if not e.strip() and not b.strip():
        return 1.0
    return 0.0


def _categorize(avg: float) -> str:
    if avg > _CAT_HIGH:
        return "Highly Similar"
    if avg > _CAT_MOD:
        return "Moderately Similar"
    if avg > _CAT_LOW:
        return "Slightly Similar"
    return "Divergent"


def _common_fields(baseline: pd.DataFrame, extraction: pd.DataFrame) -> list[str]:
    semantic = get_semantic_fields(baseline.columns)
    return [c for c in extraction.columns if c.lower() in semantic and c in baseline.columns]


def score_run(
    baseline: pd.DataFrame,
    extraction: pd.DataFrame,
    scorer_name: str,
    *,
    allow_duplicates: bool = False,
    method: str = "greedy",
) -> dict[str, pd.DataFrame]:
    """End-to-end: align, score per field, build the four output sheets."""
    if scorer_name not in SCORERS:
        raise ValueError(f"Unknown scorer: {scorer_name}. Available: {list_scorers()}")

    cfg = _CONFIG.get(scorer_name, {
        "suffix": f"_{scorer_name}",
        "stat_prefix": scorer_name.replace("_", " ").title().replace(" ", "_"),
        "file_prefix": f"{scorer_name}_comparison",
    })
    suffix, stat_prefix = cfg["suffix"], cfg["stat_prefix"]
    scorer = SCORERS[scorer_name]

    res: AlignmentResult = align(
        baseline, extraction,
        method=method, allow_duplicates=allow_duplicates,
    )
    fields = _common_fields(baseline, extraction)

    pairs_by_ext = dict(res.pairs)  # extraction_idx → baseline_row_id

    per_vuln_rows: list[dict] = []
    for ext_idx, ext_row in extraction.iterrows():
        name = ext_row.get("Name")
        if ext_idx in pairs_by_ext:
            base_row = baseline.loc[pairs_by_ext[ext_idx]]
            row = {"Name": name, "_status": "OK"}
            for col in fields:
                row[f"{col}{suffix}"] = _pair_score(scorer, ext_row[col], base_row[col])
        else:
            # Distinguish UNMATCHED (no candidate) from UNMATCHED_EXCESS
            # (candidate was already consumed) — preserves the entity/paper
            # downstream consumers' status semantics.
            status = "UNMATCHED"
            for d in res.debug_rows:
                if d["extraction_row_id"] == ext_idx and d["Status"] == "UNMATCHED_EXCESS":
                    status = "UNMATCHED_EXCESS"
                    break
            row = {"Name": name, "_status": status}
            for col in fields:
                row[f"{col}{suffix}"] = 0.0
        per_vuln_rows.append(row)

    per_vuln = pd.DataFrame(per_vuln_rows)

    # ---- Summary
    matched = per_vuln[per_vuln["_status"] == "OK"]
    summary_rows = []
    for col in fields:
        col_name = f"{col}{suffix}"
        if matched.empty:
            summary_rows.append({
                "Column": col, "Count_Matched": 0,
                f"Avg_{stat_prefix}": 0.0, f"Std_{stat_prefix}": 0.0,
                f"Min_{stat_prefix}": 0.0, f"Max_{stat_prefix}": 0.0,
                f"Median_{stat_prefix}": 0.0,
            })
        else:
            vals = matched[col_name].astype(float)
            summary_rows.append({
                "Column": col, "Count_Matched": len(matched),
                f"Avg_{stat_prefix}": float(vals.mean()),
                f"Std_{stat_prefix}": float(vals.std()),
                f"Min_{stat_prefix}": float(vals.min()),
                f"Max_{stat_prefix}": float(vals.max()),
                f"Median_{stat_prefix}": float(vals.median()),
            })
    summary = pd.DataFrame(summary_rows)

    # ---- Categorization (Matched + Non-existent + Absent)
    score_cols = [f"{c}{suffix}" for c in fields]
    cat_rows: list[dict] = []
    for _, row in per_vuln.iterrows():
        if row["_status"] == "OK":
            avg = sum(float(row[c]) for c in score_cols) / max(len(score_cols), 1)
            cat_rows.append({
                "Vulnerability_Name": row["Name"],
                f"Avg_{stat_prefix}": avg,
                "Category": _categorize(avg),
                "Type": "Matched",
            })
        elif row["_status"] == "UNMATCHED_EXCESS":
            cat_rows.append({
                "Vulnerability_Name": row["Name"],
                f"Avg_{stat_prefix}": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (excess duplicate)",
            })
        else:
            cat_rows.append({
                "Vulnerability_Name": row["Name"],
                f"Avg_{stat_prefix}": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (LLM invention)",
            })
    for rid in res.unmatched_baseline:
        cat_rows.append({
            "Vulnerability_Name": baseline.loc[rid, "Name"],
            f"Avg_{stat_prefix}": 0.0,
            "Category": "Absent",
            "Type": "Absent (not extracted)",
        })
    categorization = pd.DataFrame(cat_rows)

    mapping_debug = pd.DataFrame(res.debug_rows)

    return {
        "Per_Vulnerability": per_vuln,
        "Summary": summary,
        "Categorization": categorization,
        "Mapping_Debug": mapping_debug,
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _parse_args(default_scorer: str = "bertscore") -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unified extraction-vs-baseline comparison (any scorer)."
    )
    parser.add_argument("--baseline-file", dest="baseline_file", type=Path, required=True)
    parser.add_argument("--extraction-file", dest="extraction_file", type=Path, required=True)
    parser.add_argument("--output-dir", dest="output_dir", type=Path, required=True)
    parser.add_argument("--llm", type=str, default=None,
                        help="Model name (used in output filename)")
    parser.add_argument("--allow-duplicates", dest="allow_duplicates", action="store_true",
                        help="Keep legitimate baseline duplicates instead of dedup-by-Name")
    parser.add_argument("--scorer", type=str, default=default_scorer, choices=list_scorers(),
                        help=f"Scorer to apply (default: {default_scorer})")
    parser.add_argument("--method", type=str, default="greedy", choices=("greedy", "hungarian"),
                        help="Alignment algorithm (default: greedy)")
    return parser.parse_args()


def run_pipeline(
    baseline_file: Path,
    extraction_file: Path,
    output_dir: Path,
    scorer_name: str,
    llm: str | None = None,
    allow_duplicates: bool = False,
    method: str = "greedy",
    quiet: bool = False,
) -> Path:
    """Reusable in-process entry point.

    Identical behavior to the CLI ``main()`` but importable, so tools that
    need to score many runs in one process (avoiding repeated BERTScore model
    loads) can call this directly.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    baseline = load_baseline(baseline_file)
    extraction = load_extraction(extraction_file)

    sheets = score_run(
        baseline, extraction, scorer_name,
        allow_duplicates=allow_duplicates, method=method,
    )

    cfg = _CONFIG.get(scorer_name, {"file_prefix": f"{scorer_name}_comparison"})
    model = llm or "model"
    output = output_dir / f"{cfg['file_prefix']}_vulnerabilities_{model}.xlsx"
    write_xlsx(output, sheets)

    if not quiet:
        n_matched = int((sheets["Per_Vulnerability"]["_status"] == "OK").sum())
        n_total = len(sheets["Per_Vulnerability"])
        print(
            f"[{scorer_name.upper()}] matched={n_matched}/{n_total}, "
            f"fields scored={len(sheets['Summary'])}"
        )
        print(f"[{scorer_name.upper()}] saved → {output}")
    return output


def main(default_scorer: str = "bertscore") -> None:
    """CLI entry point — thin wrapper around :func:`run_pipeline`.

    ``default_scorer`` is the value used when ``--scorer`` is omitted on the
    command line. Legacy wrappers call this with the appropriate default so
    they retain their historical behavior.
    """
    args = _parse_args(default_scorer)
    run_pipeline(
        baseline_file=args.baseline_file,
        extraction_file=args.extraction_file,
        output_dir=args.output_dir,
        scorer_name=args.scorer,
        llm=args.llm,
        allow_duplicates=args.allow_duplicates,
        method=args.method,
    )


if __name__ == "__main__":
    main()
