"""Paired Wilcoxon tests + Bonferroni correction (metrics.md §5).

Two contrasts of interest:

    pairwise_models    — for each (version, target, source, field, metric),
        Wilcoxon between every pair of models, paired by ``run`` index.
    pairwise_versions  — for each (target, model, source, field, metric),
        Wilcoxon between every pair of versions (root folder names),
        paired by ``run`` index. Used for cross-root comparisons (e.g.
        running the pipeline against ``results_runs_v2/`` vs
        ``results_runs_v3/``).

Wilcoxon signed-rank is non-parametric and pairs samples — appropriate
when run-to-run noise is correlated within (target, model) and we are
not willing to assume normality on small N (≈10 runs).

Bonferroni is applied per *family* of comparisons (e.g. all pairwise
within one (version, source, metric)) and reported in a separate column
so callers can re-derive a different correction if desired.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from itertools import combinations
from pathlib import Path

# UTF-8 stdout on Windows.
if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"


import pandas as pd  # noqa: E402
from scipy.stats import wilcoxon  # noqa: E402

from metrics.aggregators.bootstrap_ci import derive_vuln_rates  # noqa: E402
from metrics.aggregators.multi_run import gather_long  # noqa: E402

# Columns that identify a single observation in long-format. Wilcoxon will
# pair rows that match on these, varying only the dimension under test.
_PAIR_KEYS = ("target", "source", "field", "metric")


# ---------------------------------------------------------------------------
# Wilcoxon helpers — defensive against the small-sample edge cases scipy
# raises (zero variance, all-zero differences, n < 1).
# ---------------------------------------------------------------------------

def _safe_wilcoxon(a: list[float], b: list[float]) -> tuple[float | None, float | None]:
    """Return ``(statistic, p_value)`` or ``(None, None)`` if not computable.

    Reasons we can't compute: < 1 paired observation, or all differences
    are identical (Wilcoxon is undefined). Reporting None is honest;
    raising would force every caller to wrap try/except.
    """
    if len(a) != len(b) or len(a) < 1:
        return None, None
    diffs = [x - y for x, y in zip(a, b)]
    if all(d == 0 for d in diffs):
        return None, None
    try:
        result = wilcoxon(a, b)
        return float(result.statistic), float(result.pvalue)
    except (ValueError, ZeroDivisionError):
        return None, None


def _bonferroni(pvals: list[float | None], alpha: float = 0.05) -> list[float | None]:
    """Bonferroni-corrected p-values: ``min(p · m, 1.0)`` over m valid tests."""
    valid = [p for p in pvals if p is not None]
    m = len(valid)
    if m == 0:
        return list(pvals)
    return [min(p * m, 1.0) if p is not None else None for p in pvals]


# ---------------------------------------------------------------------------
# Pairwise model contrasts.
# ---------------------------------------------------------------------------

def pairwise_models(long_df: pd.DataFrame) -> pd.DataFrame:
    """For each (version, *_PAIR_KEYS), Wilcoxon between every pair of models.

    Pairing is by ``run`` index — the same run number across the two models
    is treated as a paired observation. This is a deliberate simplification:
    different models on the same run share input data and chunking, so the
    pairing is meaningful.
    """
    rows: list[dict] = []
    if long_df.empty:
        return pd.DataFrame(rows)

    group_cols = ["version", *_PAIR_KEYS]
    for keys, sub in long_df.groupby(group_cols, dropna=False):
        models = sorted(sub["model"].unique())
        if len(models) < 2:
            continue
        per_model = {m: sub[sub["model"] == m].set_index("run")["value"] for m in models}
        for m_a, m_b in combinations(models, 2):
            common_runs = per_model[m_a].index.intersection(per_model[m_b].index)
            a = per_model[m_a].loc[common_runs].tolist()
            b = per_model[m_b].loc[common_runs].tolist()
            stat, p = _safe_wilcoxon(a, b)
            rows.append({
                **dict(zip(group_cols, keys)),
                "model_a": m_a, "model_b": m_b,
                "n": len(common_runs),
                "mean_a": (sum(a) / len(a)) if a else None,
                "mean_b": (sum(b) / len(b)) if b else None,
                "statistic": stat, "p_value": p,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    # Bonferroni per (version, source, metric) family.
    df["p_bonferroni"] = (
        df.groupby(["version", "source", "metric"])["p_value"]
        .transform(lambda s: _bonferroni(list(s)))
    )
    return df


# ---------------------------------------------------------------------------
# Pairwise version contrasts.
# ---------------------------------------------------------------------------

def pairwise_versions(long_df: pd.DataFrame) -> pd.DataFrame:
    """For each (target, model, *_PAIR_KEYS[1:]), Wilcoxon between every
    pair of versions (root folder labels), paired by ``run`` index.

    Mirrors :func:`pairwise_models`: with N versions present, emits N choose 2
    rows per group. Returns empty when only one version is loaded (nothing
    to contrast).
    """
    rows: list[dict] = []
    if long_df.empty:
        return pd.DataFrame(rows)

    group_cols = ["target", "model", *_PAIR_KEYS[1:]]  # drop "target" duplicate
    for keys, sub in long_df.groupby(group_cols, dropna=False):
        versions = sorted(sub["version"].unique())
        if len(versions) < 2:
            continue
        per_version = {v: sub[sub["version"] == v].set_index("run")["value"] for v in versions}
        for v_a, v_b in combinations(versions, 2):
            common = per_version[v_a].index.intersection(per_version[v_b].index)
            a = per_version[v_a].loc[common].tolist()
            b = per_version[v_b].loc[common].tolist()
            stat, p = _safe_wilcoxon(a, b)
            mean_a = (sum(a) / len(a)) if a else None
            mean_b = (sum(b) / len(b)) if b else None
            rows.append({
                **dict(zip(group_cols, keys)),
                "version_a": v_a, "version_b": v_b,
                "n": len(common),
                "mean_a": mean_a, "mean_b": mean_b,
                "delta_b_minus_a": (mean_b - mean_a) if mean_a is not None and mean_b is not None else None,
                "statistic": stat, "p_value": p,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["p_bonferroni"] = (
        df.groupby(["source", "metric"])["p_value"]
        .transform(lambda s: _bonferroni(list(s)))
    )
    return df


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wilcoxon paired tests + Bonferroni for model and V2/V3 contrasts.",
    )
    parser.add_argument("--root", type=Path, nargs="+", required=True,
                        help="One or more result roots (e.g. results_runs results_runs_V2)")
    parser.add_argument("--output", type=Path, required=True, help="Output XLSX path")
    args = parser.parse_args()

    # Prefer pre-aggregated Long sheets (sbseg-tp/v*) over re-scanning raw runs;
    # fall back to gather_long when the aggregate isn't there.
    frames: list[pd.DataFrame] = []
    for root in args.root:
        agg_path = root / "aggregated_metrics.xlsx"
        if agg_path.exists():
            frames.append(pd.read_excel(agg_path, sheet_name="Long", engine="openpyxl"))
        else:
            frames.append(gather_long([root]))
    long_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    if long_df.empty:
        print("[STATS] No artifacts found.")
        return

    long_df = derive_vuln_rates(long_df)

    pairwise_df = pairwise_models(long_df)
    version_df = pairwise_versions(long_df)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        pairwise_df.to_excel(writer, sheet_name="Pairwise_Models", index=False)
        version_df.to_excel(writer, sheet_name="Pairwise_Versions", index=False)

    print(f"[STATS] pairwise model rows  : {len(pairwise_df)}")
    print(f"[STATS] pairwise version rows: {len(version_df)}")
    if not version_df.empty:
        sig = version_df[version_df["p_bonferroni"].fillna(1.0) < 0.05]
        print(f"[STATS] versions significant (Bonferroni p<0.05): {len(sig)} of {len(version_df)}")
    print(f"[STATS] saved → {args.output}")


if __name__ == "__main__":
    main()
