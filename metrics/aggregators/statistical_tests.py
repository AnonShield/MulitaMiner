"""Paired Wilcoxon tests + Bonferroni correction (metrics.md §5).

Two contrasts of interest:

    pairwise_models  — for each (version, target, source, field, metric),
        Wilcoxon between every pair of models, paired by ``run`` index.
    v2_vs_v3         — for each (target, model, source, field, metric),
        Wilcoxon between V2 and V3 paired by ``run`` index.

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

sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd  # noqa: E402
from scipy.stats import wilcoxon  # noqa: E402

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
# V2 vs V3 contrast.
# ---------------------------------------------------------------------------

def v2_vs_v3(long_df: pd.DataFrame) -> pd.DataFrame:
    """For each (target, model, source, field, metric), Wilcoxon V2 vs V3."""
    rows: list[dict] = []
    if long_df.empty:
        return pd.DataFrame(rows)

    group_cols = ["target", "model", *_PAIR_KEYS[1:]]  # drop the per-version "target" duplicate
    for keys, sub in long_df.groupby(group_cols, dropna=False):
        versions = set(sub["version"].unique())
        if not {"v2", "v3"}.issubset(versions):
            continue
        v2 = sub[sub["version"] == "v2"].set_index("run")["value"]
        v3 = sub[sub["version"] == "v3"].set_index("run")["value"]
        common = v2.index.intersection(v3.index)
        a, b = v2.loc[common].tolist(), v3.loc[common].tolist()
        stat, p = _safe_wilcoxon(a, b)
        rows.append({
            **dict(zip(group_cols, keys)),
            "n": len(common),
            "mean_v2": (sum(a) / len(a)) if a else None,
            "mean_v3": (sum(b) / len(b)) if b else None,
            "delta_v3_minus_v2": ((sum(b) / len(b)) - (sum(a) / len(a))) if a and b else None,
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

    long_df = gather_long(args.root)
    if long_df.empty:
        print("[STATS] No artifacts found.")
        return

    pairwise_df = pairwise_models(long_df)
    version_df = v2_vs_v3(long_df)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        pairwise_df.to_excel(writer, sheet_name="Pairwise_Models", index=False)
        version_df.to_excel(writer, sheet_name="V2_vs_V3", index=False)

    print(f"[STATS] pairwise model rows: {len(pairwise_df)}")
    print(f"[STATS] V2 vs V3 rows      : {len(version_df)}")
    if not version_df.empty:
        sig = version_df[version_df["p_bonferroni"].fillna(1.0) < 0.05]
        print(f"[STATS] V2 vs V3 significant (Bonferroni p<0.05): {len(sig)} of {len(version_df)}")
    print(f"[STATS] saved → {args.output}")


if __name__ == "__main__":
    main()
