"""Bootstrap confidence intervals for the paper's headline metrics.

Complements :mod:`statistical_tests` (Wilcoxon, decides "is the difference
real?") with a per-cell uncertainty estimate ("how confident am I in this
number?"). Both are reported in the paper: CIs go in the result tables,
Wilcoxon goes in the comparison text.

Aggregation level matches the paper. Each headline cell in the aggregate
table is the grand mean over all (model, baseline, run) observations for
that version --- i.e. 5 models × 3 baselines × 10 runs = 150 cells per
version. We bootstrap over those 150 observations directly (pooled
bootstrap on the cells that make up the reported number).

Pooled (rather than hierarchical) is the right resampling unit here
because the paper's reported point estimate is itself a pooled mean.
A hierarchical bootstrap would estimate the CI of a different number
(the mean of (model, baseline) means).

Output: tidy DataFrame with one row per (version, source, metric):
    version, source, metric, n, mean, ci_lo, ci_hi, half_width
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from pathlib import Path

if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

sys.path.insert(0, str(Path(__file__).parents[2]))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from metrics.aggregators.multi_run import gather_long  # noqa: E402

# Metrics that appear in the paper's headline aggregate table.
# Each entry: (source, metric). field is always "_overall" for these.
HEADLINE_METRICS: tuple[tuple[str, str], ...] = (
    ("coverage", "n_matched_pairs"),
    ("coverage", "n_extraction_unmatched"),
    ("coverage", "n_baseline_unmatched"),
    ("coverage", "exact_record_match"),
    ("coverage", "hallucination_rate"),
    ("coverage", "omission_rate"),
    ("coverage", "vuln_hallucination_rate"),
    ("coverage", "vuln_omission_rate"),
    ("severity", "macro_F1"),
    ("severity", "coverage_aware_macro_F1"),
    ("severity", "accuracy"),
)


def derive_vuln_rates(long_df: pd.DataFrame) -> pd.DataFrame:
    """Add vuln_hallucination_rate / vuln_omission_rate per run if missing.

    Older aggregated_metrics.xlsx files were generated before these metrics
    existed in coverage.py. Derive them on the fly from the counts so bootstrap
    and Wilcoxon can run without re-extracting 150 PDFs.
    """
    if long_df.empty:
        return long_df
    have = set(long_df[long_df["source"] == "coverage"]["metric"].unique())
    needed = {"vuln_hallucination_rate", "vuln_omission_rate"} - have
    if not needed:
        return long_df

    cov = long_df[(long_df["source"] == "coverage") & (long_df["field"] == "_overall")]
    piv = cov.pivot_table(
        index=["version", "target", "model", "run"],
        columns="metric",
        values="value",
    ).reset_index()
    required = {"n_matched_pairs", "n_extraction_unmatched", "n_baseline_unmatched"}
    if not required.issubset(piv.columns):
        return long_df

    n_ext_total = piv["n_matched_pairs"] + piv["n_extraction_unmatched"]
    n_base_total = piv["n_matched_pairs"] + piv["n_baseline_unmatched"]

    new_rows = []
    for metric, num, denom in [
        ("vuln_hallucination_rate", piv["n_extraction_unmatched"], n_ext_total),
        ("vuln_omission_rate", piv["n_baseline_unmatched"], n_base_total),
    ]:
        if metric not in needed:
            continue
        rate = (num / denom).where(denom > 0, 0.0)
        block = piv[["version", "target", "model", "run"]].copy()
        block["source"] = "coverage"
        block["field"] = "_overall"
        block["metric"] = metric
        block["value"] = rate.values
        new_rows.append(block)

    if not new_rows:
        return long_df
    return pd.concat([long_df] + new_rows, ignore_index=True)


def bootstrap_ci(
    values: np.ndarray,
    n_boot: int = 10_000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float, float]:
    """Percentile bootstrap CI for the mean.

    Returns ``(mean, ci_lo, ci_hi)``. Empty input returns ``(nan, nan, nan)``.
    """
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if values.size == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    # Vectorised resampling: one (n_boot, n) matrix, mean over axis=1.
    idx = rng.integers(0, values.size, size=(n_boot, values.size))
    boot_means = values[idx].mean(axis=1)
    lo = float(np.percentile(boot_means, 100 * alpha / 2))
    hi = float(np.percentile(boot_means, 100 * (1 - alpha / 2)))
    return float(values.mean()), lo, hi


def headline_cis(long_df: pd.DataFrame, n_boot: int = 10_000) -> pd.DataFrame:
    """Compute bootstrap CIs for every (version, source, metric) headline.

    Pools observations across (model, target, run) within each version,
    matching how the paper's aggregate table reports its numbers.
    """
    if long_df.empty:
        return pd.DataFrame()

    rows: list[dict] = []
    for version in sorted(long_df["version"].unique()):
        for source, metric in HEADLINE_METRICS:
            sub = long_df[
                (long_df["version"] == version)
                & (long_df["source"] == source)
                & (long_df["field"] == "_overall")
                & (long_df["metric"] == metric)
            ]
            if sub.empty:
                continue
            mean, lo, hi = bootstrap_ci(sub["value"].to_numpy(), n_boot=n_boot)
            rows.append({
                "version": version,
                "source": source,
                "metric": metric,
                "n": int(sub.shape[0]),
                "mean": mean,
                "ci_lo": lo,
                "ci_hi": hi,
                "half_width": (hi - lo) / 2.0,
            })
    return pd.DataFrame(rows)


def per_config_cis(long_df: pd.DataFrame, n_boot: int = 10_000) -> pd.DataFrame:
    """CIs at the (version, model, target) level — 10 runs per group.

    Useful for the per-model tables and for diagnostics (e.g. which
    (model, baseline) pair carries the largest residual uncertainty).
    """
    if long_df.empty:
        return pd.DataFrame()

    rows: list[dict] = []
    group_cols = ["version", "model", "target", "source", "metric"]
    sub_all = long_df[long_df["field"] == "_overall"]
    for keys, grp in sub_all.groupby(group_cols, dropna=False):
        if (keys[3], keys[4]) not in HEADLINE_METRICS:
            continue
        mean, lo, hi = bootstrap_ci(grp["value"].to_numpy(), n_boot=n_boot)
        rows.append({
            **dict(zip(group_cols, keys)),
            "n": int(grp.shape[0]),
            "mean": mean,
            "ci_lo": lo,
            "ci_hi": hi,
        })
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap 95%% CIs for headline metrics across versions.",
    )
    parser.add_argument("--root", type=Path, nargs="+", required=True,
                        help="One or more result roots (e.g. sbseg-tp/v1 sbseg-tp/v2 sbseg-tp/v3)")
    parser.add_argument("--output", type=Path, required=True, help="Output XLSX path")
    parser.add_argument("--n-boot", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    # gather_long discovers run artifacts under each root; for already-aggregated
    # sbseg-tp/v* folders we instead read the saved Long sheet directly.
    frames: list[pd.DataFrame] = []
    for root in args.root:
        agg_path = root / "aggregated_metrics.xlsx"
        if agg_path.exists():
            frames.append(pd.read_excel(agg_path, sheet_name="Long", engine="openpyxl"))
        else:
            frames.append(gather_long([root]))
    long_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    if long_df.empty:
        print("[CI] No artifacts found.")
        return

    long_df = derive_vuln_rates(long_df)

    headline = headline_cis(long_df, n_boot=args.n_boot)
    per_config = per_config_cis(long_df, n_boot=args.n_boot)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        headline.to_excel(writer, sheet_name="Headline", index=False)
        per_config.to_excel(writer, sheet_name="Per_Config", index=False)

    print(f"[CI] headline rows  : {len(headline)}")
    print(f"[CI] per-config rows: {len(per_config)}")
    print(f"[CI] saved → {args.output}")
    print()
    print(headline.to_string(index=False))


if __name__ == "__main__":
    main()
