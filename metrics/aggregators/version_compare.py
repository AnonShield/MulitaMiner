"""Paper-ready V2 vs V3 comparative table (metrics.md §0).

Composes the aggregated mean ± std with the Wilcoxon V2-vs-V3 result into
a single wide table — one row per (target, model, source, field, metric)
with columns ``V2_mean ± V2_std``, ``V3_mean ± V3_std``, ``delta``,
``p_value``, ``p_bonferroni``, ``significant``.

This is the figure-ready format that goes into the paper. Aggregator and
statistical_tests stay tidy/long; this module is the only place that
collapses them into wide for human reading.
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

import pandas as pd  # noqa: E402

from metrics.aggregators.multi_run import aggregate, gather_long  # noqa: E402
from metrics.aggregators.statistical_tests import v2_vs_v3  # noqa: E402

# Group key shared by aggregator output and the wilcoxon V2-vs-V3 output.
_KEYS = ["target", "model", "source", "field", "metric"]


def _format_meanstd(mean: float, std: float) -> str:
    """Compact ``mean ± std`` string. ``None`` mean → empty string."""
    if pd.isna(mean):
        return ""
    if pd.isna(std):
        std = 0.0
    return f"{mean:.3f} ± {std:.3f}"


def build_table(long_df: pd.DataFrame) -> pd.DataFrame:
    """Build the wide V2 vs V3 table from a long-format observation set."""
    if long_df.empty:
        return pd.DataFrame()

    agg = aggregate(long_df)

    # Pivot V2 and V3 stats side by side.
    v2 = agg[agg["version"] == "v2"].drop(columns=["version"])
    v3 = agg[agg["version"] == "v3"].drop(columns=["version"])
    v2 = v2.rename(columns={"mean": "v2_mean", "std": "v2_std",
                            "min": "v2_min", "max": "v2_max", "n_runs": "v2_n"})
    v3 = v3.rename(columns={"mean": "v3_mean", "std": "v3_std",
                            "min": "v3_min", "max": "v3_max", "n_runs": "v3_n"})

    wide = v2.merge(v3, on=_KEYS, how="outer")
    wide["delta_v3_minus_v2"] = wide["v3_mean"] - wide["v2_mean"]
    wide["v2_summary"] = wide.apply(
        lambda r: _format_meanstd(r.get("v2_mean"), r.get("v2_std")), axis=1)
    wide["v3_summary"] = wide.apply(
        lambda r: _format_meanstd(r.get("v3_mean"), r.get("v3_std")), axis=1)

    # Attach Wilcoxon V2-vs-V3 results.
    stats = v2_vs_v3(long_df)
    if not stats.empty:
        stats = stats[_KEYS + ["n", "p_value", "p_bonferroni"]].rename(
            columns={"n": "n_paired"})
        wide = wide.merge(stats, on=_KEYS, how="left")
        wide["significant"] = wide["p_bonferroni"].fillna(1.0) < 0.05
    else:
        wide["n_paired"] = pd.NA
        wide["p_value"] = pd.NA
        wide["p_bonferroni"] = pd.NA
        wide["significant"] = False

    # Order columns paper-friendly: keys first, then summaries, then stats.
    ordered = [
        *_KEYS,
        "v2_summary", "v3_summary", "delta_v3_minus_v2",
        "n_paired", "p_value", "p_bonferroni", "significant",
        "v2_mean", "v2_std", "v2_n", "v3_mean", "v3_std", "v3_n",
    ]
    keep = [c for c in ordered if c in wide.columns]
    return wide[keep].sort_values(_KEYS).reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="V2 vs V3 wide comparative table (paper-ready).",
    )
    parser.add_argument("--root", type=Path, nargs="+", required=True,
                        help="One or more result roots (e.g. results_runs results_runs_V2)")
    parser.add_argument("--output", type=Path, required=True, help="Output XLSX path")
    args = parser.parse_args()

    long_df = gather_long(args.root)
    if long_df.empty:
        print("[VCMP] No artifacts found.")
        return

    table = build_table(long_df)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        table.to_excel(writer, sheet_name="V2_vs_V3", index=False)

    n_total = len(table)
    n_sig = int(table["significant"].sum()) if "significant" in table.columns else 0
    n_v3_better = int((table["delta_v3_minus_v2"] > 0).sum())
    print(f"[VCMP] rows: {n_total}")
    print(f"[VCMP] V3 > V2 (mean delta > 0): {n_v3_better} ({n_v3_better / max(n_total, 1):.1%})")
    print(f"[VCMP] significant (Bonferroni p<0.05): {n_sig}")
    print(f"[VCMP] saved → {args.output}")


if __name__ == "__main__":
    main()
