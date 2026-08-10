"""Wide cross-version comparative table (metrics.md §0).

Composes the aggregated mean ± std with the pairwise-version Wilcoxon
result into a single wide table — one row per
``(target, model, source, field, metric, version_a, version_b)`` with
columns ``<a>_summary``, ``<b>_summary``, ``delta_b_minus_a``,
``p_value``, ``p_bonferroni``, ``significant``.

This is the figure-ready format that goes into the paper. Aggregator and
statistical_tests stay tidy/long; this module is the only place that
collapses them into wide for human reading.

Version labels come from the root directory basenames (whatever folders
the user passed to ``--root``). With ``results_runs_v2`` and
``results_runs_v3`` you get the historical V2/V3 paper table; with any
other pair of folder names the same shape applies.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from itertools import combinations
from pathlib import Path

if sys.platform.startswith("win") and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    os.environ["PYTHONIOENCODING"] = "utf-8"

sys.path.insert(0, str(Path(__file__).parents[2]))

import pandas as pd  # noqa: E402

from metrics.aggregators.multi_run import aggregate, gather_long  # noqa: E402
from metrics.aggregators.statistical_tests import pairwise_versions  # noqa: E402

# Group key shared by aggregator output and the pairwise-versions output.
_KEYS = ["target", "model", "source", "field", "metric"]


def _format_meanstd(mean: float, std: float) -> str:
    """Compact ``mean ± std`` string. ``None`` mean → empty string."""
    if pd.isna(mean):
        return ""
    if pd.isna(std):
        std = 0.0
    return f"{mean:.3f} ± {std:.3f}"


def _build_pair(agg: pd.DataFrame, stats: pd.DataFrame,
                v_a: str, v_b: str) -> pd.DataFrame:
    """Wide table for one (version_a, version_b) pair."""
    a = agg[agg["version"] == v_a].drop(columns=["version"]).rename(
        columns={"mean": "a_mean", "std": "a_std",
                 "min": "a_min", "max": "a_max", "n_runs": "a_n"})
    b = agg[agg["version"] == v_b].drop(columns=["version"]).rename(
        columns={"mean": "b_mean", "std": "b_std",
                 "min": "b_min", "max": "b_max", "n_runs": "b_n"})

    wide = a.merge(b, on=_KEYS, how="outer")
    wide.insert(0, "version_a", v_a)
    wide.insert(1, "version_b", v_b)
    wide["delta_b_minus_a"] = wide["b_mean"] - wide["a_mean"]
    wide[f"{v_a}_summary"] = wide.apply(
        lambda r: _format_meanstd(r.get("a_mean"), r.get("a_std")), axis=1)
    wide[f"{v_b}_summary"] = wide.apply(
        lambda r: _format_meanstd(r.get("b_mean"), r.get("b_std")), axis=1)

    pair_stats = stats[(stats["version_a"] == v_a) & (stats["version_b"] == v_b)]
    if not pair_stats.empty:
        cols = _KEYS + ["n", "p_value", "p_bonferroni"]
        pair_stats = pair_stats[cols].rename(columns={"n": "n_paired"})
        wide = wide.merge(pair_stats, on=_KEYS, how="left")
        wide["significant"] = wide["p_bonferroni"].fillna(1.0) < 0.05
    else:
        wide["n_paired"] = pd.NA
        wide["p_value"] = pd.NA
        wide["p_bonferroni"] = pd.NA
        wide["significant"] = False

    ordered = [
        "version_a", "version_b", *_KEYS,
        f"{v_a}_summary", f"{v_b}_summary", "delta_b_minus_a",
        "n_paired", "p_value", "p_bonferroni", "significant",
        "a_mean", "a_std", "a_n", "b_mean", "b_std", "b_n",
    ]
    keep = [c for c in ordered if c in wide.columns]
    return wide[keep].sort_values(_KEYS).reset_index(drop=True)


def build_table(long_df: pd.DataFrame) -> pd.DataFrame:
    """Build the wide cross-version table from a long-format observation set.

    With N versions present, emits rows for all N choose 2 pairs concatenated.
    """
    if long_df.empty:
        return pd.DataFrame()

    versions = sorted(long_df["version"].unique())
    if len(versions) < 2:
        return pd.DataFrame()

    agg = aggregate(long_df)
    stats = pairwise_versions(long_df)

    parts = [_build_pair(agg, stats, v_a, v_b) for v_a, v_b in combinations(versions, 2)]
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-version wide comparative table (paper-ready).",
    )
    parser.add_argument("--root", type=Path, nargs="+", required=True,
                        help="Two or more result roots; folder basenames become version labels.")
    parser.add_argument("--output", type=Path, required=True, help="Output XLSX path")
    args = parser.parse_args()

    long_df = gather_long(args.root)
    if long_df.empty:
        print("[VCMP] No artifacts found.")
        return

    table = build_table(long_df)
    if table.empty:
        print("[VCMP] Need at least two distinct versions to build the table.")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output) as writer:
        table.to_excel(writer, sheet_name="Version_Compare", index=False)

    n_total = len(table)
    n_sig = int(table["significant"].sum()) if "significant" in table.columns else 0
    n_b_better = int((table["delta_b_minus_a"] > 0).sum())
    print(f"[VCMP] rows: {n_total}")
    print(f"[VCMP] B > A (mean delta > 0): {n_b_better} ({n_b_better / max(n_total, 1):.1%})")
    print(f"[VCMP] significant (Bonferroni p<0.05): {n_sig}")
    print(f"[VCMP] saved → {args.output}")


if __name__ == "__main__":
    main()
