#!/usr/bin/env python
"""Entry point for the metrics report pipeline.

Reads ``aggregated_metrics.xlsx`` from the given roots, builds the
chart figures once, and emits both the interactive HTML report and the
PNG export (for the paper). Run after ``run_metrics.py`` so the
aggregator output exists.

Usage::

    python -m metrics.plot.metrics
    python -m metrics.plot.metrics --root results_runs results_runs_v2
    python -m metrics.plot.metrics --report-only
    python -m metrics.plot.metrics --png-only --output-dir paper_figures/
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path


import subprocess

from metrics.plot.report import build_report
from metrics.plot.comparison_report import build_comparison_report
from metrics.plot.png import export_all
from metrics.plot.data_source import load_dataset


def _ensure_aggregated(roots) -> None:
    """Run the multi_run aggregator for any root missing aggregated_metrics.xlsx.

    Aggregator is single-root by design (each root keeps its own xlsx), so
    we loop over the missing ones and call once per root.
    """
    missing = [r for r in roots if r.is_dir() and not (r / "aggregated_metrics.xlsx").is_file()]
    if not missing:
        return
    print(f"[METRICS] running aggregator for: {[str(r) for r in missing]}")
    for root in missing:
        cmd = [sys.executable, "-m", "metrics.aggregators.multi_run", "--root", str(root)]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"[METRICS] aggregator failed for {root} (exit {exc.returncode}); "
                  "continuing with whatever exists")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the metrics report (HTML + PNGs).")
    parser.add_argument("--root", type=Path, nargs="+", default=[Path("outputs/runs")],
                        help="Result roots — each must contain aggregated_metrics.xlsx (default: outputs/runs).")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/plots"),
                        help="Where the HTML and PNGs are written (default: outputs/plots).")
    parser.add_argument("--png-only", action="store_true", help="Skip the HTML report.")
    parser.add_argument("--report-only", action="store_true", help="Skip the PNG export.")
    args = parser.parse_args()

    if args.png_only and args.report_only:
        print("[METRICS] --png-only and --report-only are mutually exclusive.")
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now()

    print("=" * 70)
    print("[METRICS] MulitaMiner — chart pipeline")
    print(f"[METRICS] roots:  {[str(r) for r in args.root]}")
    print(f"[METRICS] output: {args.output_dir}")
    print("=" * 70)

    _ensure_aggregated(args.root)

    if not args.png_only:
        # Auto-dispatch: exactly 2 versions → pairwise comparison report.
        # 3+ versions is rejected (comparison is pairwise-only by design — KPIs
        # with delta, paired Wilcoxon, and the wide leaderboard assume A/B).
        ds = load_dataset(args.root)
        n_versions = len(ds.versions or [])
        if n_versions == 2:
            report_path = build_comparison_report(args.root, args.output_dir)
            print(f"[METRICS] comparison report ({ds.versions}) → {report_path}")
        elif n_versions >= 3:
            print(
                f"[METRICS] comparison report supports exactly 2 versions, found {n_versions}: "
                f"{ds.versions}. Re-run with roots containing only 2 versions."
            )
            return 2
        else:
            report_path = build_report(args.root, args.output_dir)
            print(f"[METRICS] report → {report_path}")

    if not args.report_only:
        pngs = export_all(args.root, args.output_dir)
        print(f"[METRICS] {len(pngs)} PNG(s) exported")

    elapsed = datetime.now() - started
    print(f"[METRICS] done in {elapsed.seconds}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
