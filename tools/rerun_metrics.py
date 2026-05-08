"""Iterate over existing run directories and (re)run metric pipelines.

Walks ``results_runs/`` (default) or any ``--root`` you pass, and for each
``<root>/<target>/<llm>/<runN>/`` invokes every selected metric script
without redoing the LLM extraction.

The list of available methods, the dispatch table and the dependency
auto-resolution all reuse :mod:`main` (no duplication). Adding a new
metric to ``main.METRIC_SCRIPTS`` automatically exposes it here too.

Usage examples::

    # Default — every registered metric, every run under results_runs/
    python tools/rerun_metrics.py

    # Pointing at a specific results root (e.g. when you keep multiple)
    python tools/rerun_metrics.py --root results_runs_v3

    # Multiple roots in one go (paper-style cross-version comparison)
    python tools/rerun_metrics.py --root results_runs_v2 results_runs_v3

    # Filter by target / model
    python tools/rerun_metrics.py --only-target OpenVAS_JuiceShop --only-llm llama4

    # Subset of metrics — auto-deps still apply
    python tools/rerun_metrics.py --methods coverage severity

    # Re-run even when outputs already exist
    python tools/rerun_metrics.py --force
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Single source of truth for available metrics + their CLIs + their order.
from main import (  # noqa: E402
    ALL_METHODS_ORDER,
    METRIC_SCRIPTS,
    expand_evaluation_methods,
)

# Single canonical results root by default. Multi-root walks (e.g. for the
# V2-vs-V3 paper experiment) are opt-in via ``--root``.
DEFAULT_ROOT: Path = PROJECT_ROOT / "results_runs"
BASELINES_DIR = PROJECT_ROOT / "baselines"

# Output filename glob per method — used to detect "already done" runs and
# skip them unless ``--force`` is passed.
_OUTPUT_PATTERNS: dict[str, str] = {
    "bert":     "bert_comparison_*.xlsx",
    "rouge":    "rouge_comparison_*.xlsx",
    "entity":   "entity_metrics_*.xlsx",
    "schema":   "schema_report_*.json",
    "severity": "severity_confusion_*.xlsx",
    "coverage": "coverage_*.xlsx",
}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_baseline(target_name: str) -> Path | None:
    """Locate ``baselines/<scanner>/<target>.xlsx`` across any scanner dir."""
    if not BASELINES_DIR.is_dir():
        return None
    for scanner_dir in BASELINES_DIR.iterdir():
        if not scanner_dir.is_dir():
            continue
        candidate = scanner_dir / f"{target_name}.xlsx"
        if candidate.is_file():
            return candidate
    return None


def discover_runs(
    roots: list[Path],
    only_target: str | None,
    only_llm: str | None,
) -> list[tuple[str, str, Path]]:
    """Return ``(target, llm, run_dir)`` tuples found under any root."""
    runs: list[tuple[str, str, Path]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for target_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            if only_target and target_dir.name != only_target:
                continue
            for llm_dir in sorted(p for p in target_dir.iterdir() if p.is_dir()):
                if only_llm and llm_dir.name != only_llm:
                    continue
                for run_dir in sorted(p for p in llm_dir.iterdir() if p.is_dir()):
                    if not run_dir.name.lower().startswith("run"):
                        continue
                    runs.append((target_dir.name, llm_dir.name, run_dir))
    return runs


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _expected_extraction_xlsx(run_dir: Path, target: str, llm: str) -> Path | None:
    """Locate the converted-extraction XLSX inside ``run_dir``.

    V3 uses the canonical name ``<target>_<llm>_<run>.xlsx``; V2 attaches a
    timestamp (``<target>_<llm>_<run>_<target>_<llm>_<ts>.xlsx``). Both are
    accepted by globbing for ``<target>_<llm>_<run>*.xlsx`` and excluding
    files that match the metric-output globs.
    """
    metric_outputs = {p for pat in _OUTPUT_PATTERNS.values() for p in run_dir.glob(pat)}
    candidates = [
        p for p in sorted(run_dir.glob(f"{target}_{llm}_{run_dir.name}*.xlsx"))
        if p not in metric_outputs
    ]
    return candidates[0] if candidates else None


def metric_done(run_dir: Path, method: str) -> bool:
    pattern = _OUTPUT_PATTERNS.get(method)
    return bool(pattern and any(run_dir.glob(pattern)))


def run_metric(
    method: str,
    baseline: Path,
    run_dir: Path,
    target: str,
    llm: str,
    allow_duplicates: bool,
) -> bool:
    """Invoke one metric script for one run; return True on success."""
    extraction = _expected_extraction_xlsx(run_dir, target, llm)
    if extraction is None:
        print(f"  [SKIP] no extraction xlsx in {run_dir}")
        return False

    script_path, *fixed_args = METRIC_SCRIPTS[method]
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / script_path),
        "--baseline-file", str(baseline),
        "--extraction-file", str(extraction),
        "--output-dir", str(run_dir),
        "--llm", llm,
        *fixed_args,
    ]
    if allow_duplicates:
        cmd.append("--allow-duplicates")

    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  [ERROR] {method} failed (exit {exc.returncode})")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root", type=Path, nargs="+", default=[DEFAULT_ROOT],
        help=f"Result roots to walk. Default: {DEFAULT_ROOT.name}/. Pass multiple "
             "paths for cross-root comparisons (e.g. results_runs_v2 results_runs_v3).",
    )
    parser.add_argument("--only-target", help="Filter by target dir name (e.g. OpenVAS_JuiceShop)")
    parser.add_argument("--only-llm", help="Filter by LLM dir name (e.g. llama4)")
    parser.add_argument(
        "--methods", nargs="+", default=["all"],
        help=(
            "Metric names to run. Use 'all' for every registered metric. "
            f"Available: {', '.join(ALL_METHODS_ORDER)}. Producer/consumer "
            "deps are auto-resolved (e.g. requesting only 'paper' adds 'bert')."
        ),
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-run even when the expected output file already exists.",
    )
    parser.add_argument(
        "--allow-duplicates", action=argparse.BooleanOptionalAction, default=True,
        help="Forwarded to each metric. Default: on (use --no-allow-duplicates to disable).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    methods = expand_evaluation_methods(args.methods)
    if not methods:
        print("[ERROR] No valid metrics resolved from --methods.")
        sys.exit(1)

    runs = discover_runs(
        [Path(r) for r in args.root], args.only_target, args.only_llm,
    )
    if not runs:
        print("[ERROR] No runs discovered under the given roots.")
        sys.exit(1)

    print(f"[INFO] {len(runs)} runs × {len(methods)} methods → "
          f"{len(runs) * len(methods)} invocations max")
    print(f"[INFO] methods: {methods}")
    print(f"[INFO] roots  : {[str(r) for r in args.root if Path(r).is_dir()]}")
    print(f"[INFO] force  : {args.force}, allow_duplicates: {args.allow_duplicates}")
    print()

    stats = {"ok": 0, "skipped": 0, "failed": 0, "no_baseline": 0}

    for i, (target, llm, run_dir) in enumerate(runs, 1):
        rel = run_dir.relative_to(PROJECT_ROOT) if run_dir.is_relative_to(PROJECT_ROOT) else run_dir
        print(f"[{i}/{len(runs)}] {rel}")

        baseline = find_baseline(target)
        if baseline is None:
            print(f"  [SKIP] no baseline found for '{target}'")
            stats["no_baseline"] += 1
            continue

        for method in methods:
            if not args.force and metric_done(run_dir, method):
                print(f"  [SKIP] {method} already done")
                stats["skipped"] += 1
                continue
            print(f"  [RUN] {method}")
            ok = run_metric(method, baseline, run_dir, target, llm, args.allow_duplicates)
            stats["ok" if ok else "failed"] += 1

    print()
    print("=" * 60)
    print(
        f"Done: {stats['ok']} ok · {stats['skipped']} skipped · "
        f"{stats['failed']} failed · {stats['no_baseline']} no-baseline"
    )
    print("=" * 60)


if __name__ == "__main__":
    main()
