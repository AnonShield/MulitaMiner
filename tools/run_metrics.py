"""Run metric pipelines across all extracted runs.

Walks ``results_runs/`` (default) or any ``--root`` you pass, and for each
``<root>/<target>/<llm>/<runN>/`` invokes every selected metric script
in parallel. Auto-runs the multi_run aggregator at the end.

Used both as a standalone tool (re-running metrics on existing extractions)
and as the post-pass triggered by ``run_experiments.py``.

The list of available methods, the dispatch table and the dependency
auto-resolution all reuse :mod:`main` (no duplication). Adding a new
metric to ``main.METRIC_SCRIPTS`` automatically exposes it here too.

Usage examples::

    # Default — every registered metric, every run under results_runs/
    python tools/run_metrics.py

    # Pointing at a specific results root (e.g. when you keep multiple)
    python tools/run_metrics.py --root results_runs_v3

    # Multiple roots in one go (paper-style cross-version comparison)
    python tools/run_metrics.py --root results_runs_v2 results_runs_v3

    # Filter by target / model
    python tools/run_metrics.py --only-target OpenVAS_JuiceShop --only-llm llama4

    # Subset of metrics — auto-deps still apply
    python tools/run_metrics.py --methods coverage severity

    # Re-run even when outputs already exist
    python tools/run_metrics.py --force
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Single source of truth for available metrics + their CLIs + their order.
from mulitaminer.pipeline.metrics_dispatch import (  # noqa: E402
    ALL_METHODS_ORDER,
    METRIC_SCRIPTS,
    expand_evaluation_methods,
)
from mulitaminer.configs.constants import RUNS_DIR  # noqa: E402

# Single canonical results root by default. Multi-root walks (e.g. for the
# V2-vs-V3 paper experiment) are opt-in via ``--root``.
DEFAULT_ROOT: Path = RUNS_DIR
DEFAULT_BASELINES_DIR: Path = PROJECT_ROOT / "resources" / "baselines"
# Overridable via --baselines-dir (reassigned in main() from the parsed args).
BASELINES_DIR = DEFAULT_BASELINES_DIR

# Output filename glob per method — used to detect "already done" runs and
# skip them unless ``--force`` is passed.
_OUTPUT_PATTERNS: dict[str, str] = {
    "bert":     "bert_comparison_*.xlsx",
    "rouge":    "rouge_comparison_*.xlsx",
    "token_f1": "token_f1_comparison_*.xlsx",
    "field_f1":  "field_f1_metrics_*.xlsx",
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

def _expected_extraction_file(run_dir: Path, target: str, llm: str) -> Path | None:
    """Locate the extraction file inside ``run_dir`` — JSON preferred.

    Pipelines now read JSON natively (the tool's default output), so we look
    for ``<target>_<llm>_<run>*.json`` first. Fall back to the legacy XLSX
    glob for older runs that only have the converted output. Files matching
    metric-output globs are excluded so we never confuse them with the input.
    """
    metric_outputs = {p for pat in _OUTPUT_PATTERNS.values() for p in run_dir.glob(pat)}

    for ext in ("json", "xlsx"):
        candidates = [
            p for p in sorted(run_dir.glob(f"{target}_{llm}_{run_dir.name}*.{ext}"))
            if p not in metric_outputs
        ]
        if candidates:
            return candidates[0]
    return None


def metric_done(run_dir: Path, method: str) -> bool:
    pattern = _OUTPUT_PATTERNS.get(method)
    return bool(pattern and any(run_dir.glob(pattern)))


# Methods routed through compare_extractions.run_pipeline (no subprocess).
# BERTScore loads a transformer model once per process — running in-process
# means we pay the load cost once across all runs instead of once per subprocess.
_IN_PROCESS_SCORERS: dict[str, str] = {"bert": "bertscore", "rouge": "rouge_l"}


def run_metric_subprocess(
    method: str,
    baseline: Path,
    run_dir: Path,
    target: str,
    llm: str,
    allow_duplicates: bool,
) -> tuple[bool, str | None]:
    """Invoke one metric script for one run as a subprocess."""
    extraction = _expected_extraction_file(run_dir, target, llm)
    if extraction is None:
        return False, "no extraction file"

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
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True, None
    except subprocess.CalledProcessError as exc:
        # Surface the full traceback so subtle errors (numpy/pandas type clashes
        # that only manifest on certain extractions) aren't reduced to a one-liner.
        out = (exc.stderr or exc.stdout or "").strip()
        if not out:
            return False, f"exit {exc.returncode} (no stderr)"
        return False, "\n----- subprocess stderr -----\n" + out + "\n-----------------------------"


def run_metric_in_process(
    method: str,
    baseline: Path,
    run_dir: Path,
    target: str,
    llm: str,
    allow_duplicates: bool,
) -> tuple[bool, str | None]:
    """Run bert/rouge directly via compare_extractions.run_pipeline.

    Reuses the same Python process across calls so heavy resources
    (BERTScore transformer) load exactly once.
    """
    extraction = _expected_extraction_file(run_dir, target, llm)
    if extraction is None:
        return False, "no extraction file"

    from metrics.pipelines.compare_extractions import run_pipeline
    try:
        run_pipeline(
            baseline_file=baseline,
            extraction_file=extraction,
            output_dir=run_dir,
            scorer_name=_IN_PROCESS_SCORERS[method],
            llm=llm,
            allow_duplicates=allow_duplicates,
            quiet=True,
        )
        return True, None
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


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
    parser.add_argument(
        "--baselines-dir", type=Path, default=DEFAULT_BASELINES_DIR,
        help="Directory holding <scanner>/<target>.xlsx baselines. "
             f"Default: {DEFAULT_BASELINES_DIR.relative_to(PROJECT_ROOT).as_posix()}/.",
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
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Parallel workers (run-level). Default: 4. Use 1 for serial.",
    )
    parser.add_argument(
        "--no-aggregate", action="store_true",
        help="Skip the multi_run aggregator at the end.",
    )
    return parser.parse_args()


def _rel(run_dir: Path) -> str:
    return str(run_dir.relative_to(PROJECT_ROOT) if run_dir.is_relative_to(PROJECT_ROOT) else run_dir)


def _process_one(
    method: str, target: str, llm: str, run_dir: Path,
    force: bool, allow_duplicates: bool,
) -> tuple[str, str, str | None]:
    """Run a single (method, run) pair. Returns (status, rel, err).

    status ∈ {"ok", "skipped", "no_baseline", "failed"}.
    """
    rel = _rel(run_dir)
    baseline = find_baseline(target)
    if baseline is None:
        return "no_baseline", rel, None

    if not force and metric_done(run_dir, method):
        return "skipped", rel, None

    runner = run_metric_in_process if method in _IN_PROCESS_SCORERS else run_metric_subprocess
    ok, err = runner(method, baseline, run_dir, target, llm, allow_duplicates)
    return ("ok" if ok else "failed"), rel, err


def _run_aggregator(roots: list[Path]) -> None:
    """Invoke metrics.aggregators.multi_run with default output path."""
    valid_roots = [str(r) for r in roots if Path(r).is_dir()]
    if not valid_roots:
        return
    primary = Path(valid_roots[0])
    output = primary / "aggregated_metrics.xlsx"
    cmd = [
        sys.executable, "-m", "metrics.aggregators.multi_run",
        "--root", *valid_roots,
        "--output", str(output),
    ]
    print(f"\n[AGG] Running aggregator → {output}")
    try:
        subprocess.run(cmd, check=True, cwd=str(PROJECT_ROOT))
    except subprocess.CalledProcessError as exc:
        print(f"[AGG] Aggregator failed (exit {exc.returncode})")


def main() -> None:
    args = _parse_args()

    global BASELINES_DIR
    BASELINES_DIR = args.baselines_dir

    methods = expand_evaluation_methods(args.methods)
    if not methods:
        print("[ERROR] No valid metrics resolved from --methods.")
        sys.exit(1)

    roots = [Path(r) for r in args.root]
    runs = discover_runs(roots, args.only_target, args.only_llm)
    if not runs:
        print("[ERROR] No runs discovered under the given roots.")
        sys.exit(1)

    print(f"[INFO] {len(runs)} runs × {len(methods)} methods → "
          f"{len(runs) * len(methods)} invocations max")
    print(f"[INFO] methods: {methods}")
    print(f"[INFO] roots  : {[str(r) for r in roots if r.is_dir()]}")
    print(f"[INFO] workers: {args.workers}, force: {args.force}, "
          f"allow_duplicates: {args.allow_duplicates}")
    print()

    stats = {"ok": 0, "skipped": 0, "failed": 0, "no_baseline": 0}
    failures: list[tuple[str, str, str]] = []  # (rel, method, error)
    print_lock = threading.Lock()

    def _record(method: str, status: str, rel: str, err: str | None,
                completed: list[int], total: int) -> None:
        with print_lock:
            completed[0] += 1
            stats[status] += 1
            tag = f"[{method} {completed[0]}/{total}]"
            if status == "failed":
                failures.append((rel, method, err or ""))
                print(f"{tag} {rel}  FAIL: {err}")
            elif status == "no_baseline":
                print(f"{tag} {rel}  SKIP (no baseline)")
            elif status == "skipped":
                print(f"{tag} {rel}  skip (already done)")
            else:
                print(f"{tag} {rel}  ok")

    # Iterate methods in dependency order. Schema runs first; bert/rouge produce
    # the matched-pairs that field_f1/severity/coverage consume; so phase order is
    # crucial regardless of within-phase parallelism.
    for method in methods:
        completed = [0]
        is_in_process = method in _IN_PROCESS_SCORERS
        # In-process scorers (bert/rouge) hold a shared transformer model;
        # parallelizing across threads serializes on torch anyway and forces
        # multiple model loads. Run sequentially in-process.
        workers = 1 if is_in_process else max(1, args.workers)
        print(f"\n[PHASE] {method} ({'in-process' if is_in_process else 'subprocess'}, "
              f"workers={workers})")

        if workers <= 1:
            for target, llm, run_dir in runs:
                status, rel, err = _process_one(
                    method, target, llm, run_dir, args.force, args.allow_duplicates
                )
                _record(method, status, rel, err, completed, len(runs))
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [
                    pool.submit(_process_one, method, target, llm, run_dir,
                                args.force, args.allow_duplicates)
                    for target, llm, run_dir in runs
                ]
                for fut in as_completed(futures):
                    status, rel, err = fut.result()
                    _record(method, status, rel, err, completed, len(runs))

    print()
    print("=" * 60)
    print(
        f"Done: {stats['ok']} ok · {stats['skipped']} skipped · "
        f"{stats['failed']} failed · {stats['no_baseline']} no-baseline"
    )
    if failures:
        print("\nFailures:")
        for rel, method, err in failures:
            print(f"  - [{method}] {rel}: {err}")
    print("=" * 60)

    if not args.no_aggregate and stats["ok"] + stats["skipped"] > 0:
        _run_aggregator(roots)


if __name__ == "__main__":
    main()
