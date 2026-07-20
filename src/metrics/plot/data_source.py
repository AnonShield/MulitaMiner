"""Single source of truth for chart input data.

Reads the canonical aggregator output (``aggregated_metrics.xlsx``) plus
the per-run metric XLSX files that hold matrices/distributions too large
for the long format. Returns a :class:`Dataset` dataclass — every chart
module pulls from this, never from disk directly.

Replaces the legacy ``data_collector.py`` (which read removed
``summary_all_extractions_*.xlsx`` files and was 800 lines of manual
walking).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pandas as pd


@dataclass
class Dataset:
    """All data the report needs, indexed for fast filtering.

    The two DataFrames mirror the aggregator's two sheets; ``per_run`` is
    the long table (one row per run/field/metric) and ``agg`` is the
    summarised mean ± std. Targets/models/sources/metrics are pre-computed
    so chart code doesn't repeat ``df["model"].unique()`` everywhere.
    """
    long: pd.DataFrame
    agg: pd.DataFrame
    targets: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    run_dirs: list[Path] = field(default_factory=list)

    def filter(self, **kwargs) -> "Dataset":
        """Return a new Dataset filtered on long/agg by the given column=value pairs."""
        long = self.long.copy()
        agg = self.agg.copy()
        for k, v in kwargs.items():
            if k in long.columns:
                long = long[long[k] == v]
            if k in agg.columns:
                agg = agg[agg[k] == v]
        return Dataset(
            long=long, agg=agg,
            targets=sorted(long["target"].dropna().unique().tolist()),
            models=sorted(long["model"].dropna().unique().tolist()),
            sources=sorted(long["source"].dropna().unique().tolist()),
            versions=long["version"].dropna().drop_duplicates().tolist(),
            run_dirs=self.run_dirs,
        )


# ---------------------------------------------------------------------------
# Loaders.
# ---------------------------------------------------------------------------

def load_dataset(roots: Iterable[Path]) -> Dataset:
    """Read ``<root>/aggregated_metrics.xlsx`` from each root and merge.

    If a root has no aggregated file, it's skipped silently (a fresh root
    won't have one until the aggregator runs). The result is empty when
    no roots have data — chart modules check ``dataset.long.empty`` and
    render a placeholder.
    """
    long_parts: list[pd.DataFrame] = []
    agg_parts: list[pd.DataFrame] = []
    run_dirs: list[Path] = []

    for root in roots:
        root = Path(root)
        agg_file = root / "aggregated_metrics.xlsx"
        if agg_file.is_file():
            sheets = _read_agg_sheets(agg_file)
            if sheets is not None:
                long_parts.append(sheets[0])
                agg_parts.append(sheets[1])
        run_dirs.extend(_discover_run_dirs(root))

    long = pd.concat(long_parts, ignore_index=True) if long_parts else _empty_long()
    agg = pd.concat(agg_parts, ignore_index=True) if agg_parts else _empty_agg()

    return Dataset(
        long=long, agg=agg,
        targets=sorted(long["target"].dropna().unique().tolist()) if not long.empty else [],
        models=sorted(long["model"].dropna().unique().tolist()) if not long.empty else [],
        sources=sorted(long["source"].dropna().unique().tolist()) if not long.empty else [],
        versions=long["version"].dropna().drop_duplicates().tolist() if not long.empty else [],
        run_dirs=run_dirs,
    )


def _read_agg_sheets(path: Path, *, retries: int = 3, delay: float = 0.4):
    """Read Long + Aggregated sheets, retrying on transient read errors.

    On Windows the aggregator's subprocess may finish before the OS makes
    the freshly-written file fully visible (AV scan, write buffer flush).
    A short backoff turns those flaky EOFErrors into a successful read on
    the second attempt.
    """
    import time
    import zipfile

    transient = (EOFError, zipfile.BadZipFile, OSError)
    for attempt in range(retries):
        try:
            long = pd.read_excel(path, sheet_name="Long")
            agg = pd.read_excel(path, sheet_name="Aggregated")
            return long, agg
        except (ValueError, FileNotFoundError):
            return None
        except transient as exc:
            if attempt == retries - 1:
                print(f"[DATA] giving up reading {path}: {type(exc).__name__}: {exc}")
                return None
            time.sleep(delay * (attempt + 1))
    return None


def _empty_long() -> pd.DataFrame:
    return pd.DataFrame(columns=["version", "target", "model", "run", "source", "field", "metric", "value"])


def _empty_agg() -> pd.DataFrame:
    return pd.DataFrame(columns=["version", "target", "model", "source", "field", "metric",
                                 "mean", "std", "min", "max", "n_runs"])


def _discover_run_dirs(root: Path) -> list[Path]:
    """Yield every ``<root>/<target>/<llm>/run<N>/`` directory under ``root``."""
    if not root.is_dir():
        return []
    out: list[Path] = []
    for target_dir in root.iterdir():
        if not target_dir.is_dir():
            continue
        for llm_dir in target_dir.iterdir():
            if not llm_dir.is_dir():
                continue
            for run_dir in llm_dir.iterdir():
                if run_dir.is_dir() and run_dir.name.lower().startswith("run"):
                    out.append(run_dir)
    return out


# ---------------------------------------------------------------------------
# Per-run readers — for matrices that don't fit the long format.
# ---------------------------------------------------------------------------

def load_severity_confusions(run_dirs: Iterable[Path]) -> dict[tuple[str, str], pd.DataFrame]:
    """Return ``{(target, model): mean_confusion_matrix}``.

    Reads the ``Confusion`` sheet from every ``severity_confusion_*.xlsx``
    and averages across runs of the same (target, model). Empty dict when
    no severity files exist.
    """
    raw: dict[tuple[str, str], list[pd.DataFrame]] = {}
    for run_dir in run_dirs:
        target = run_dir.parent.parent.name
        model = run_dir.parent.name
        for path in run_dir.glob("severity_confusion_*.xlsx"):
            try:
                df = pd.read_excel(path, sheet_name="Confusion", index_col=0)
            except (ValueError, FileNotFoundError):
                continue
            raw.setdefault((target, model), []).append(df)

    out: dict[tuple[str, str], pd.DataFrame] = {}
    for key, mats in raw.items():
        # Reindex to a common label set in case of missing rows/cols across runs.
        labels = sorted({lbl for m in mats for lbl in m.index} | {lbl for m in mats for lbl in m.columns})
        aligned = [m.reindex(index=labels, columns=labels, fill_value=0) for m in mats]
        out[key] = sum(aligned) / len(aligned)
    return out


def load_similarity_categorizations(run_dirs: Iterable[Path]) -> dict[str, dict[str, dict[str, list[int]]]]:
    """Return ``{metric: {baseline: {model: [hs, ms, ss, div, abs]}}}`` summed across runs.

    Reads the ``Categorization`` sheet from every ``bert_comparison_*.xlsx``
    and ``rouge_comparison_*.xlsx`` and counts how many vulnerabilities fall
    into each similarity bucket. ``Non-existent`` is excluded (LLM
    invention — not in the baseline, so it doesn't belong on a similarity
    distribution scale). Baseline = the target directory name; runs of the
    same (target, model) are summed before percentage conversion upstream.
    """
    categories = ["Highly Similar", "Moderately Similar", "Slightly Similar", "Divergent", "Absent"]
    metric_files = {"bert": "bert_comparison", "rouge": "rouge_comparison"}

    out: dict[str, dict[str, dict[str, list[int]]]] = {}
    for run_dir in run_dirs:
        model = run_dir.parent.name
        baseline = run_dir.parent.parent.name
        for metric, prefix in metric_files.items():
            for path in run_dir.glob(f"{prefix}_*.xlsx"):
                try:
                    df = pd.read_excel(path, sheet_name="Categorization")
                except (ValueError, FileNotFoundError):
                    continue
                if "Category" not in df.columns:
                    continue
                counts = [int((df["Category"] == c).sum()) for c in categories]
                bucket = (out.setdefault(metric, {})
                            .setdefault(baseline, {})
                            .setdefault(model, [0] * len(categories)))
                for i, v in enumerate(counts):
                    bucket[i] += v
    return out


def load_coverage_summaries(run_dirs: Iterable[Path]) -> pd.DataFrame:
    """Return one row per (target, model, run) with coverage Summary fields.

    Used by the hallucination × omission scatter — values are already in
    the long table but reading per-run keeps the run identity for jitter.
    """
    rows: list[dict] = []
    for run_dir in run_dirs:
        target = run_dir.parent.parent.name
        model = run_dir.parent.name
        run = run_dir.name
        for path in run_dir.glob("coverage_*.xlsx"):
            try:
                df = pd.read_excel(path, sheet_name="Summary")
            except (ValueError, FileNotFoundError):
                continue
            if df.empty:
                continue
            r = df.iloc[0].to_dict()
            r.update({"target": target, "model": model, "run": run})
            rows.append(r)
            break
    return pd.DataFrame(rows)
