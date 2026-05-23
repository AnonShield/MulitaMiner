"""Most-missed vulnerabilities — names that show up as ``Absent`` most often.

Reads the ``Categorization`` sheet from every ``bert_comparison_*.xlsx``
(falling back to ``rouge_comparison_*.xlsx`` when the BERT one is missing)
and counts, per baseline, how often each ``Vulnerability_Name`` was tagged
``Absent`` across all (run, model) attempts.

**Why one scorer per (run, model) and not both?** BERT and ROUGE share
the same alignment step — a vulnerability is ``Absent`` because no
extraction mapped to it, not because either scorer said so. Counting
both files as separate observations would double-count every miss and
make the denominator twice the number of runs you actually executed.
"""
from __future__ import annotations

import pandas as pd

from metrics.plot.data_source import Dataset


def top_absent_per_baseline(dataset: Dataset, top_n: int = 20) -> dict:
    """Return ``{baselines: [...], rows: {baseline: [{name, count, pct, models}]}}``.

    ``count`` = number of (run, model) attempts where the name was Absent.
    ``pct``   = count / total (run, model) observations of that baseline.
    ``models`` = distinct models that missed it.
    """
    if not dataset.run_dirs:
        return {"empty": True, "baselines": [], "rows": {}}

    observations: dict[str, int] = {}
    absences: dict[str, dict[str, dict]] = {}

    for run_dir in dataset.run_dirs:
        baseline = run_dir.parent.parent.name
        model = run_dir.parent.name
        # Prefer BERT; fall back to ROUGE if absent. One file per (run, model).
        candidates = sorted(run_dir.glob("bert_comparison_*.xlsx")) \
                     or sorted(run_dir.glob("rouge_comparison_*.xlsx"))
        if not candidates:
            continue
        try:
            df = pd.read_excel(candidates[0], sheet_name="Categorization")
        except (ValueError, FileNotFoundError):
            continue
        if "Category" not in df.columns or "Vulnerability_Name" not in df.columns:
            continue

        observations[baseline] = observations.get(baseline, 0) + 1
        missed = df[df["Category"] == "Absent"]["Vulnerability_Name"].dropna()
        bucket = absences.setdefault(baseline, {})
        for name in missed.astype(str):
            entry = bucket.setdefault(name, {"count": 0, "models": set()})
            entry["count"] += 1
            entry["models"].add(model)

    if not absences:
        return {"empty": True, "baselines": [], "rows": {}}

    baselines = sorted(absences.keys())
    rows: dict[str, list[dict]] = {}
    for b in baselines:
        denom = max(1, observations.get(b, 1))
        ranked = sorted(absences[b].items(), key=lambda kv: -kv[1]["count"])[:top_n]
        rows[b] = [
            {
                "name":  name,
                "count": int(stats["count"]),
                "pct":   round(stats["count"] / denom * 100, 1),
                "models": sorted(stats["models"]),
                "n_models": len(stats["models"]),
            }
            for name, stats in ranked
        ]
    return {"empty": False, "baselines": baselines, "rows": rows, "top_n": top_n}
