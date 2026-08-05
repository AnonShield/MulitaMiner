"""Print a per-version summary table from coverage/severity metric files.

Usage: python claims/summarize_versions.py <results_root> [<results_root> ...]
Each root follows the <root>/<target>/<llm>/run<N>/ layout used by tools/run_metrics.py.
"""
import sys
from pathlib import Path

import pandas as pd

VERSION_LABELS = {"results_runs_v1": "V1", "results_runs_v2": "V2", "results_runs_v3": "V3"}


def summarize_root(root: Path) -> list[dict]:
    rows = []
    for cov in sorted(root.glob("*/*/run*/coverage_*.xlsx")):
        run_dir = cov.parent
        target, llm = run_dir.parent.parent.name, run_dir.parent.name
        s = pd.read_excel(cov, sheet_name="Summary").iloc[0]
        row = {
            "version": VERSION_LABELS.get(root.name, root.name),
            "target": target,
            "llm": llm,
            "run": run_dir.name,
            "Exact Record Match": float(s["exact_record_match"]),
            "Field omission": float(s["omission_rate"]),
            "Field hallucination": float(s["hallucination_rate"]),
            "Vuln omission": float(s["vuln_omission_rate"]),
            "Matched pairs": int(s["n_matched_pairs"]),
        }
        sev = list(run_dir.glob("severity_confusion_*.xlsx"))
        if sev:
            m = pd.read_excel(sev[0], sheet_name="Summary").iloc[0]
            row["Severity macro-F1"] = float(m["macro_F1"])
        rows.append(row)
    return rows


def fmt(metric: str, value: float) -> str:
    if "omission" in metric.lower() or "hallucination" in metric.lower():
        return f"{value * 100:.1f}%"
    if metric == "Matched pairs":
        return f"{value:.0f}"
    return f"{value:.2f}"


def main() -> int:
    roots = [Path(a) for a in sys.argv[1:]]
    if not roots:
        print(__doc__)
        return 1
    rows = []
    for root in roots:
        if not root.is_dir():
            print(f"[WARN] root not found: {root}")
            continue
        found = summarize_root(root)
        if not found:
            print(f"[WARN] no coverage_*.xlsx under {root} (run tools/run_metrics.py first)")
        rows.extend(found)
    if not rows:
        return 1

    df = pd.DataFrame(rows)
    metrics = [c for c in df.columns if c not in ("version", "target", "llm", "run")]
    versions = list(dict.fromkeys(df["version"]))

    for (target, llm), group in df.groupby(["target", "llm"], sort=False):
        print(f"\nTarget: {target} | LLM: {llm}")
        width = max(len(m) for m in metrics) + 2
        header = "".join(f"{v:>10}" for v in group["version"])
        print(f"{'Metric':<{width}}{header}")
        print("-" * (width + 10 * len(group)))
        for m in metrics:
            vals = "".join(f"{fmt(m, x):>10}" for x in group[m])
            print(f"{m:<{width}}{vals}")

    if len(versions) > 1:
        print("\nExpected trend (paper, Table 3): Exact Record Match rises and")
        print("omission falls from V1 to V3. Single-run values vary (stochastic")
        print("LLM decoding); the ordering across versions is what validates the claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
