"""Print the per-model extraction quality table (Table 1 layout of the paper).

Usage: python claims/summarize_models.py <results_root> [<results_root> ...]
Walks <root>/<target>/<llm>/run<N>/ and reads the metric outputs of each run.
"""
import glob
import json
import sys
from pathlib import Path

import pandas as pd

try:
    sys.stdout.reconfigure(encoding="utf-8")
    ARROW_DOWN = "↓"
except Exception:
    ARROW_DOWN = "v"

# config name -> (display name, is_cloud)
MODELS = {
    "ministral3": ("Ministral 3 8B", False),
    "llama31_local": ("Llama 3.1 8B", False),
    "gemma4": ("Gemma 4 E4B", False),
    "qwen3_local": ("Qwen3 8B", False),
    "phi4": ("Phi-4 14B", False),
    "gpt_oss": ("gpt-oss 21B", False),
    "deepseek_local": ("DeepSeek-Coder-V2 16B", False),
    "foundation_sec": ("Foundation-Sec 8B", False),
    "primus": ("Primus-Merged 8B", False),
    "deepseek": ("deepseek-v4-flash (cloud)", True),
}


def _one(pattern, run_dir):
    hits = sorted(run_dir.glob(pattern))
    return hits[0] if hits else None


def read_run(run_dir: Path) -> dict:
    """Collect the Table 1 metrics of a single run directory."""
    row = {}

    bert = _one("bert_comparison_*.xlsx", run_dir)
    if bert:
        d = pd.read_excel(bert, sheet_name="Summary")
        row["BERTScore"] = d["Avg_BERTScore_F1"].mean() * 100

    ent = _one("entity_metrics_*.xlsx", run_dir)
    if ent:
        d = pd.read_excel(ent, sheet_name="Summary")
        row["Ent.F1"] = d["F1_Score"].mean() * 100

    cov = _one("coverage_*.xlsx", run_dir)
    if cov:
        s = pd.read_excel(cov, sheet_name="Summary").iloc[0]
        row["Exact"] = float(s["exact_record_match"]) * 100
        row["Omiss"] = float(s["vuln_omission_rate"]) * 100
        row["Halluc"] = float(s["vuln_hallucination_rate"]) * 100

    sch = _one("schema_report_*.json", run_dir)
    if sch:
        d = json.loads(sch.read_text(encoding="utf-8"))
        row["Schema"] = float(d.get("schema_conformance_rate", 0)) * 100

    sev = _one("severity_confusion_*.xlsx", run_dir)
    if sev:
        s = pd.read_excel(sev, sheet_name="Summary").iloc[0]
        row["Sev.mF1"] = float(s["macro_F1"]) * 100
        row["Sev.cov"] = float(s["coverage_aware_macro_F1"]) * 100

    return row


COLUMNS = ["BERTScore", "Ent.F1", "Exact", "Omiss", "Halluc", "Schema", "Sev.mF1", "Sev.cov"]


def main() -> int:
    roots = [Path(a) for a in sys.argv[1:]] or [Path("results_runs")]

    found = {}   # llm -> {target -> row}
    targets = []
    for root in roots:
        if not root.is_dir():
            print(f"[WARN] root not found: {root}")
            continue
        for cov in sorted(root.glob("*/*/run*/coverage_*.xlsx")):
            run_dir = cov.parent
            llm = run_dir.parent.name
            target = run_dir.parent.parent.name
            if target not in targets:
                targets.append(target)
            found.setdefault(llm, {})[target] = read_run(run_dir)

    if not found:
        print("No metric outputs found. Run the extraction and the metric pass first.")
        return 1

    # Locals first, cloud reference last, mirroring the paper's table
    order = [m for m in MODELS if m in found and not MODELS[m][1]]
    order += [m for m in MODELS if m in found and MODELS[m][1]]
    order += [m for m in found if m not in MODELS]

    width = max(len(MODELS.get(m, (m,))[0]) for m in order) + 2
    header = f"{'Model':<{width}}" + "".join(
        f"{c + (' ' + ARROW_DOWN if c in ('Omiss', 'Halluc') else ''):>11}" for c in COLUMNS
    )

    print()
    print("Per-model extraction quality (single run, %)")
    print(f"Baseline: {', '.join(targets)}")
    print()
    print(header)
    print("-" * len(header))

    for i, llm in enumerate(order):
        label = MODELS.get(llm, (llm, False))[0]
        is_cloud = MODELS.get(llm, (llm, False))[1]
        if is_cloud and i > 0:
            print("-" * len(header))
        # average across targets when more than one baseline was run
        rows = list(found[llm].values())
        cells = ""
        for c in COLUMNS:
            vals = [r[c] for r in rows if c in r]
            cells += f"{(sum(vals) / len(vals)):>11.1f}" if vals else f"{'n/a':>11}"
        print(f"{label:<{width}}{cells}")

    print()
    print("BERTScore covers the free-text fields; Ent.F1 the deterministic ones")
    print("(cvss, plugin, port, protocol, severity). Compare with Table 1 of the paper,")
    print("keeping in mind this is a single run on one baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
