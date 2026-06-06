"""BERTScore 95% confidence intervals via per-vulnerability bootstrap (WTICG paper).

Reproduces the BERTScore CIs reported in Table 2 (tab:quality) and the
Ministral-3 vs. cloud difference test used in the Introduction / RQ1.

Method
------
The headline BERTScore in the paper is the mean of the per-field rescaled
F1 (``Avg_BERTScore_F1``) over 12 free-text TEXT_FIELDS, averaged over the
three targets (each target weighted equally). The point estimate here
reproduces tab:quality exactly (verified against the aggregated Long sheet).

CIs come from resampling the *matched vulnerabilities* (status == "OK") with
replacement, stratified within each target (targets stay fixed, equal weight),
recomputing the field-wise statistic each replicate. The per-vulnerability
raw F1 scores are read from ``bert_comparison_vulnerabilities_*.xlsx``
(sheet ``Per_Vulnerability``), which the pipeline already produces per run.

Locals are greedy/deterministic, so run1 is used; the cloud reference is
non-deterministic, so its 5 runs are pooled.

The difference test (cloud - Ministral) bootstraps the paired per-target
difference; the hierarchical variant additionally resamples the 3 targets.

Run:  python wticg/analysis/bootstrap_bertscore_ci.py   (from repo root)
Out:  wticg/results/bertscore_ci.csv  and console summary.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

import numpy as np
import pandas as pd

# wticg/ root (this script is in wticg/analysis/). Data lives at wticg/{3060,5080,cloud}.
BASE = Path(__file__).resolve().parents[1]
ROOTS = ["3060", "5080", "cloud"]
N_BOOT = 10_000
SEED = 42

TEXT_FIELDS = [
    "description", "detection_method", "detection_result", "impact", "insight",
    "instances", "log_method", "plugin_details", "product_detection_result",
    "references", "solution", "source",
]
COLS = [f + "_bertscore_f1" for f in TEXT_FIELDS]

MODEL_ROOT = {
    "gemma4": "3060", "ministral3": "3060", "qwen3_local": "3060",
    "phi4": "5080", "foundation_sec": "5080", "primus": "5080",
    "llama31_local": "5080", "gpt_oss": "5080", "deepseek_local": "5080",
    "deepseek": "cloud",
}
# display order + tab:quality point estimates (for cross-checking)
ORDER = ["ministral3", "deepseek", "gpt_oss", "phi4", "llama31_local",
         "primus", "qwen3_local", "gemma4", "deepseek_local", "foundation_sec"]
LABEL = {
    "ministral3": "Ministral 3", "deepseek": "deepseek-v4-flash (cloud)",
    "gpt_oss": "gpt-oss", "phi4": "Phi-4", "llama31_local": "Llama 3.1",
    "primus": "Primus-Merged", "qwen3_local": "Qwen3", "gemma4": "Gemma 4 E4B",
    "deepseek_local": "DeepSeek-Coder-V2", "foundation_sec": "Foundation-Sec",
}
TABLE = {"gemma4": 83.5, "ministral3": 93.0, "qwen3_local": 85.0,
         "llama31_local": 85.5, "phi4": 91.0, "deepseek_local": 79.4,
         "gpt_oss": 91.1, "foundation_sec": 78.8, "primus": 85.2, "deepseek": 94.2}


def _matrix(path: str) -> np.ndarray | None:
    """Per-vulnerability x field matrix (%) for matched pairs only."""
    d = pd.read_excel(path, sheet_name="Per_Vulnerability")
    d = d[d["_status"].astype(str).str.upper() == "OK"]
    if d.empty:
        return None
    return d[COLS].to_numpy(dtype=float) * 100.0


def load(model: str) -> dict[str, np.ndarray]:
    """target -> stacked per-vulnerability matrix for one model."""
    root = MODEL_ROOT[model]
    out: dict[str, np.ndarray] = {}
    for tdir in glob.glob(str(BASE / root / "*")):
        if not os.path.isdir(tdir) or not os.path.basename(tdir).lower().startswith("openvas"):
            continue
        target = os.path.basename(tdir)
        mdir = os.path.join(tdir, model)
        if not os.path.isdir(mdir):
            continue
        runs = ["run*"] if root == "cloud" else ["run1"]
        mats = []
        for r in runs:
            for g in glob.glob(os.path.join(mdir, r, "bert_comparison_vulnerabilities_*.xlsx")):
                m = _matrix(g)
                if m is not None:
                    mats.append(m)
        if mats:
            out[target] = np.vstack(mats)
    return out


def stat(m: np.ndarray) -> float:
    """Field-wise: nanmean per field, then mean over fields (matches tab:quality)."""
    return float(np.nanmean(np.nanmean(m, axis=0)))


def model_ci(td: dict[str, np.ndarray], rng: np.random.Generator, B: int = N_BOOT):
    targets = list(td)
    base = float(np.mean([stat(td[t]) for t in targets]))
    reps = np.empty(B)
    for i in range(B):
        reps[i] = np.mean([stat(td[t][rng.integers(0, td[t].shape[0], td[t].shape[0])])
                           for t in targets])
    lo, hi = np.percentile(reps, [2.5, 97.5])
    return base, float(lo), float(hi)


def diff_test(mini: dict, cloud: dict, rng: np.random.Generator, hierarchical: bool, B: int = N_BOOT):
    """Bootstrap CI of (cloud - Ministral), paired per target."""
    T = sorted(set(mini) & set(cloud))
    point = float(np.mean([stat(cloud[t]) - stat(mini[t]) for t in T]))
    reps = np.empty(B)
    for i in range(B):
        ts = rng.choice(T, len(T), replace=True) if hierarchical else T
        reps[i] = np.mean([
            stat(cloud[t][rng.integers(0, cloud[t].shape[0], cloud[t].shape[0])])
            - stat(mini[t][rng.integers(0, mini[t].shape[0], mini[t].shape[0])])
            for t in ts])
    lo, hi = np.percentile(reps, [2.5, 97.5])
    return point, float(lo), float(hi)


def main():
    rng = np.random.default_rng(SEED)
    data = {m: load(m) for m in ORDER}

    rows = []
    print(f"{'model':24}{'table':>6}{'boot':>6}   95% CI")
    for m in ORDER:
        base, lo, hi = model_ci(data[m], rng)
        rows.append({"model": m, "label": LABEL[m], "table": TABLE[m],
                     "bootstrap_point": round(base, 2),
                     "ci_low": round(lo, 2), "ci_high": round(hi, 2)})
        print(f"{LABEL[m]:24}{TABLE[m]:6.1f}{base:6.1f}   [{lo:.1f}, {hi:.1f}]")

    p, lo, hi = diff_test(data["ministral3"], data["deepseek"], rng, hierarchical=False)
    ph, loh, hih = diff_test(data["ministral3"], data["deepseek"], rng, hierarchical=True)
    print(f"\ncloud - Ministral diff = {p:.2f} pp  per-vuln CI [{lo:.2f}, {hi:.2f}]"
          f"  (excludes 0: {not (lo <= 0 <= hi)})")
    print(f"                         {ph:.2f} pp  hierarchical CI [{loh:.2f}, {hih:.2f}]"
          f"  (excludes 0: {not (loh <= 0 <= hih)})")

    out_dir = BASE / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out_dir / "bertscore_ci.csv", index=False)
    with open(out_dir / "bertscore_diff_test.txt", "w", encoding="utf-8") as f:
        f.write(f"cloud - Ministral (BERTScore, pp)\n")
        f.write(f"per-vuln bootstrap : {p:.2f}  95% CI [{lo:.2f}, {hi:.2f}]  excludes 0: {not (lo <= 0 <= hi)}\n")
        f.write(f"hierarchical (+targets): {ph:.2f}  95% CI [{loh:.2f}, {hih:.2f}]  excludes 0: {not (loh <= 0 <= hih)}\n")
    print(f"\nwrote {out_dir / 'bertscore_ci.csv'}")


if __name__ == "__main__":
    main()
