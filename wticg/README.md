# WTICG — On-Premise vs. Cloud LLMs for Vulnerability Extraction

Self-contained folder with everything for the WTICG/SBC paper: experiment data,
analysis scripts, results, the interactive report, and the LaTeX snippets.

## Layout

```
wticg/
  3060/  5080/  cloud/        experiment data per hardware source.
                              Each has aggregated_metrics.xlsx (+ Long sheet),
                              run_checkpoints_merged_<src>.json, per-target/model/run
                              folders, and securebert_metrics_<src>.xlsx.
  build_report.py             generates the interactive HTML report.
  comparison_v1_v2_v3.html    report engine (CSS+JS), reused verbatim.
  relatorio_local.html        generated report (open in a browser).
  analysis/
    bootstrap_bertscore_ci.py BERTScore 95% CIs (per-vulnerability bootstrap) + diff test.
    securebert_compare.py     SecureBERT vs distilBERT backbone sensitivity (raw vs raw).
    make_paper_charts.py       trade-off PNG + omission heatmap PNG for the paper.
  results/
    bertscore_ci.csv           per-model BERTScore point estimate + 95% CI.
    bertscore_diff_test.txt     cloud - Ministral difference test.
    securebert_summary.txt      field-level agreement stats.
  paper/
    snippets.tex               ready-to-paste LaTeX blocks (corrections).
    tradeoff.png               Fig: per-model omission x hallucination (tornado).
    heatmap.png                Fig: per-field omission rate (3 empty fields dropped).
```

## Reproduce (run from the repo root)

```
python wticg/build_report.py                 # -> wticg/relatorio_local.html
python wticg/analysis/bootstrap_bertscore_ci.py   # -> wticg/results/bertscore_ci.csv
python wticg/analysis/make_paper_charts.py        # -> wticg/paper/*.png
python wticg/analysis/securebert_compare.py       # GPU/CPU, ~min; regenerates securebert xlsx
```

## Key numbers (paper)

- BERTScore: best local Ministral 3 = 93.0 [92.1, 93.9]; cloud = 94.2 [93.8, 94.5].
  The cloud edge is small but **statistically significant**: cloud - Ministral =
  1.15 pp, 95% CI [0.2, 2.1], excludes 0. Do **not** claim "indistinguishable".
  The local-cloud gap (~1.2 pp) is dwarfed by the spread across local models (~14 pp).
- SecureBERT vs distilBERT backbone: per-model <= 0.21 pp, no ranking change;
  field-level max 3.9 pp, 336/360 cells within 2 pp.
- Omission heatmap drops 3 fields that are empty for all models
  (instances, plugin, plugin_details).

## Notes

- Data folders are not git-tracked. Paths in `build_report.py`,
  `securebert_compare.py`, and the analysis scripts are anchored to this folder
  (`wticg/`), so the report reads/writes here, not at the repo root.
- `securebert_metrics_<src>.xlsx` uses the suffixed naming; `build_report.py`
  reads exactly that.
