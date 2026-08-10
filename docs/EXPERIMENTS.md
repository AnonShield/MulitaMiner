# Experiments

This document describes the experiments conducted to validate TMM, as presented in the paper.

## Ground Truth Curated Baselines

The model selection for dataset extraction was based on empirical evaluation of five LLMs against three manually constructed baselines (ground truth):

| Baseline           | Critical | High   | Medium | Low   | Log    | **Total** |
| ------------------ | -------- | ------ | ------ | ----- | ------ | --------- |
| Artifactory 5.11.0 | 9        | 62     | 31     | 3     | 20     | **125**   |
| Juice Shop         | 0        | 2      | 3      | 0     | 29     | **34**    |
| bBWA               | 0        | 19     | 36     | 3     | 0      | **58**    |
| **Total**          | **9**    | **83** | **70** | **6** | **49** | **217**   |

These baselines were constructed by two security specialists and serve as ground truth for evaluating extraction quality.

## Evaluation Metrics to Curated Baselines

Extraction quality is measured using two complementary dimensions:

1. **BERTScore**: Global semantic similarity
2. **ROUGE-L**: Structural textual proximity

Results are categorized into similarity bands:

- **Highly Similar**: ≥ 0.7
- **Moderately Similar**: 0.6 - 0.7
- **Slight Similarity**: 0.4 - 0.6
- **Divergent**: < 0.4
- **Absent**: Vulnerability in baseline but not extracted
- **Excedent**: Vulnerability extracted but not in baseline

## LLM Comparison Results

### Per-Version Extraction Datasets (129 Docker Reports) for Native Baseline

The 129 OpenVAS PDF reports in [`dockers/`](../dockers/) (see [docs/INVENTORY.md](INVENTORY.md) for the full container list) were extracted by all 5 LLMs across 3 pipeline iterations (V1, V2, V3), each consolidated into a per-LLM CSV dataset under `artifacts/<version>/openvas_129_dockers/` and evaluated against the same ground-truth baseline ([`baselines/native/vulnnet_scans_openvas.csv`](../baselines/native/vulnnet_scans_openvas.csv)):

| LLM      | V1 rows | V2 rows | V3 rows |
| -------- | ------- | ------- | ------- |
| DeepSeek | 13,274  | 6,706   | 6,511   |
| GPT-4    | 8,396   | 6,805   | 6,168   |
| GPT-5    | 3,528   | 5,699   | 6,432   |
| LLaMa 3  | 7,463   | 6,625   | 6,449   |
| LLaMa 4  | 10,094  | 6,585   | 6,401   |

Row counts are raw extracted entries per dataset (pre host+name matching against the baseline). The drop and convergence from V1 to V3 reflects successive fixes to the extraction/consolidation pipeline, reducing duplicate/split entries across LLMs.

Metrics for each version (and a combined V1+V2+V3 comparison) are computed with [`tools/TMM_metrics_run.py`](../tools/TMM_metrics_run.py) — see the "Consolidated Multi-LLM Metrics Report" claim in the main [README](../README.md#experiments) for the exact commands, producing `artifacts/<version>/TMM_metrics_<version>.xlsx` and `artifacts/TMM_metrics_all_versions.xlsx`.

### Token Consumption and Cost (TMMv3 Batch)

Tokens and cost per model in the TMMv3 batch (129 PDFs per model):

| Model     | Version                             | Input tokens   | Output tokens  | Cost         | Cost/PDF   |
| --------- | ------------------------------------ | -------------: | -------------: | -----------: | ---------: |
| DeepSeek  | `deepseek-coder`                     | 22,867,811     | 4,863,716      | US$4.56      | US$0.035   |
| GPT-4     | `gpt-4o-mini-2024-07-18`             | 13,355,126     | 5,229,819      | US$5.14      | US$0.040   |
| GPT-5     | `gpt-5-mini-2025-08-07`              | 22,092,445     | 4,505,512      | US$44.13     | US$0.342   |
| LLaMA 3   | `llama-3.3-70b-versatile`            | 16,528,717     | 7,668,978      | US$15.81     | US$0.123   |
| LLaMA 4   | `llama-4-scout-17b-16e-instruct`     | 14,243,919     | 7,659,172      | US$4.17      | US$0.032   |
| **Total** | --                                    | **89,088,018** | **29,927,197** | **US$73.82** | --         |

## Running Experiments

### Metrics Report per Version (TMM_metrics_run.py)

Compute BERTScore/ROUGE-L/deterministic-field metrics for all 5 LLMs of a given version against the native baseline, and generate the consolidated XLSX report:

```bash
# V1
python tools/TMM_metrics_run.py --baseline baselines/native/vulnnet_scans_openvas.csv --versions TMMv1:artifacts/v1/openvas_129_dockers/deepseek_v1.csv:deepseek TMMv1:artifacts/v1/openvas_129_dockers/gpt4_v1.csv:gpt4 TMMv1:artifacts/v1/openvas_129_dockers/gpt5_v1.csv:gpt5 TMMv1:artifacts/v1/openvas_129_dockers/llama3_v1.csv:llama3 TMMv1:artifacts/v1/openvas_129_dockers/llama4_v1.csv:llama4 --xlsx artifacts/v1/TMM_metrics_v1.xlsx

# V2
python tools/TMM_metrics_run.py --baseline baselines/native/vulnnet_scans_openvas.csv --versions TMMv2:artifacts/v2/openvas_129_dockers/deepseek_v2.csv:deepseek TMMv2:artifacts/v2/openvas_129_dockers/gpt4_v2.csv:gpt4 TMMv2:artifacts/v2/openvas_129_dockers/gpt5_v2.csv:gpt5 TMMv2:artifacts/v2/openvas_129_dockers/llama3_v2.csv:llama3 TMMv2:artifacts/v2/openvas_129_dockers/llama4_v2.csv:llama4 --xlsx artifacts/v2/TMM_metrics_v2.xlsx

# V3
python tools/TMM_metrics_run.py --baseline baselines/native/vulnnet_scans_openvas.csv --versions TMMv3:artifacts/v3/openvas_129_dockers/deepseek_v3.csv:deepseek TMMv3:artifacts/v3/openvas_129_dockers/gpt4_v3.csv:gpt4 TMMv3:artifacts/v3/openvas_129_dockers/gpt5_v3.csv:gpt5 TMMv3:artifacts/v3/openvas_129_dockers/llama3_v3.csv:llama3 TMMv3:artifacts/v3/openvas_129_dockers/llama4_v3.csv:llama4 --xlsx artifacts/v3/TMM_metrics_v3.xlsx

# All versions combined (15 LLM x version entries in one report)
python tools/TMM_metrics_run.py --baseline baselines/native/vulnnet_scans_openvas.csv --versions TMMv1:artifacts/v1/openvas_129_dockers/deepseek_v1.csv:deepseek TMMv1:artifacts/v1/openvas_129_dockers/gpt4_v1.csv:gpt4 TMMv1:artifacts/v1/openvas_129_dockers/gpt5_v1.csv:gpt5 TMMv1:artifacts/v1/openvas_129_dockers/llama3_v1.csv:llama3 TMMv1:artifacts/v1/openvas_129_dockers/llama4_v1.csv:llama4 TMMv2:artifacts/v2/openvas_129_dockers/deepseek_v2.csv:deepseek TMMv2:artifacts/v2/openvas_129_dockers/gpt4_v2.csv:gpt4 TMMv2:artifacts/v2/openvas_129_dockers/gpt5_v2.csv:gpt5 TMMv2:artifacts/v2/openvas_129_dockers/llama3_v2.csv:llama3 TMMv2:artifacts/v2/openvas_129_dockers/llama4_v2.csv:llama4 TMMv3:artifacts/v3/openvas_129_dockers/deepseek_v3.csv:deepseek TMMv3:artifacts/v3/openvas_129_dockers/gpt4_v3.csv:gpt4 TMMv3:artifacts/v3/openvas_129_dockers/gpt5_v3.csv:gpt5 TMMv3:artifacts/v3/openvas_129_dockers/llama3_v3.csv:llama3 TMMv3:artifacts/v3/openvas_129_dockers/llama4_v3.csv:llama4 --xlsx artifacts/TMM_metrics_all_versions.xlsx
```

Each run produces sheets for Summary, Overview (global + per-version), All LLMs, one sheet per LLM, and Omission & Hallucination analysis. Close the target `.xlsx` in Excel before re-running — the script cannot overwrite a file that's open (locked on Windows).

### Full Experiment Suite

```bash
# Windows
python tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm deepseek --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm gpt4 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm gpt5 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm llama4 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm llama3 --convert csv [--allow-duplicates] [--output-dir <output_directory>]

# Linux/macOS
python3 tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm deepseek --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python3 tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm gpt4 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python3 tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm gpt5 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python3 tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm llama4 --convert csv [--allow-duplicates] [--output-dir <output_directory>]
python3 tools/batch_pdf_extractor.py --input-dir dockers --scanner openvas --llm llama3 --convert csv [--allow-duplicates] [--output-dir <output_directory>]

```