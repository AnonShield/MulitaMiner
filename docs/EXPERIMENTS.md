# Experiments

This document describes the experiments conducted to validate MulitaMiner, as presented in the paper.

## Ground Truth Baselines

The model selection for dataset extraction was based on empirical evaluation of five LLMs against three manually constructed baselines (ground truth):

| Baseline           | Critical | High   | Medium | Low   | Log    | **Total** |
| ------------------ | -------- | ------ | ------ | ----- | ------ | --------- |
| Artifactory 5.11.0 | 9        | 62     | 31     | 3     | 20     | **125**   |
| Juice Shop         | 0        | 2      | 3      | 0     | 29     | **34**    |
| bBWA               | 0        | 19     | 36     | 3     | 0      | **58**    |
| **Total**          | **9**    | **83** | **70** | **6** | **49** | **217**   |

These baselines were constructed by two security specialists and serve as ground truth for evaluating extraction quality.

## Evaluation Metrics

Extraction quality is measured using two complementary dimensions:

1. **BERTScore**: Global semantic similarity
2. **ROUGE-L**: Structural textual proximity

Results are categorized into similarity bands:

- **Highly Similar**: ≥ 0.7
- **Moderately Similar**: 0.6 - 0.7
- **Low Similarity**: 0.4 - 0.6
- **Divergent**: < 0.4
- **Absent**: Vulnerability in baseline but not extracted
- **Excedent**: Vulnerability extracted but not in baseline

## LLM Comparison Results

### DeepSeek Performance

DeepSeek presented highly competitive results in both metrics:

- High and consistent BERTScore values across all evaluated scenarios
- Especially strong on Juice Shop and bBWA baselines
- Strong semantic preservation of vulnerability descriptions

### Token Consumption and Cost

| LLM       | Input Tokens    | Output Tokens  | Total Tokens    | Cost (US$) |
| --------- | --------------- | -------------- | --------------- | ---------- |
| DeepSeek  | 25,406,920      | 4,441,620      | 29,848,540      | **8.98**   |
| GPT-4     | 25,406,920      | 4,038,727      | 29,445,647      | 12.47      |
| GPT-5     | 23,835,099      | 3,891,631      | 27,726,730      | 13.74      |
| LLaMa 3   | 25,406,920      | 4,723,980      | 30,130,900      | 18.72      |
| LLaMa 4   | 25,406,920      | 5,114,794      | 30,521,714      | 8.15       |
| **Total** | **125,462,779** | **22,210,752** | **147,673,531** | **62.06**  |

**Conclusion**: DeepSeek delivered the best balance between extraction quality and cost.

## Dataset Statistics

The dataset comprises **6,700 vulnerabilities** extracted from **129 OpenVAS PDF reports**, processed by DeepSeek and consolidated in a structured format with scanner-independent schema.

### Severity Distribution

| Severity  | Count     | Percentage |
| --------- | --------- | ---------- |
| Critical  | 964       | 14.39%     |
| High      | 1,465     | 21.87%     |
| Medium    | 1,908     | 28.48%     |
| Low       | 494       | 7.37%      |
| Log       | 1,869     | 27.90%     |
| **Total** | **6,700** | **100%**   |

The concentration of **36.25%** of vulnerabilities in Critical and High categories reinforces the practical value for SecDevOps teams in remediation prioritization.

### Extraction Accuracy

Comparison against OpenVAS CSV baseline (6,343 vulnerabilities) using fuzzy matching (85% threshold):

| Metric                       | Value       |
| ---------------------------- | ----------- |
| Baseline total (OpenVAS CSV) | 6,343       |
| Extracted total              | 6,700       |
| **Recall**                   | **96.18%**  |
| **Precision**                | **91.06%**  |
| **F1-score**                 | **0.9355**  |
| False positives              | 599 (8.94%) |
| False negatives              | 242 (3.82%) |

## Running Experiments

### Full Experiment Suite

```bash
# Run experiments with specified configurations

# Windows
python tools/run_experiments.py --input-dir test\openvas --llms deepseek gpt4 --scanner openvas --evaluation-methods bert rouge --runs-per-model 5

# Linux/macOS
python3 tools/run_experiments.py --input-dir test/openvas --llms deepseek gpt4 --scanner openvas --evaluation-methods bert rouge --runs-per-model 5

# With allow-duplicates (OpenVAS recommended)
python tools/run_experiments.py --input-dir test\openvas --llms deepseek gpt4 --scanner openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates

# Resume from checkpoint if interrupted

# Windows
python tools/run_experiments.py --checkpoint-file run_checkpoints_2026-03-16T12-28-08.json

# Linux/macOS
python3 tools/run_experiments.py --checkpoint-file run_checkpoints_2026-03-16T12-28-08.json
```

**Key Features:**

- Runs extraction, export, and evaluation for all pairs (report, LLM, run)
- One scanner per invocation — run twice for different scanners
- Checkpoint support: resumes interrupted executions via `--checkpoint-file`
- Generates detailed logs, output files, metrics, and automatic summaries
- **Automatic reporting**: Generates comprehensive final report with timing and token cost analysis
- **Automatic chart generation**: Calls `process_results.py` automatically at the end
- Outputs organized in respective evaluation directories based on metrics

**Parameters:**

- `--input-dir`: Directory containing paired .xlsx (baseline) and .pdf (report) files
- `--llms`: Space-separated LLMs to test (e.g., `deepseek gpt4 llama3`)
- `--scanner`: Scanner to use (`openvas` or `tenable`)
- `--evaluation-methods`: Evaluation methods (default: `bert`, can add `rouge`)
- `--runs-per-model`: Number of runs per combination (default: 10)
- `--allow-duplicates`: Flag to allow duplicates (recommended for OpenVAS; omit for Tenable)
- `--checkpoint-file`: Checkpoint file to resume from

### Output Structure

Results are automatically organized by:

- `results_runs/` → `<baseline>/<llm>/run<N>/` (extraction and metrics outputs)
- `resultados_bert/` (when BERT evaluation enabled)
- `resultados_rouge/` (when ROUGE evaluation enabled)
- Final report with timing and token cost analysis
- Checkpoint files for resuming interrupted runs

### Automatic Chart Generation

Charts are automatically generated at the end of `run_experiments.py` execution. To generate charts manually:

```bash
# Windows
python tools/process_results.py

# Linux/macOS
python3 tools/process_results.py
```

Generates:

- Similarity category distribution charts (stacked bar)
- Metric heatmaps (BERT/ROUGE) per LLM and baseline
- Statistical summaries and visualizations

## Deduplication Strategies

### OpenVAS

- `--allow-duplicates` (**recommended**): uses custom strategy for maximum granularity
- Removes only exact duplicates (same Name, port, protocol)
- Legitimate vulnerabilities may repeat on different ports

### Tenable WAS

- Without `--allow-duplicates` (**recommended**): uses custom strategy for smart merge
- Groups instances/bases of the same type
- Consolidates arrays (URLs, description, etc.)

These strategies were designed to balance granularity and efficiency, avoiding vulnerability exceedances and respecting the structure of each scanner.
