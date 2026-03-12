# Usage Guide

Complete guide for using MulitaMiner with all available options.

## CLI Interface

**Basic syntax:**

```bash
python main.py <pdf_path> [options]
```

## Main Parameters

### Required Input

- `pdf_path`: **Path to the PDF file** of the vulnerability report

### Processing Options

| Parameter   | Description      | Default   | Examples                             |
| ----------- | ---------------- | --------- | ------------------------------------ |
| `--scanner` | Scanner strategy | `default` | `tenable`, `openvas`, `cais_tenable` |
| `--llm`     | Language Model   | `gpt4`    | `deepseek`, `llama3`, `gpt5`         |

### Export Options

| Parameter         | Description       | Default | Examples               |
| ----------------- | ----------------- | ------- | ---------------------- |
| `--convert`       | Conversion format | `none`  | `csv`, `xlsx`, `all`   |
| `--output-file`   | Output file name  | auto    | `vulnerabilities.json` |
| `--output-dir`    | Output folder     | current | `./results`            |
| `--csv-delimiter` | CSV separator     | `,`     | `;`                    |

### Evaluation Options

| Parameter             | Description                 | Default                    |
| --------------------- | --------------------------- | -------------------------- |
| `--evaluate`          | Enable metrics evaluation   | `false`                    |
| `--baseline-file`     | Ground truth file (.xlsx)   | required with `--evaluate` |
| `--evaluation-method` | Method: `bert` or `rouge`   | `bert`                     |
| `--allow-duplicates`  | Allow legitimate duplicates | `false`                    |

## Usage Examples

### Basic Usage

```bash
# Standard processing with GPT-4
python main.py report.pdf

# Specific scanner
python main.py report_tenable.pdf --scanner tenable

# Specific model
python main.py report.pdf --llm deepseek
```

### Export Formats

```bash
# CSV with custom configuration
python main.py report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en.csv"

# Full export to Excel
python main.py large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results

# All formats simultaneously
python main.py report.pdf --convert all --output-dir ./exports
```

### Specialized Scenarios

```bash
# Tenable WAS optimized for maximum extraction
python main.py tenable_report.pdf --scanner tenable --llm gpt4 --convert all

# OpenVAS with Groq model
python main.py openvas_scan.pdf --scanner openvas --llm llama3 --convert csv

# CAIS Tenable for enterprise integration
python main.py cais_tenable.pdf --scanner cais_tenable --llm gpt5 --convert xlsx
```

### Extraction with Metrics Evaluation

```bash
# Extract vulnerabilities and evaluate extraction quality using the 'bert' method
python main.py report_tenable.pdf --scanner tenable --convert all --evaluate --baseline-file metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx --evaluation-method bert

# Evaluation with legitimate duplicates allowed (recommended for OpenVAS)
python main.py report_openvas.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --allow-duplicates
```

## Batch Extraction

To process all PDFs in a directory in batch:

```bash
python tools/batch_pdf_extractor.py <pdfs_directory> --convert <format> --llm <model> --scanner <scanner> [--allow-duplicates] [--output-dir <dir>]
```

Example:

```bash
python tools/batch_pdf_extractor.py pdfs --scanner openvas --llm deepseek --allow-duplicates --output-dir jsons
```

## Validation and Debugging

```bash
# Chunk validation before processing
python tools/chunk_validator.py report.pdf

# Detailed chunk analysis by LLM
python tools/chunk_validator.py report.pdf --llm gpt4 --scanner tenable
```

## Metrics Analysis

### Isolated Analyses

#### BERT Analysis

```bash
python metrics/bert/compare_extractions_bert.py --baseline-file <relative_path_to_baseline_file> --extraction-file <relative_path_to_extraction_file> --model <llm> --allow-duplicates
```

#### ROUGE Analysis

```bash
python metrics/rouge/compare_extractions_rouge.py --baseline-file <relative_path_to_baseline_file> --extraction-file <relative_path_to_extraction_file> --model <llm> --allow-duplicates
```

### Chart Generation

> **Important:** Pass the baseline (ground truth) file in the --baseline parameter. The plotting script uses the baseline as a reference to automatically compare the results of all models/extractions available.

```bash
# Simple chart for one model
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek

# Comparison of three models
python -m metrics.plot.cli --metric bert --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek,gpt4,llama3

# Chart focused on specific metrics
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek --baseline-sheet Vulnerabilities
```

## Processing Flow

1. **Input**: PDF specified in `pdf_path`
2. **Chunk calculation**: Optimized system calculates ideal sizes per LLM
3. **Processing**: Using scanner and LLM configured with optimized chunks
4. **Extraction**: Vulnerabilities extracted with smart retry
5. **Consolidation**: Removal of duplicates and merge of instances (TenableWAS)
6. **Primary output**: JSON as per scanner's `output_file`
7. **Conversions**: Additional formats (CSV, XLSX,...) as per `--convert`
8. **Visual layout**: Preserved visual layout in a .txt file (same directory as PDF)

## Generated Files

- **Main JSON**: `vulnerabilities_<scanner>.json`
- **Visual layout**: `visual_layout_extracted_<file_name>.txt`
- **Logs**: `*_removed_log.txt`, `*_duplicates_removed_log.txt`, `*_merge_log.txt`

## Output Format (JSON Structure)

```json
[
  {
    "Name": "SQL Injection",
    "description": ["Detailed description of the vulnerability"],
    "detection_result": ["Vulnerability detection result (OpenVAS only)"],
    "detection_method": ["Vulnerability detection method (OpenVAS only)"],
    "product_detection_result": ["Product detection result (OpenVAS only)"],
    "impact": ["Impact description (OpenVAS only)"],
    "solution": ["Recommended solutions"],
    "insight": ["Vulnerability insight (OpenVAS only)"],
    "log_method": ["Log method (OpenVAS only)"],
    "cvss": ["CVSSV4 BASE SCORE 7.5", "CVSSv3 BASE SCORE 6.9"],
    "port": 80,
    "protocol": "tcp",
    "severity": "HIGH",
    "references": ["CVE-2024-0001", "https://example.com/reference"],
    "plugin": 12345,
    "plugin_details": {
      "publication_date": "2020-01-15T00:00:00+00:00",
      "modification_date": "2025-01-07T00:00:00+00:00",
      "family": "Web Servers",
      "severity": "High",
      "plugin_id": 12345
    },
    "instances": [
      {
        "instance": "https://example.com/vuln1",
        "input_type": "link",
        "input_name": "id",
        "payload": "' OR 1=1 --",
        "proof": "SQL error triggered",
        "output": "Database error message",
        "request_method": "GET",
        "http_status_code": 200,
        "http_protocol": "HTTP/2",
        "response_content_type": "application/json"
      }
    ],
    "source": "TENABLEWAS"
  }
]
```

## Field Mapping by Tool

| Field                      | OpenVAS | Tenable WAS | Description              |
| -------------------------- | ------- | ----------- | ------------------------ |
| `Name`                     | ✅      | ✅          | Vulnerability name       |
| `description`              | ✅      | ✅          | Detailed description     |
| `detection_result`         | ✅      | ❌          | Detection result         |
| `detection_method`         | ✅      | ❌          | Detection method         |
| `impact`                   | ✅      | ❌          | Impact                   |
| `solution`                 | ✅      | ✅          | Recommended solution     |
| `insight`                  | ✅      | ❌          | Vulnerability insight    |
| `product_detection_result` | ✅      | ❌          | Product detection result |
| `log_method`               | ✅      | ❌          | Log method               |
| `cvss`                     | ✅      | ✅          | CVSS scores              |
| `port`                     | ✅      | ✅          | Vulnerability port       |
| `protocol`                 | ✅      | ✅          | Protocol                 |
| `severity`                 | ✅      | ✅          | Severity                 |
| `references`               | ✅      | ✅          | References and links     |
| `plugin`                   | ❌      | ✅          | Plugin                   |
| `plugin_details`           | ✅      | ✅          | Plugin details           |
| `instances`                | ✅      | ✅          | Instances                |
| `source`                   | ✅      | ✅          | Report source            |

## Advanced Scripts and Utilities

### `tools/run_experiments.py` — Massive Execution and Automated Evaluation

Automates large-scale experiments with checkpoint support, automatic evaluation (BERT/ROUGE), and result organization.

```bash
python tools/run_experiments.py [--checkpoint-file run_checkpoints_YYYY-MM-DDTHH-MM-SS.json]
```

### `tools/process_results.py` — Chart and Statistics Generation

Generates charts (stacked bar, heatmaps) and statistics from experiment results.

```bash
python tools/process_results.py
```

### `tools/dataset_generator.py` — Dataset Consolidation

Generates consolidated datasets (CSV, XLSX, JSON, JSONL) from multiple JSON files.

```bash
python tools/dataset_generator.py --input-folder jsons --output-folder data --format xlsx

# Generate all formats at once
python tools/dataset_generator.py --input-folder jsons --output-folder data --format all
```

### `tools/sum_tokens_cost_all_llms.py` — Token Sum and Cost Estimation

Sums tokens processed per LLM and estimates costs.

```bash
python tools/sum_tokens_cost_all_llms.py --tokens-dir results_tokens
```

### chunk_validator.py

Token distribution analysis and chunk validation tool.

```bash
python chunk_validator.py document.pdf --LLM gpt4 --scanner tenable
```
