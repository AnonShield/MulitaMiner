# Usage Guide

Complete guide for using MulitaMiner with all available options.

## CLI Interface

**Basic syntax:**

```bash
python main.py --input <pdf_path> [options]
```

## Main Parameters

### Required Input

- `--input`: **Path to the PDF file** of the vulnerability report

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

# Specific scanner and model
python main.py --input report_tenable.pdf --scanner tenable --llm deepseek
```

### Export Formats

```bash
# Syntax: CSV with custom configuration
python main.py --input <pdf_path> --convert csv --csv-delimiter <char> --csv-encoding <encoding> --output-file <filename>

# Example: CSV with semicolon separator
python main.py --input vulnerabilities_report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en"

# Syntax: Export to Excel
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert xlsx --output-dir <output_directory>

# Example: Tenable report to Excel
python main.py --input large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results

# Syntax: All formats
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert all

# Example: Generate all formats
python main.py --input openvas.pdf --scanner openvas --llm deepseek --convert all
```

### Specialized Scenarios

```bash
# Example: Tenable with GPT-4
python main.py --input tenable_report.pdf --scanner tenable --llm gpt4 --convert all

# Example: OpenVAS with GPT-4
python main.py --input openvas_report.pdf --scanner openvas --llm gpt4 --convert all --allow-duplicates

# Example: CAIS with GPT-4
python main.py --input cais_tenable.pdf --scanner cais_tenable --llm gpt4 --convert all
```

### Extraction with Metrics Evaluation

```bash
# Syntax: Extract and evaluate with BERT
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --evaluate --baseline <baseline_file> --evaluation-method bert [--allow-duplicates]

# Example: OpenVAS extraction with BERT evaluation (xlsx)
python main.py --input openvas_report.pdf --scanner openvas --llm deepseek --evaluate --baseline openvas_report.xlsx --evaluation-method bert --allow_duplicates

# Example: OpenVAS extraction with BERT evaluation (json)
python main.py --input openvas_report.pdf --scanner openvas --llm deepseek --evaluate --baseline openvas_report.json --evaluation-method bert --allow_duplicates

# Syntax: Extract and evaluate with ROUGE-L
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --evaluate --baseline <baseline_file> --evaluation-method bert [--allow-duplicates]

# Example: Tenable extraction with ROUGE-L evaluation (xlsx)
python main.py --input tenable_report.pdf --scanner tenable --llm deepseek --evaluate --baseline tenable_report.xlsx --evaluation-method bert --allow_duplicates

# Example: Tenable extraction with ROUGE-L evaluation (json)
python main.py --input tenable_report.pdf --scanner tenable --llm deepseek --evaluate --baseline tenable_report.json --evaluation-method bert --allow_duplicates
```

## Output Files and Logs

Each extraction generates multiple files in the output directory:

| File Name                        | Description                                                                             |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| `*_output.json` (or custom name) | **Main output:** Extracted vulnerabilities in JSON format                               |
| `*_deduplication_log.txt`        | **Consolidation report:** Details on how vulnerabilities were consolidated/deduplicated |
| `*_removed_log.txt`              | **Removed items log:** Vulnerabilities that were filtered out (invalid descriptions)    |
| `*_merge_log.txt`                | **Merge log:** Generated only for strategies with complex merge logic (e.g., Tenable)   |
| `final_report_*.txt`             | **Execution summary:** Timing, token usage, and overall statistics                      |

### Understanding the Consolidation Log

The `*_deduplication_log.txt` file provides detailed information about vulnerability consolidation:

```
======================================================================
CONSOLIDATION & DEDUPLICATION REPORT
======================================================================

Strategy: OpenVAS custom merge
Description: Groups vulnerabilities by (Name, port, protocol), keeps most complete

INPUT VULNERABILITIES: 46

PROCESSING STAGE 1: Strategy-Specific Consolidation
  Result: 36 vulnerabilities
  Removed: 10 (duplicate merge)
  Note: This is the custom OpenVAS consolidation strategy

OUTPUT FINAL: 36 vulnerabilities (valid & saved)

======================================================================
DETAIL: Vulnerability Groups
----------------------------------------------------------------------
Group 1: Key = ('SMTP too long line', 25, 'tcp')
  Total vulnerabilities in group: 1
    1. Name: SMTP too long line
       Port: 25 | Protocol: tcp | Severity: High
       Description: Some antivirus scanners dies when they process...
...
```

This log shows:

- **Strategy name and description**: Which consolidation method was used
- **Input count**: Original number of vulnerabilities from extraction
- **Output count**: Final number of vulnerabilities after consolidation
- **Removed count**: How many were removed and why
- **Group details**: How vulnerabilities were grouped/merged (if applicable)

This allows you to:

- Verify consolidation worked as expected
- Understand why certain vulnerabilities were removed
- Debug issues with duplicate handling
- Evaluate the impact of different `--allow-duplicates` settings

### Example Output Structure

When running with `--output-file openvas_test`, you'll get:

```
./openvas_test.json                          # Main output
./openvas_test_deduplication_log.txt         # Consolidation details
./openvas_test_removed_log.txt               # Filtered vulnerabilities
./final_report_20260320_210550_*.txt         # Execution summary
results_tokens/openvas_test_*_tokens.json    # Token usage statistics
```

## Batch Extraction

To process all PDFs in a directory in batch:

```bash
# Syntax
python tools/batch_pdf_extractor.py --input-dir <pdfs_directory> --scanner <scanner> --llm <llm> --convert <format> [--allow-duplicates] [--output-dir <output_directory>]

# Example: Process all PDFs in 'pdfs/' folder
python tools/batch_pdf_extractor.py --input-dir pdfs --scanner openvas --llm deepseek --convert all --allow-duplicates --output-dir jsons
```

## Validation and Debugging

```bash
# Syntax: Basic chunk validation
python tools/chunk_validator.py --input <pdf_path>

# Example:
python tools/chunk_validator.py --input report.pdf

# Syntax: Detailed chunk analysis for specific LLM and scanner
python tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Example: Tenable with GPT-4
python tools/chunk_validator.py --input report.pdf --llm gpt4 --scanner tenable
```

## Metrics Analysis

The metrics scripts automatically handle JSON-to-XLSX conversion and cache the converted files for efficiency. You can pass either `.json` or `.xlsx` files directly.

### Isolated Analyses

#### BERT Analysis

```bash
# Syntax: Using JSON extraction (automatic conversion to XLSX)
python metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Example:
python metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Syntax: Or using pre-converted XLSX
python metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Example:
python metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates
```

#### ROUGE Analysis (ROUGE-L)

```bash
# Syntax: Using JSON extraction (automatic conversion to XLSX)
python metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Example:
python metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Syntax: Or using pre-converted XLSX
python metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Example:
python metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates
```

**Note:** The `--model` parameter is optional but recommended for result organization. Both scripts generate four output sheets:

- **Per_Vulnerability**: Detailed scores per vulnerability
- **Summary**: Aggregate statistics
- **Categorization**: Similarity categorization (Highly Similar, Moderately Similar, etc.)
- **Mapping_Debug**: Internal matching details

**Internal Note:** When called from `run_experiments.py`, metrics use `--baseline-file` argument (for internal consistency in checkpoint tracking).

### Chart Generation

> **Important:** Pass the baseline (ground truth) file in the `--baseline` parameter. The plotting script uses the baseline as a reference to automatically compare the results of all models/extractions available.

```bash
# Syntax: Single model comparison
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm>

# Example: ROUGE chart for DeepSeek
python -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek

# Syntax: Multiple models comparison
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm1>,<llm2>,<llm3>

# Example: BERT comparison for three models
python -m metrics.plot.cli --metric bert --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek,gpt4,llama3

# Syntax: Chart with specific baseline sheet
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm> --baseline-sheet <sheet_name>

# Example: ROUGE with specific sheet
python -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek --baseline-sheet Vulnerabilities
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

Automates large-scale experiments with checkpoint support, automatic evaluation (BERT/ROUGE), comprehensive reporting, and result organization. **Automatically calls `process_results.py` at the end to generate charts.**

```bash
# Syntax: Run experiments with specified configurations
python tools/run_experiments.py --input-dir <input_directory> --llms <llm1> <llm2> ... --scanners <scanner1> <scanner2> ... --evaluation-methods <method1> <method2> ... --runs-per-model <number> --allow-duplicates <true/false> ...

# Example: Run with DeepSeek and GPT-4 on OpenVAS
python tools/run_experiments.py --input-dir test/openvas --llms deepseek gpt4 --scanners openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates true

# Syntax: Resume from checkpoint
python tools/run_experiments.py --input-dir <input_directory> --llms <llm> --scanners <scanner> --checkpoint-file <checkpoint_file.json>

# Example: Resume interrupted run
python tools/run_experiments.py --input-dir test/openvas --llms deepseek --scanners openvas --checkpoint-file run_checkpoints_2026-03-16T12-28-08.json
```

**Key Features:**

- **Checkpoint support**: Resume interrupted experiments from checkpoint files
- **Timing reports**: Tracks extraction and metrics evaluation times
- **Token cost analysis**: Integrates with `results_tokens/` directory
- **Automatic reporting**: Generates comprehensive final report with `reporting.py`
- **Chart generation**: Automatically calls `process_results.py` at the end
- **Organized results**: Stores outputs in `results_runs/` → `resultados_bert/` and `resultados_rouge/`

**Parameters:**

- `--input-dir`: Directory with paired .xlsx (baseline) and .pdf (report) files
- `--llms`: Space-separated list of LLMs (e.g., `deepseek gpt4 llama3`)
- `--scanners`: Space-separated list of scanners (e.g., `openvas tenable`)
- `--evaluation-methods`: Evaluation methods (default: `bert`, can add `rouge`)
- `--runs-per-model`: Number of runs per model combination (default: 10)
- `--allow-duplicates`: Boolean per scanner (e.g., `true false` for `openvas tenable`)
- `--checkpoint-file`: Optional checkpoint file to resume execution

### `tools/process_results.py` — Chart and Statistics Generation

Generates comparison charts (stacked bar, heatmaps) and statistics from experiment results. **Called automatically by `run_experiments.py`.**

```bash
# Manual chart generation (automatically called by run_experiments.py)
python tools/process_results.py
```

### `tools/dataset_generator.py` — Dataset Consolidation

Generates consolidated datasets (CSV, XLSX, JSON, JSONL) from multiple JSON files.

```bash
# Syntax: Generate specific format
python tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format <format>

# Example: Generate XLSX from JSONs
python tools/dataset_generator.py --input-folder jsons --output-folder dataset --format xlsx

# Syntax: Generate all formats simultaneously
python tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format all

# Example: Generate CSV, XLSX, JSON, and JSONL
python tools/dataset_generator.py --input-folder jsons --output-folder dataset --format all
```

### `chunk_validator.py`

Token distribution analysis and chunk validation tool.

```bash
# Syntax
python tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Example
python tools/chunk_validator.py --input document.pdf --llm gpt4 --scanner tenable
```
