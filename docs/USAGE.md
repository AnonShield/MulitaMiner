# Usage Guide

Complete guide for using MulitaMiner with all available options.

## CLI Interface

**Basic syntax:**

```bash
# Windows
python main.py --input <pdf_path> [options]

# Linux/macOS
python3 main.py --input <pdf_path> [options]
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

| Parameter              | Description                              | Default |
| ---------------------- | ---------------------------------------- | ------- |
| `--baseline-path`      | Ground truth file (.xlsx or .json)       | none    |
| `--evaluation-methods` | Methods: `bert`, `rouge` (space-separated) | none  |
| `--allow-duplicates`   | Allow legitimate duplicates              | `false` |

## Usage Examples

### Basic Usage

```bash
# Windows
python main.py --input report_tenable.pdf --scanner tenable --llm deepseek

# Linux/macOS
python3 main.py --input report_tenable.pdf --scanner tenable --llm deepseek
```

### Export Formats

```bash
# Syntax: CSV with custom configuration

# Windows
python main.py --input <pdf_path> --convert csv --csv-delimiter <char> --csv-encoding <encoding> --output-file <filename>

# Linux/macOS
python3 main.py --input <pdf_path> --convert csv --csv-delimiter <char> --csv-encoding <encoding> --output-file <filename>

# Example: CSV with semicolon separator

# Windows
python main.py --input vulnerabilities_report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en"

# Linux/macOS
python3 main.py --input vulnerabilities_report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en"

# Syntax: Export to Excel

# Windows
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert xlsx --output-dir <output_directory>

# Linux/macOS
python3 main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert xlsx --output-dir <output_directory>

# Example: Tenable report to Excel

# Windows
python main.py --input large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results

# Linux/macOS
python3 main.py --input large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results

# Syntax: All formats

# Windows
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert all

# Linux/macOS
python3 main.py --input <pdf_path> --scanner <scanner> --llm <llm> --convert all

# Example: Generate all formats

# Windows
python main.py --input openvas.pdf --scanner openvas --llm deepseek --convert all

# Linux/macOS
python3 main.py --input openvas.pdf --scanner openvas --llm deepseek --convert all
```

### Specialized Scenarios

```bash
# Example: Tenable with GPT-4

# Windows
python main.py --input tenable_report.pdf --scanner tenable --llm gpt4 --convert all

# Linux/macOS
python3 main.py --input tenable_report.pdf --scanner tenable --llm gpt4 --convert all

# Example: OpenVAS with GPT-4

# Windows
python main.py --input openvas_report.pdf --scanner openvas --llm gpt4 --convert all --allow-duplicates

# Linux/macOS
python3 main.py --input openvas_report.pdf --scanner openvas --llm gpt4 --convert all --allow-duplicates

# Example: CAIS with GPT-4

# Windows
python main.py --input cais_tenable.pdf --scanner cais_tenable --llm gpt4 --convert all

# Linux/macOS
python3 main.py --input cais_tenable.pdf --scanner cais_tenable --llm gpt4 --convert all
```

### Extraction with Metrics Evaluation

```bash
# Syntax: Extract and evaluate with BERT

# Windows
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --baseline-path <baseline_file> --evaluation-methods bert [--allow-duplicates]

# Linux/macOS
python3 main.py --input <pdf_path> --scanner <scanner> --llm <llm> --baseline-path <baseline_file> --evaluation-methods bert [--allow-duplicates]

# Example: OpenVAS extraction with BERT evaluation (xlsx)

# Windows
python main.py --input openvas_report.pdf --scanner openvas --llm deepseek --baseline-path openvas_report.xlsx --evaluation-methods bert --allow-duplicates

# Linux/macOS
python3 main.py --input openvas_report.pdf --scanner openvas --llm deepseek --baseline-path openvas_report.xlsx --evaluation-methods bert --allow-duplicates

# Example: OpenVAS extraction with BERT evaluation (json)

# Windows
python main.py --input openvas_report.pdf --scanner openvas --llm deepseek --baseline-path openvas_report.json --evaluation-methods bert --allow-duplicates

# Linux/macOS
python3 main.py --input openvas_report.pdf --scanner openvas --llm deepseek --baseline-path openvas_report.json --evaluation-methods bert --allow-duplicates

# Syntax: Extract and evaluate with ROUGE-L

# Windows
python main.py --input <pdf_path> --scanner <scanner> --llm <llm> --baseline-path <baseline_file> --evaluation-methods rouge [--allow-duplicates]

# Linux/macOS
python3 main.py --input <pdf_path> --scanner <scanner> --llm <llm> --baseline-path <baseline_file> --evaluation-methods rouge [--allow-duplicates]

# Example: Tenable extraction with ROUGE-L evaluation (xlsx)

# Windows
python main.py --input tenable_report.pdf --scanner tenable --llm deepseek --baseline-path tenable_report.xlsx --evaluation-methods rouge

# Linux/macOS
python3 main.py --input tenable_report.pdf --scanner tenable --llm deepseek --baseline-path tenable_report.xlsx --evaluation-methods rouge

# Example: Tenable extraction with both BERT and ROUGE (json baseline)

# Windows
python main.py --input tenable_report.pdf --scanner tenable --llm deepseek --baseline-path tenable_report.json --evaluation-methods bert rouge

# Linux/macOS
python3 main.py --input tenable_report.pdf --scanner tenable --llm deepseek --baseline-path tenable_report.json --evaluation-methods bert rouge
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

# Windows
python tools/batch_pdf_extractor.py --input-dir <pdfs_directory> --scanner <scanner> --llm <llm> --convert <format> [--allow-duplicates] [--output-dir <output_directory>]

# Linux/macOS
python3 tools/batch_pdf_extractor.py --input-dir <pdfs_directory> --scanner <scanner> --llm <llm> --convert <format> [--allow-duplicates] [--output-dir <output_directory>]

# Example: Process all PDFs in 'pdfs/' folder

# Windows
python tools/batch_pdf_extractor.py --input-dir pdfs --scanner openvas --llm deepseek --convert all --allow-duplicates --output-dir jsons

# Linux/macOS
python3 tools/batch_pdf_extractor.py --input-dir pdfs --scanner openvas --llm deepseek --convert all --allow-duplicates --output-dir jsons
```

## Validation and Debugging

```bash
# Syntax: Basic chunk validation

# Windows
python tools/chunk_validator.py --input <pdf_path>

# Linux/macOS
python3 tools/chunk_validator.py --input <pdf_path>

# Example:

# Windows
python tools/chunk_validator.py --input report.pdf

# Linux/macOS
python3 tools/chunk_validator.py --input report.pdf

# Syntax: Detailed chunk analysis for specific LLM and scanner

# Windows
python tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Linux/macOS
python3 tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Example: Tenable with GPT-4

# Windows
python tools/chunk_validator.py --input report.pdf --llm gpt4 --scanner tenable

# Linux/macOS
python3 tools/chunk_validator.py --input report.pdf --llm gpt4 --scanner tenable
```

## Metrics Analysis

The metrics scripts automatically handle JSON-to-XLSX conversion and cache the converted files for efficiency. You can pass either `.json` or `.xlsx` files directly.

### Isolated Analyses

#### BERT Analysis

```bash
# Syntax: Using JSON extraction (automatic conversion to XLSX)

# Windows
python metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Linux/macOS
python3 metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Example:

# Windows
python metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Linux/macOS
python3 metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Syntax: Or using pre-converted XLSX

# Windows
python metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Linux/macOS
python3 metrics/bert/compare_extractions_bert.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Example:

# Windows
python metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates

# Linux/macOS
python3 metrics/bert/compare_extractions_bert.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates
```

#### ROUGE Analysis (ROUGE-L)

```bash
# Syntax: Using JSON extraction (automatic conversion to XLSX)

# Windows
python metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Linux/macOS
python3 metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.json> --model <llm> [--allow-duplicates]

# Example:

# Windows
python metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Linux/macOS
python3 metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.json --model llama3 --allow-duplicates

# Syntax: Or using pre-converted XLSX

# Windows
python metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Linux/macOS
python3 metrics/rouge/compare_extractions_rouge.py --baseline <baseline_xlsx> --extraction-file <extraction.xlsx> --model <llm> [--allow-duplicates]

# Example:

# Windows
python metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates

# Linux/macOS
python3 metrics/rouge/compare_extractions_rouge.py --baseline test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test.xlsx --model llama3 --allow-duplicates
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

# Windows
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm>

# Linux/macOS
python3 -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm>

# Example: ROUGE chart for DeepSeek

# Windows
python -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek

# Linux/macOS
python3 -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek

# Syntax: Multiple models comparison

# Windows
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm1>,<llm2>,<llm3>

# Linux/macOS
python3 -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm1>,<llm2>,<llm3>

# Example: BERT comparison for three models

# Windows
python -m metrics.plot.cli --metric bert --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek,gpt4,llama3

# Linux/macOS
python3 -m metrics.plot.cli --metric bert --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek,gpt4,llama3

# Syntax: Chart with specific baseline sheet

# Windows
python -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm> --baseline-sheet <sheet_name>

# Linux/macOS
python3 -m metrics.plot.cli --metric <metric> --baseline <baseline_xlsx> --models <llm> --baseline-sheet <sheet_name>

# Example: ROUGE with specific sheet

# Windows
python -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek --baseline-sheet Vulnerabilities

# Linux/macOS
python3 -m metrics.plot.cli --metric rouge --baseline test/openvas/OpenVAS_JuiceShop.xlsx --models deepseek --baseline-sheet Vulnerabilities
```

## Processing Flow

1. **Input**: PDF specified in `pdf_path`
2. **Temp blocks creation**: Scanner-aware segmentation creates blocks in `temp_blocks_<llm>/` directory (preserves report structure)
3. **Chunk calculation**: Optimized system calculates ideal token sizes per LLM (within each block)
4. **Processing**: Using scanner and LLM configured with optimized chunks
5. **Extraction**: Vulnerabilities extracted with smart retry
6. **Consolidation**: Removal of duplicates and merge of instances (scanner-specific)
7. **Primary output**: JSON as per scanner's `output_file`
8. **Conversions**: Additional formats (CSV, XLSX,...) as per `--convert`
9. **Visual layout**: Preserved visual layout in a .txt file (same directory as PDF)

## Generated Files

- **Main JSON**: `vulnerabilities_<scanner>.json`
- **Visual layout**: `visual_layout_extracted_<file_name>.txt`
- **Logs**: `*_removed_log.txt`, `*_duplicates_removed_log.txt`, `*_merge_log.txt`

## Output Format (JSON Structure)

The vulnerability extraction produces a **standard JSON schema with 18 fields across all scanners** (OpenVAS, Tenable WAS, etc.). The schema structure remains identical regardless of the source scanner, though the fields are populated differently depending on the scanner type. Below is a **complete example from Tenable WAS** to demonstrate a real-world output:

```json
[
  {
    "Name": "Missing HTTP Strict Transport Security Policy",
    "description": [
      "Strict-Transport-Security (HSTS) is a web security policy mechanism which helps secure HTTPS only websites against downgrade attacks",
      "It ensures that all communications with the server are encrypted using TLS/SSL protocols"
    ],
    "detection_result": [],
    "detection_method": [],
    "product_detection_result": [],
    "impact": [],
    "solution": [
      "Add the Strict-Transport-Security header to HTTPS responses with an appropriate max-age value",
      "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    ],
    "insight": [],
    "log_method": [],
    "cvss": [
      "CVSSV4 BASE SCORE 5.3",
      "CVSSV4 VECTOR CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
      "CVSSV3 BASE SCORE 5.3",
      "CVSSV3 VECTOR CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ],
    "port": null,
    "protocol": null,
    "severity": "HIGH",
    "references": [
      "CWE-693",
      "OWASP-A06:2021",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    ],
    "plugin": 131371,
    "plugin_details": {
      "publication_date": "2018-10-25T00:00:00+00:00",
      "modification_date": "2024-12-15T00:00:00+00:00",
      "family": "Web Applications",
      "severity": "High",
      "plugin_id": 131371
    },
    "instances": [
      {
        "instance": "https://juice-shop-388277804329.us-west1.run.app/",
        "input_type": "link",
        "input_name": null,
        "payload": null,
        "proof": "The scanner did not find Strict-Transport-Security header in the response",
        "output": "Header missing in HTTPS response",
        "request_method": "GET",
        "http_status_code": 200,
        "http_protocol": "HTTP/2",
        "response_content_type": "text/html"
      },
      {
        "instance": "https://juice-shop-388277804329.us-west1.run.app/api/Users",
        "input_type": "link",
        "input_name": null,
        "payload": null,
        "proof": "The scanner did not find Strict-Transport-Security header in the response",
        "output": "Header missing in HTTPS response",
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

### Field Mapping Overview

**Note on OpenVAS vs Tenable WAS:**

- **OpenVAS**: Fills `detection_result`, `detection_method`, `product_detection_result`, `impact`, `insight`, `log_method` with extracted data. Has `instances=[]`, `plugin=null`, `plugin_details={}`.
- **Tenable WAS**: All OpenVAS-specific fields are empty arrays `[]`. Fills `port=null`, `protocol=null`, `plugin=<number>`, `plugin_details={...}`, and `instances=[{...}]` with endpoint data.

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

# Windows
python tools/run_experiments.py --input-dir <input_directory> --llms <llm1> <llm2> ... --scanner <scanner> --evaluation-methods <method1> <method2> ... --runs-per-model <number> [--allow-duplicates]

# Linux/macOS
python3 tools/run_experiments.py --input-dir <input_directory> --llms <llm1> <llm2> ... --scanner <scanner> --evaluation-methods <method1> <method2> ... --runs-per-model <number> [--allow-duplicates]

# Example: Run with DeepSeek and GPT-4 on OpenVAS (with allow-duplicates)

# Windows
python tools/run_experiments.py --input-dir test\openvas --llms deepseek gpt4 --scanner openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates

# Linux/macOS
python3 tools/run_experiments.py --input-dir test/openvas --llms deepseek gpt4 --scanner openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates

# Example: Run on Tenable (no --allow-duplicates)

# Windows
python tools/run_experiments.py --input-dir test\tenable --llms deepseek gpt4 --scanner tenable --evaluation-methods bert rouge --runs-per-model 5

# Linux/macOS
python3 tools/run_experiments.py --input-dir test/tenable --llms deepseek gpt4 --scanner tenable --evaluation-methods bert rouge --runs-per-model 5

# Syntax: Resume from checkpoint

# Windows
python tools/run_experiments.py --checkpoint-file <checkpoint_file.json>

# Linux/macOS
python3 tools/run_experiments.py --checkpoint-file <checkpoint_file.json>

# Example: Resume interrupted run

# Windows
python tools/run_experiments.py --checkpoint-file run_checkpoints_2026-03-16T12-28-08.json

# Linux/macOS
python3 tools/run_experiments.py --checkpoint-file run_checkpoints_2026-03-16T12-28-08.json
```

**Key Features:**

- **One scanner per invocation**: run separately for OpenVAS and Tenable
- **Checkpoint support**: Resume interrupted experiments from checkpoint files
- **Timing reports**: Tracks and sums execution time across all runs
- **Token cost analysis**: Integrates with `results_tokens/` directory
- **Automatic reporting**: Generates comprehensive final report with `reporting.py`
- **Chart generation**: Automatically calls `process_results.py` at the end
- **Organized results**: Stores outputs in `results_runs/` → `resultados_bert/` and `resultados_rouge/`

**Parameters:**

- `--input-dir`: Directory with paired .xlsx (baseline) and .pdf (report) files
- `--llms`: Space-separated list of LLMs (e.g., `deepseek gpt4 llama3`)
- `--scanner`: Scanner to use (`openvas` or `tenable`)
- `--evaluation-methods`: Evaluation methods (default: `bert`, can add `rouge`)
- `--runs-per-model`: Number of runs per model combination (default: 10)
- `--allow-duplicates`: Flag to allow duplicates (recommended for OpenVAS; omit for Tenable)
- `--checkpoint-file`: Optional checkpoint file to resume execution

### `tools/process_results.py` — Chart and Statistics Generation

Generates comparison charts (stacked bar, heatmaps) and statistics from experiment results. **Called automatically by `run_experiments.py`.**

```bash
# Manual chart generation (automatically called by run_experiments.py)

# Windows
python tools/process_results.py

# Linux/macOS
python3 tools/process_results.py
```

### `tools/dataset_generator.py` — Dataset Consolidation

Generates consolidated datasets (CSV, XLSX, JSON, JSONL) from multiple JSON files.

```bash
# Syntax: Generate specific format

# Windows
python tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format <format>

# Linux/macOS
python3 tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format <format>

# Example: Generate XLSX from JSONs

# Windows
python tools/dataset_generator.py --input-folder jsons --output-folder dataset --format xlsx

# Linux/macOS
python3 tools/dataset_generator.py --input-folder jsons --output-folder dataset --format xlsx

# Syntax: Generate all formats simultaneously

# Windows
python tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format all

# Linux/macOS
python3 tools/dataset_generator.py --input-folder <input_folder> --output-folder <output_folder> --format all

# Example: Generate CSV, XLSX, JSON, and JSONL

# Windows
python tools/dataset_generator.py --input-folder jsons --output-folder dataset --format all

# Linux/macOS
python3 tools/dataset_generator.py --input-folder jsons --output-folder dataset --format all
```

### `chunk_validator.py`

Token distribution analysis and chunk validation tool.

```bash
# Syntax

# Windows
python tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Linux/macOS
python3 tools/chunk_validator.py --input <pdf_path> --llm <llm> --scanner <scanner>

# Example

# Windows
python tools/chunk_validator.py --input document.pdf --llm gpt4 --scanner tenable

# Linux/macOS
python3 tools/chunk_validator.py --input document.pdf --llm gpt4 --scanner tenable
```
