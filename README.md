<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/2.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/1.png">
    <img src="assets/1.svg" width="500" alt="MulitaMiner logo">
  </picture>

# MulitaMiner

**Vulnerability Extraction from Security Reports using LLMs**

_Automated · Structured · Multi-LLM_

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-orange)
![update](https://img.shields.io/badge/last%20update-Feb%202026-lightgrey)

</div>

## Overview

**MulitaMiner** is a tool developed to extract and process vulnerabilities from security PDF reports using Large Language Models (LLMs) with an optimized chunking system. The tool implements an intelligent token optimization system that ensures efficient processing with no exceedances, supporting multiple LLM providers and specialized scanning strategies for different security tools (OpenVAS, Tenable WAS, Nessus, ...).

### Use Cases

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Enterprise Integration**: Support for CAIS formats for corporate systems
- **Research and Development**: Comparative evaluation of different LLMs

### Key Features

- **Multi-LLM Support**: 6 different providers with optimized configurations
- **Intelligent Consolidation**: Automatic merging or removal of duplicate vulnerabilities (configurable)
- **Detailed Logs**: Automatic generation of removal and deduplication logs (removed_log, duplicates_removed_log, merge_log)
- **Metrics Evaluation**: Automatic comparison with baselines using BERT/ROUGE
- **Multi-Format Export**: JSON, CSV, XLSX with preserved layouts

## Features

### Intelligent Extraction

- **Automatic extraction** of vulnerabilities from security PDF reports
- **Multi-scanner support**: OpenVAS, Tenable WAS, Nessus, and others
- **Automatic validation** of extracted data with normalization
- **Robust retry system** with smart chunk subdivision

### Optimized Chunking System

- **Automatic token calculation** based on each LLM's specific limits
- **Dynamic chunk size optimization** per model
- **Integrated validation** with `chunk_validator.py` for quality analysis

### Advanced Consolidation

- **TenableWAS**: Smart merging of vulnerability instances and base findings
- **OpenVAS**: Grouping by name similarity and characteristics
- **CAIS**: Consolidation by definitions with specialized fields

### Multi-LLM with Optimization

- **6 supported LLMs** with individual optimized configurations:
  - **DeepSeek**: Ultra-efficient for technical analysis
  - **GPT-4**: Balanced for general use
  - **GPT-5**: Ultra-secure for critical processing
  - **Llama 3/4**: Groq-hosted models with different profiles
  - **Qwen3**: Efficient alternative

### Multi-Format Export and Logs

- **Structured JSON** (main format)
- **CSV/TSV** with customizable delimiters
- **XLSX** (Excel) with advanced formatting
- **Visual layout preserved** in .txt file
- **Detailed logs**:
  - `*_removed_log.txt`: Vulnerabilities removed due to missing description/essential fields
  - `*_duplicates_removed_log.txt`: Vulnerabilities removed as exact duplicates (when `--allow-duplicates`)
  - `*_merge_log.txt`: Vulnerabilities actually merged (when `--allow-duplicates` is not active)

## Installation

### System Requirements

- **Python**: 3.8+ (recommended: Python 3.10+)
- **RAM**: 4GB+ recommended for large PDF processing

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/vulnerability-extractor.git
cd Vulnerability_Extractor
```

#### 2. Virtual Environment (Highly Recommended)

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### Main Python Dependencies

#### Core - LLM Framework and Processing

```pip-requirements
langchain>=0.1.0,<0.3.0          # Main framework for LLMs
langchain-openai>=0.1.0,<0.2.0   # OpenAI integration
```

#### PDF Processing - Optimized Text Extraction

```pip-requirements
pdfplumber>=0.10.0,<0.12.0       # PDF text extraction
```

#### UI/UX - Progress Bars and Feedback

```pip-requirements
tqdm>=4.0.0,<5.0.0               # Progress bars
```

#### Data Processing - Merge and Normalization

```pip-requirements
deepmerge>=1.1.0,<2.0.0          # Complex dictionary merge
```

#### Metrics Evaluation

```pip-requirements
rapidfuzz>=3.0.0,<4.0.0          # Fuzzy string matching
bert-score>=0.3.0,<0.4.0         # BERTScore for evaluation
rouge-score>=0.1.0,<0.2.0        # ROUGE metrics
```

#### Export Formats - CSV, XLSX

```pip-requirements
pandas>=1.3.0,<3.0.0             # DataFrames and manipulation
openpyxl>=3.0.0,<4.0.0           # Excel export
```

## Configuration

### API Key Configuration

API keys are configured via **environment variables** in the `.env` file. The system supports automatic variable substitution in JSON configuration files.

#### 1. Configure the .env file

Edit the existing `.env` file with your API keys:

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"
API_KEY_GPT4 = "your-openai-api-key"
API_KEY_GPT5 = "your-openai-api-key"
API_KEY_LLAMA3 = "your-groq-api-key"
API_KEY_LLAMA4 = "your-groq-api-key"
API_KEY_QWEN3 = "your-groq-api-key"
```

#### 2. How substitution works

JSON configuration files use the `${VARIABLE_NAME}` syntax to reference variables from `.env`:

```json
{
  "api_key": "${API_KEY_DEEPSEEK}",
  "endpoint": "https://api.deepseek.com/v1",
  "model": "deepseek-coder"
}
```

**⚠️ Security:** Never commit the `.env` file to public repositories!

### Token Calculation System

```
max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

#### Formula Components

| Component              | Description             | Example       |
| ---------------------- | ----------------------- | ------------- |
| `max_tokens`           | Model's total limit     | 8192 (Llama4) |
| `reserve_for_response` | Space for LLM response  | 5000 tokens   |
| `prompt_overhead`      | Template + instructions | 600 tokens    |
| `system_overhead`      | Metadata + overhead     | 500 tokens    |
| `safety_buffer`        | Safety margin           | 600 tokens    |

#### Real Configurations per LLM

| LLM          | Total Limit | Reserve | Final Chunk | Calculated Overhead | Efficiency |
| ------------ | ----------- | ------- | ----------- | ------------------- | ---------- |
| **GPT-4**    | 12,000      | 4,000   | **7,300**   | 700 tokens          | 60.8%      |
| **GPT-5**    | 16,000      | 6,000   | **8,300**   | 1,700 tokens        | 51.9%      |
| **DeepSeek** | 4,096       | 1,500   | **1,750**   | 846 tokens          | 42.7%      |
| **Llama3**   | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |
| **Llama4**   | 8,192       | 5,000   | **1,492**   | 1,700 tokens        | 18.2%      |
| **Qwen3**    | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |

**Calculated Overhead** = (Total Limit - Reserve) - Final Chunk

#### Value Interpretation

- **Overhead varies by LLM**: More complex templates require more space
- **Reserve for response**: Based on real tests of model verbosity
- **Efficiency**: Percentage of the total limit used for chunk processing

> **Note:** The values in the tables are based on practical tests and benchmarks with major LLM providers (OpenAI, Groq, DeepSeek). They reflect real usage scenarios but may vary depending on the model, prompt template, and provider updates. It is recommended to validate limits and reserves directly in the official documentation or your environment's execution logs.

## Usage

### CLI Interface

**Basic syntax:**

```bash
python main.py <pdf_path> [options]
```

### Main Parameters

#### Required Input

- `pdf_path`: **Path to the PDF file** of the vulnerability report

#### Processing Options

| Parameter   | Description      | Default   | Examples                             |
| ----------- | ---------------- | --------- | ------------------------------------ |
| `--scanner` | Scanner strategy | `default` | `tenable`, `openvas`, `cais_tenable` |
| `--llm`     | Language Model   | `gpt4`    | `deepseek`, `llama3`, `gpt5`         |

#### Export Options

| Parameter         | Description       | Default | Examples               |
| ----------------- | ----------------- | ------- | ---------------------- |
| `--convert`       | Conversion format | `none`  | `csv`, `xlsx`, `all`   |
| `--output-file`   | Output file name  | auto    | `vulnerabilities.json` |
| `--output-dir`    | Output folder     | current | `./results`            |
| `--csv-delimiter` | CSV separator     | `,`     | `;`                    |

#### Evaluation Options

| Parameter             | Description                 | Default                    |
| --------------------- | --------------------------- | -------------------------- |
| `--evaluate`          | Enable metrics evaluation   | `false`                    |
| `--baseline-file`     | Ground truth file (.xlsx)   | required with `--evaluate` |
| `--evaluation-method` | Method: `bert` or `rouge`   | `bert`                     |
| `--allow-duplicates`  | Allow legitimate duplicates | `false`                    |

### Batch Extraction

To process all PDFs in a directory in batch:

```bash
python tools/batch_pdf_extractor.py <pdfs_directory> --convert <format> --llm <model> --scanner <scanner> [--allow-duplicates] [--output-dir <dir>]
```

All extra arguments are passed to main.py. Example:

```bash
python tools/batch_pdf_extractor.py pdfs --scanner openvas --LLM deepseek --allow-duplicates --output-dir jsons
```

---

### Usage Examples

#### Basic Usage

```bash
# Standard processing with GPT-4
python main.py report.pdf
# Specific scanner
python main.py report_tenable.pdf --scanner tenable
# Specific model
python main.py report.pdf --llm deepseek
```

#### Export Formats

```bash
# CSV with custom configuration
python main.py report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en.csv"
# Full export to Excel
python main.py large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results
# All formats simultaneously
python main.py report.pdf --convert all --output-dir ./exports
```

#### Specialized Scenarios

```bash
# Tenable WAS optimized for maximum extraction
python main.py tenable_report.pdf --scanner tenable --llm gpt4 --convert all
# OpenVAS with Groq model
python main.py openvas_scan.pdf --scanner openvas --llm llama3 --convert csv
# CAIS Tenable for enterprise integration
python main.py cais_tenable.pdf --scanner cais_tenable --llm gpt5 --convert xlsx
```

#### Advanced Usage: Extraction with Metrics Evaluation

You can perform extraction and, in the same operation, evaluate the quality of the result by comparing it with a "ground truth" (baseline) file.

```bash
# Extract vulnerabilities and evaluate extraction quality using the 'bert' method
python main.py report_tenable.pdf --scanner tenable --convert all --evaluate --baseline-file metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx --evaluation-method bert
# Evaluation with legitimate duplicates allowed (recommended for OpenVAS)
python main.py report_openvas.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --allow-duplicates
```

#### Validation and Debugging

```bash
# Chunk validation before processing
python tools/chunk_validator.py report.pdf
# Detailed chunk analysis by LLM
python tools/chunk_validator.py report.pdf --llm gpt4 --scanner tenable
```

### Metrics Analysis

#### Isolated Analyses

You can run metrics analyses independently, comparing extractions already performed with ground truth baselines.

##### BERT Analysis

```bash
# BERT analysis
python metrics/bert/compare_extractions_bert.py --baseline-file <relative_path_to_baseline_file> --extraction-file <relative_path_to_extraction_file> --model <llm> --allow-duplicates
```

##### ROUGE Analysis

```bash
# Basic ROUGE analysis
python metrics/rouge/compare_extractions_rouge.py --baseline-file <relative_path_to_baseline_file> --extraction-file <relative_path_to_extraction_file> --model <llm> --allow-duplicates
```

### Chart Generation

> **Important:** Pass the baseline (ground truth) file in the --baseline parameter. **Do not** use the extraction file generated by the model here. The plotting script uses the baseline as a reference to automatically compare the results of all models/extractions available for that dataset.

Use the plot CLI to generate comparative metric charts for one or more models.

#### Individual Chart

```bash
# Simple chart for one model
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek
```

#### Multiple Comparison

```bash
# Comparison of three models
python -m metrics.plot.cli --metric bert --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek,gpt4,llama3
```

#### Chart with Filters

```bash
# Chart focused on specific metrics
python -m metrics.plot.cli --metric rouge --baseline tenable/TenableWAS_bWAAP.xlsx --models deepseek --baseline-sheet Vulnerabilities
```

### Processing Flow

1. **Input**: PDF specified in `pdf_path`
2. **Chunk calculation**: Optimized system calculates ideal sizes per LLM
3. **Processing**: Using scanner and LLM configured with optimized chunks
4. **Extraction**: Vulnerabilities extracted with smart retry
5. **Consolidation**: Removal of duplicates and merge of instances (TenableWAS)
6. **Primary output**: JSON as per scanner's `output_file`
7. **Conversions**: Additional formats (CSV, XLSX,...) as per `--convert`
8. **Visual layout**: Preserved visual layout in a .txt file (same directory as PDF)

### Generated Files

- **Main JSON**: `vulnerabilities_<scanner>.json`
- **Visual layout**: `visual_layout_extracted_<file_name>.txt`

### Output Format

#### JSON Structure

The tool generates a JSON file with the vulnerabilities found. The complete format includes specific fields for different types of reports:

```json
[
  {
    "Name": "SQL Injection",
    "description": ["Detailed description of the vulnerability"],
    "detection_result": ["Vulnerability detection result (OpenVAS only)"],
    "detection_method": ["Vulnerability detection method (OpenVAS only)"],
    "impact": ["Impact description (OpenVAS only)"],
    "solution": ["Recommended solutions"],
    "insight": ["Vulnerability insight (OpenVAS only)"],
    "product_detection_result": ["Product detection result (OpenVAS only)"],
    "log_method": ["Log method (OpenVAS only)"],
    "cvss": [
      "CVSSV4 BASE SCORE - number",
      "CVSSV4 VECTOR - string",
      "CVSSv3 BASE SCORE - number",
      "CVSSv3 VECTOR - string",
      "CVSSv2 BASE SCORE - number",
      "CVSS BASE SCORE - number",
      "CVSS VECTOR - string"
    ],
    "port": "80",
    "protocol": "tcp",
    "severity": "HIGH",
    "references": ["List of references"],
    "plugin": ["Plugin details (Tenable WAS only)"],
    "source": "OPENVAS"
  }
]
```

#### Field Mapping by Tool

| Field                      | OpenVAS | Tenable WAS | Description                             |
| -------------------------- | ------- | ----------- | --------------------------------------- |
| `Name`                     | ✅      | ✅          | Vulnerability name                      |
| `description`              | ✅      | ✅          | Detailed description                    |
| `detection_result`         | ✅      | ❌          | Detection result (OpenVAS only)         |
| `detection_method`         | ✅      | ❌          | Detection method (OpenVAS only)         |
| `impact`                   | ✅      | ❌          | Impact of vulnerability (OpenVAS only)  |
| `solution`                 | ✅      | ✅          | Recommended solutions                   |
| `insight`                  | ✅      | ❌          | Vulnerability insight (OpenVAS only)    |
| `product_detection_result` | ✅      | ❌          | Product detection result (OpenVAS only) |
| `log_method`               | ✅      | ❌          | Log method (OpenVAS only)               |
| `cvss`                     | ✅      | ✅          | CVSS scores (multiple versions)         |
| `port`                     | ✅      | ✅          | Vulnerability port                      |
| `protocol`                 | ✅      | ✅          | Protocol (tcp/udp)                      |
| `severity`                 | ✅      | ✅          | Severity (LOG/LOW/MEDIUM/HIGH/CRITICAL) |
| `references`               | ✅      | ✅          | References and links                    |
| `plugin`                   | ❌      | ✅          | Plugin details (Tenable WAS only)       |
| `source`                   | ✅      | ✅          | Report source (OPENVAS/TENABLEWAS)      |

### Troubleshooting

#### Token Errors

| Error                                              | Cause                              | Solution                                         |
| -------------------------------------------------- | ---------------------------------- | ------------------------------------------------ |
| "Setting 'max_tokens' and 'max_completion_tokens'" | Conflict between OpenAI parameters | System fixed to use only `max_completion_tokens` |
| "Token limit exceeded"                             | Chunk too large                    | Optimized chunk system solves automatically      |
| "Rate limit exceeded"                              | Too many requests                  | Wait for quota reset or use alternative provider |

#### Connectivity Errors

| Error                | Cause                   | Solution                                |
| -------------------- | ----------------------- | --------------------------------------- |
| `SSL/Network`        | Temporary network issue | Try again or increase `timeout`         |
| "Invalid API key"    | Incorrect/expired key   | Check configuration in `.env`           |
| "Discontinued model" | Model not available     | Update to valid model in configurations |

#### Model Errors

| Error             | Cause                   | Solution                   |
| ----------------- | ----------------------- | -------------------------- |
| "quota limit"     | Provider limit exceeded | Use Groq or wait for reset |
| "model not found" | Incorrect name          | Check LLM configuration    |

### Optimization Tips

#### By Report Size

| Size             | Recommendation | Justification                       |
| ---------------- | -------------- | ----------------------------------- |
| **< 50 pages**   | GPT-4/GPT-5    | Larger chunks, efficient processing |
| **50-200 pages** | Llama3/Qwen3   | Optimal balancing                   |
| **> 200 pages**  | Llama4         | More precise incremental processing |

#### By Analysis Type

| Scenario                | Best LLM    | Why?                              |
| ----------------------- | ----------- | --------------------------------- |
| **Technical Analysis**  | DeepSeek    | Specialized in code/security      |
| **Critical Processing** | GPT-5       | Maximum security and precision    |
| **Economy**             | Llama3/Groq | Efficient                         |
| **Debugging**           | Llama4      | Maximum precision in small chunks |

#### ⚡ Performance Tips

- **Optimized BERTScore**: Model loaded once, evaluation in ~30 seconds
- **Evaluation with duplicates**: Use `--allow-duplicates` with OpenVAS
- **Monitoring**: Detailed logs for bottleneck identification

## Experiments

MulitaMiner was validated through practical experiments with different types of reports and LLM configurations.

### Test Scenarios

#### Tenable WAS Reports

- **Tested configuration**: Scanner `tenable` + LLM `gpt4`
- **Tested documents**: Reports of 50-200 pages
- **Results**: Efficient consolidation of instances/bases, accurate plugin detection
- **Optimization**: 7300-token chunks with smart vulnerability merge

#### OpenVAS/Greenbone Reports

- **Tested configuration**: Scanner `openvas` + LLM `llama3`
- **Tested documents**: NVT reports with 100-500 vulnerabilities
- **Results**: Complete extraction of 18 specialized fields (detection_result, impact, insight)
- **Optimization**: 3492-token chunks with processing via Groq

### Token Optimization Validation

#### Experiments

```bash
# Test with 300-page document
python main.py large_report.pdf --llm gpt4
# Result: 42 chunks processed

python chunk_validator.py large_report.pdf --llm gpt4
# Analysis: Uniform distribution, 60.8% efficiency
```

#### Experiment: Comparative Performance

```bash
# Comparative test between models
python main.py test_report.pdf --llm llama4  # Maximum precision (1492 tokens)
python main.py test_report.pdf --llm gpt4    # Balanced (7300 tokens)
python main.py test_report.pdf --llm deepseek # Technical efficiency (1750 tokens)

# Results:
# - Llama4: 83 chunks, slower processing, maximum precision
# - GPT-4: 18 chunks, balanced processing, good quality
# - DeepSeek: 76 chunks, fast processing, technical quality
```

## Code Structure

```
Vulnerability_Extractor/
├── main.py                              # Main CLI script (entry point for extraction)
├── requirements.txt                     # Python dependencies
├── README.md                            # Documentation
├── chunk_validator.py                   # Chunk validator (standalone tool for chunk analysis)
├── batch_pdf_extractor.py               # Batch PDF extraction (processes multiple PDFs)
├── tools/
│   ├── run_experiments.py               # Massive execution and automated evaluation (benchmarks)
│   ├── process_results.py               # Chart and statistics generation (metrics visualization)
│   ├── dataset_generator.py             # Dataset consolidation (CSV/XLSX/JSON/JSONL)
│   ├── sum_tokens_cost_all_llms.py      # Sums tokens and estimates costs per LLM (cost analysis)
│   ├── calc_tokens_cost.py              # Calculates tokens/cost for a specific LLM (single model)
│   ├── prepare_metrics_input.py         # Generates combined files for metrics (preprocessing)
│   └── chunk_validator.py               # (link to root, for compatibility)
├── src/
│   ├── __init__.py
│   ├── configs/
│   │   ├── llms/                        # LLM configurations (JSON files for models)
│   │   ├── scanners/                    # Scanner configurations (JSON)
│   │   └── templates/                   # Prompt templates (TXT)
│   ├── converters/
│   │   ├── base_converter.py            # Base converter class
│   │   ├── csv_converter.py             # CSV/TSV export logic
│   │   └── xlsx_converter.py            # Excel export logic
│   ├── scanner_strategies/              # Modular scanner strategies
│   │   ├── __init__.py
│   │   ├── base.py                      # Base class for scanner strategies
│   │   ├── consolidation.py             # Central consolidation logic
│   │   ├── openvas.py                   # OpenVAS custom strategy
│   │   ├── registry.py                  # Strategy registry (maps scanner to logic)
│   │   └── tenablewas.py                # Tenable WAS custom strategy
│   └── utils/
│       ├── block_creation.py            # Block creation and parsing logic
│       ├── cais_validator.py            # CAIS format validation
│       ├── chunking.py                  # Chunk calculation and optimization
│       ├── cli_args.py                  # CLI argument parsing
│       ├── convertions.py               # Data conversion helpers
│       ├── llm_utils.py                 # LLM loading and configuration
│       ├── pdf_loader.py                # PDF text extraction and layout preservation
│       ├── processing.py                # Main processing pipeline
│       └── profile_registry.py          # Profile and scanner registration
├── metrics/
│   ├── __init__.py
│   ├── baselines/
│   │   ├── openvas/                     # Baseline files for OpenVAS
│   │   └── tenable/                     # Baseline files for Tenable WAS
│   ├── bert/
│   │   └── compare_extractions_bert.py  # BERTScore evaluation script
│   ├── rouge/
│   │   └── compare_extractions_rouge.py # ROUGE evaluation script
│   ├── common/
│   │   ├── cli.py                       # CLI for metrics
│   │   ├── config.py                    # Metrics configuration
│   │   ├── matching.py                  # Matching logic for metrics
│   │   └── normalization.py             # Normalization utilities
│   └── plot/
│       ├── __init__.py
│       ├── __main__.py                  # CLI entry for plotting
│       ├── charts.py                    # Chart generation logic
│       └── utils.py                     # Plotting utilities
├── data/                                # Datasets generated (CSV, XLSX, JSON, JSONL)
├── jsons/                               # JSONs used in the dataset generation
├── results_tokens/                      # Token files per LLM (token/cost analysis)
├── results_runs/                        # Experimental run results (run_experiments.py)
├── results_runs_xlsx/                   # XLSX results (run_experiments.py)µ
├── plot_runs/                           # Generated charts (metrics visualization)
└── temp_blocks/                         # Temporary vulnerability blocks (intermediate parsing)
```

### Main Components

#### Interface Scripts

- **main.py**: Main CLI with modern arguments and full orchestration
- **chunk_validator.py**: Chunk analysis and validation tool

#### Processing System

- **processing.py**: Chunking engine with automatic token calculation
- **utils.py**: Smart LLM loading with optimized configurations per model
- **pdf_loader.py**: Optimized text extraction with layout preservation

#### Specialized Strategies

- **scanner_strategies.py**: Specialized processing logic per report type
- **profile_registry.py**: Profile/scanner registration and discovery system
- **cais_validator.py**: Specific validation for CAIS format

#### Export System

- **base_converter.py**: Base framework for converters
- **csv_converter.py**: CSV/TSV export with customizable settings
- **xlsx_converter.py**: Excel export with advanced formatting

## Advanced Scripts and Utilities

### `tools/run_experiments.py` — Massive Execution and Automated Evaluation

Automates large-scale experiments, processing multiple reports, LLMs, and scanners, with robust checkpointing and automatic evaluation (BERT/ROUGE). Generates statistics, logs, and organizes results in subfolders by baseline/model/run.

**Main features:**

- Runs extraction, export, and evaluation for all pairs (report, scanner, LLM, run)
- Checkpoint support: resumes interrupted executions without repeating completed runs
- Generates detailed logs, output files, metrics, and automatic summaries
- Organizes results in `results_runs/` and `results_runs_xlsx/`
- Automatic evaluation with BERT and ROUGE

**Usage example:**

```bash
python tools/run_experiments.py [--checkpoint-file run_checkpoints_YYYY-MM-DDTHH-MM-SS.json]
```

### `tools/process_results.py` — Chart and Statistics Generation

Processes experiment results, generating charts (stacked bar, heatmaps) and statistics of similarity, coverage, and model performance.

**Main features:**

- Generates similarity category distribution charts (stacked bar)
- Generates metric heatmaps (BERT/ROUGE) per LLM and baseline
- Analyzes and summarizes results from multiple experiments
- Saves charts in `plot_runs/`

**Usage example:**

```bash
python tools/process_results.py
```

### `tools/dataset_generator.py` — Dataset Consolidation

Generates consolidated datasets (CSV, XLSX, JSON, JSONL) from multiple JSON extraction files, facilitating analysis and training.

**Main features:**

- Consolidates all JSON files in a folder into a single dataset
- Supports multiple output formats: CSV, XLSX, JSON, JSONL
- Normalizes fields, adds IDs, and standardizes severities
- Ideal for quantitative analysis and ML use

**Usage example:**

```bash
python tools/dataset_generator.py --input-folder jsons --output-folder data --format xlsx
```

- **Generate all formats at once:**

```bash
python tools/dataset_generator.py --input-folder jsons --output-folder data --format all
```

This will create CSV, XLSX, JSON, and JSONL files simultaneously in the output folder.

#### chunk_validator.py

Standalone tool for chunk analysis and validation:

**Features:**

- Token distribution analysis
- Scanner pattern detection
- Chunk integrity validation
- Suggested configuration optimization
- Detailed efficiency reports

```bash
# Full chunking analysis
python chunk_validator.py document.pdf

# Validation with specific LLM
python chunk_validator.py document.pdf --LLM gpt4 --scanner tenable
```

### `tools/sum_tokens_cost_all_llms.py` — Token Sum and Cost Estimation

Analyzes all generated token files (`*_tokens.json` in `results_tokens/`), summing the total tokens processed per LLM and estimating the cost in dollars for each model and overall.

### Difference: `run_experiments.py` vs `batch_pdf_extractor.py`

- **`batch_pdf_extractor.py`**: Runs batch extraction of PDFs from a directory, calling `main.py` for each file. Useful for quickly processing many PDFs, but does not perform automatic evaluation or advanced result organization.
- **`run_experiments.py`**: Orchestrates complete experiments, processing multiple reports, LLMs, scanners, and runs, with checkpoint, automatic evaluation (BERT/ROUGE), logs, and detailed result organization. Ideal for benchmarks, validation, and experimentation.

**Main features:**

- Sums input/output tokens per LLM
- Calculates estimated cost per model and overall (using internal price table)
- Useful for efficiency analysis and cost planning

**Usage example:**

```bash
python tools/sum_tokens_cost_all_llms.py --tokens-dir results_tokens
```

#### Optimized Token System

Precise mathematical calculations for each LLM:

- **Universal formula**: `max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer`
- **Specific configurations** per model with calculated efficiencies
- **Automatic configuration validation** at startup

## Extensibility

### Adding a new scanner

MulitaMiner was designed to be easily expanded, allowing integration of new scanners (extraction tools) without changing the system core. See the recommended flow:

1. **Create a prompt template**
   - Add a file in `src/configs/templates/` (e.g., `rapid7_prompt.txt`).
   - The template should explain to the LLM how to extract vulnerabilities from the report, mapping fields to the standard JSON format.
   - Check existing templates for examples.

**Prompt template example:**

```txt
You will receive a vulnerability report. Extract each vulnerability as a JSON object with the following fields:
{
  "Name": "Vulnerability name",
  "description": "Detailed description",
  "severity": "Severity (LOW/MEDIUM/HIGH/CRITICAL)",
  "asset": "Affected asset",
  "name_consolidated": "Consolidated name for deduplication (e.g., Name + asset)"
}
Separate each vulnerability by line. Do not include any extra text.
```

2. **Create a scanner profile**

- Add a JSON file in `src/configs/scanners/` (e.g., `rapid7.json`).
- Define: scanner name, template path, consolidation fields (`consolidation_field`), duplicate rules, retry parameters, etc.

3. **(Optional) Custom block logic**

- If the report has no clear separators, or requires special grouping (e.g., by asset, plugin, section), implement a function in `src/utils/block_creation.py`.
- Integrate in the `create_session_blocks_from_text` method.
- **If not implemented:** The system divides the text into sequential chunks based on the LLM's token limit, without considering separators. This works well for structured reports, but may mix vulnerabilities in more complex ones.

4. **(Optional) Custom consolidation logic (strategy for allow_duplicates)**

- If the scanner needs special rules to group/merge vulnerabilities (e.g., merge by asset, plugin, custom field), create a class in a new `.py` file inside `src/scanner_strategies/` (e.g., `mycustomscanner.py`).
- Your class must inherit from `ScannerStrategy` (see `base.py`) and implement the method `consolidate_all(self, vulns, allow_duplicates=True, profile_config=None)`, which will receive all vulnerabilities and must return the consolidated list according to your custom logic.
- Register your class in the system by adding it to the dictionary in `src/scanner_strategies/registry.py`. The key you use to register (e.g., 'mycustomscanner') must match the scanner name declared in your profile JSON (e.g., `"reader": "mycustomscanner"`).
- The system will automatically call your custom strategy whenever the scanner name matches the registered key.
- The method `consolidate_all` is called by the central pipeline during deduplication, and must handle both `allow_duplicates=True` and `allow_duplicates=False` cases as needed for your scanner.
  **Important:** The custom function name must be strictly `vulnerability_processing_logic`. This ensures the system will automatically recognize and execute your vulnerability processing logic whenever the corresponding scanner is selected. The expected signature is:

  ```python
  def vulnerability_processing_logic(self, vulns, allow_duplicates=True, profile_config=None):
    # ... your vulnerability processing logic ...
  ```

Thus, the central pipeline will call this function whenever needed, ensuring integration and compatibility.

- **If not implemented:** The system uses the default consolidation (`consolidation_field`), sufficient for scanners without complex duplicates.

**How deduplication and merge work:**

The `consolidation_field` defines which field will be used to identify duplicates (e.g., "Name", "Name+asset"). If there is custom logic (custom strategy), it always prevails for the relevant allow_duplicates flag value (see below).

| Scanner Type | `--allow-duplicates` **disabled**          | `--allow-duplicates` **enabled**               | Notes                         |
| ------------ | ------------------------------------------ | ---------------------------------------------- | ----------------------------- |
| **Generic**  | Removes duplicates by consolidation field  | Keeps all duplicates                           | Uses `consolidation_field`    |
| **Custom**   | Advanced merge/grouping (scanner strategy) | Simple deduplication (key defined in strategy) | Ignores `consolidation_field` |

> **How custom strategies are selected:**
>
> - For OpenVAS, the custom strategy is used only when `allow_duplicates=True` (maximum granularity, recommended for OpenVAS).
> - For Tenable WAS, the custom strategy is used only when `allow_duplicates=False` (smart merge, recommended for Tenable WAS).
> - In all other cases, the default logic using `consolidation_field` is applied.

> `--allow-duplicates` preserves occurrences when repetition represents services, ports, or distinct instances.

> Do not define `consolidation_field` and custom logic together: the system always prioritizes custom logic when the relevant allow_duplicates flag is active for that scanner.

The scanner profile controls how the report will be processed and how vulnerabilities will be grouped.

---

> **Note on deduplication strategies (OpenVAS and Tenable WAS):**
>
> - Custom strategies were created to reduce vulnerability exceedances (i.e., invented or inflated vulnerabilities by the LLM), consolidating findings according to the real structure of each scanner.
> - **OpenVAS:**
>   - `allow_duplicates=True` (**recommended**): uses custom strategy for maximum granularity, removing only exact duplicates (same Name, port, protocol). Useful for detailed analysis.
>   - Note: In OpenVAS, legitimate vulnerabilities may repeat (e.g., on different ports), so "duplicates" are not always 100% identical despite the name.
> - **Tenable WAS:**
>   - `allow_duplicates=False` (**recommended**): uses custom strategy for smart merge, grouping instances/bases of the same type and consolidating arrays (URLs, description, etc.).
>
> These strategies were designed to balance granularity and efficiency, avoiding vulnerability exceedances and respecting the structure/content of each scanner.

---

5. **Testing and validation**

- Run extractions with `main.py` using the new scanner.
- Use `chunk_validator.py` to validate chunk division and data integrity.
- Check if the extracted fields are correct and if the JSON follows the expected standard.

**Practical summary:**
For most cases, just create the template and JSON profile. Optional steps are recommended for scanners with complex reports or specific grouping rules. The system is flexible and uses default logic when there is no customization.

### Adding a new LLM

The system accepts any model compatible with the OpenAI API, just create a JSON configuration file in `src/configs/llms/`.

**Configuration example:**

```json
{
  "api_key": "${API_KEY_ANTHROPIC}",
  "endpoint": "https://api.anthropic.com/v1",
  "model": "claude-3-haiku-20240307",
  "temperature": 0,
  "max_tokens": 4096,
  "timeout": 60,
  "reserve_for_response": 3000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 2396,
  "calculation_formula": "max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer"
}
```

**Important fields:**

- `api_key`: API key (use `${VARIABLE_NAME}` to reference variables from .env)
- `endpoint`: Endpoint URL
- `model`: Model name
- Chunking and safety parameters

**Tested models:**

- OpenAI: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`
- Groq: `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
- Anthropic: `claude-3-haiku`, `claude-3-sonnet`
- DeepSeek: `deepseek-chat`
- Any API compatible with OpenAI

### Extension and validation points

- `src/configs/llms/`: New LLM providers
- `src/configs/scanners/`: New processing strategies
- `src/configs/templates/`: New extraction templates
- `src/converters/`: New export formats

**Automatic validation:**

- Token calculation: automatic for new LLMs
- Template validation: JSON format check
- Scanner test: chunk_validator.py for debugging
- Integration test: end-to-end extraction with real documents

The system was designed to grow organically, maintaining compatibility with existing configurations and facilitating integration of new security tools and LLMs.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).

- **Permitted use:** free for use, modification, distribution, and sublicensing, including for commercial purposes.
- **Notice:** provided "as is", without warranties. The user is responsible for use and secure configuration of data and keys.

See the [LICENSE](LICENSE) file for the full license text.
