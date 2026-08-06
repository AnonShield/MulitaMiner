# Architecture and Code Structure

This document describes the organization and main components of MulitaMiner.

## Project Structure

```
MulitaMiner/
├── main.py                              # Main CLI script (entry point for extraction)
├── requirements.txt                     # Python dependencies
├── README.md                            # Documentation
├── compare_dataset_csv.py               # Dataset comparison utility (CSV analysis)
├── tools/
│   ├── run_experiments.py               # Massive execution and automated evaluation (benchmarks)
│   ├── process_results.py               # Chart and statistics generation (metrics visualization)
│   ├── dataset_generator.py             # Dataset consolidation (CSV/XLSX/JSON/JSONL)
│   ├── batch_pdf_extractor.py           # Batch PDF extraction (processes multiple PDFs)
│   └── chunk_validator.py               # Chunk analysis and validation tool
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
│   ├── scanner_strategies/              # Modular scanner strategies (Strategy Pattern)
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
│       ├── llm_debug.py                 # Debug logging of raw LLM responses
│       ├── pdf_loader.py                # PDF text extraction and layout preservation
│       ├── processing.py                # Response extraction and content sanitization
│       ├── profile_registry.py          # Profile and scanner registration
│       ├── reporting.py                 # Execution summary and final report generation
│       └── tokens_cost.py               # Token usage and cost calculation
├── metrics/
│   ├── __init__.py
│   ├── scorers/                         # Single-owner implementations of each score
│   │   ├── bertscore.py                 # BERTScore F1 (semantic)
│   │   ├── rouge_l.py                   # ROUGE-L (lexical)
│   │   ├── token_f1.py                  # Token overlap
│   │   ├── exact_match.py               # Deterministic field equality
│   │   ├── presence.py                  # Field presence
│   │   └── set_f1.py                    # Set-valued field comparison
│   ├── pipelines/                       # One pipeline per metric family
│   │   ├── compare_extractions.py       # bert / rouge / token_f1 comparison sheets
│   │   ├── coverage.py                  # ERM, hallucination and omission rates
│   │   ├── severity.py                  # Severity confusion matrix and macro F1
│   │   └── schema_check.py              # Canonical V3 schema conformance
│   ├── entity/                          # Field-level precision, recall and F1
│   ├── aggregators/                     # Cross-run and cross-version aggregation
│   │   ├── multi_run.py                 # aggregated_metrics.xlsx per result root
│   │   ├── bootstrap_ci.py              # 95% bootstrap confidence intervals
│   │   ├── version_compare.py           # Wide cross-version table
│   │   └── statistical_tests.py         # Significance tests between versions
│   ├── interrater/                      # Inter-annotator agreement utilities
│   ├── common/                          # Alignment, normalization, shared CLI
│   └── plot/                            # HTML report and PNG chart generation
└── docs/                                # Documentation files
```

## Main Components

### Interface Scripts

- **main.py**: Main CLI with modern arguments and full orchestration
- **chunk_validator.py**: Chunk analysis and validation tool

### Processing System

- **src/utils/processing.py**: Response extraction and content sanitization
- **src/utils/pdf_loader.py**: Optimized text extraction with layout preservation
- **src/utils/chunking.py**: Chunk calculation and optimization logic
- **src/utils/reporting.py**: Final execution summary and report generation

### Specialized Strategies

- **src/scanner_strategies/**: Modular scanner strategies for different report types
  - `base.py`: Base class for scanner strategies
  - `openvas.py`: OpenVAS custom strategy
  - `tenablewas.py`: Tenable WAS custom strategy
  - `registry.py`: Strategy registry (maps scanner to logic)
  - `consolidation.py`: Central consolidation logic

### Configuration System

- **src/configs/llms/**: LLM provider configurations (JSON)
- **src/configs/scanners/**: Scanner processing rules (JSON)
- **src/configs/templates/**: Prompt templates (TXT)

### Export System

- **src/converters/base_converter.py**: Base framework for converters
- **src/converters/csv_converter.py**: CSV/TSV export with customizable settings
- **src/converters/xlsx_converter.py**: Excel export with advanced formatting and automatic cache management

**Cache System**: The XLSX converter automatically caches converted files with the same name as the source JSON:

- `report.json` → `report.xlsx` (created once, reused if JSON unchanged)
- Checks file modification times to determine if reconversion is needed
- Particularly useful for metrics evaluation where multiple runs compare the same extraction

### Metrics System

- **metrics/scorers/**: one module per score (BERTScore, ROUGE-L, Token-F1, exact
  match, presence, set F1). Each score has a single owner, so pipelines never
  reimplement one.
- **metrics/pipelines/**: one pipeline per metric family. `compare_extractions.py`
  produces the comparison sheets consumed by the other pipelines; `coverage.py`
  computes Exact Record Match plus hallucination and omission rates;
  `severity.py` builds the confusion matrix and macro F1; `schema_check.py`
  validates records against the canonical V3 schema.
- **metrics/entity/**: per-field precision, recall and F1 over deterministic fields.
- **metrics/aggregators/**: aggregation across runs and versions, including the
  bootstrap confidence intervals reported in the paper.
- **metrics/common/**: record alignment, normalization and shared CLI parsing.
- **metrics/plot/**: HTML report and PNG charts from the aggregated metrics.

## Key Features

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

### Multi-LLM Support

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
  - `*_duplicates_removed_log.txt`: Vulnerabilities removed as exact duplicates
  - `*_merge_log.txt`: Vulnerabilities actually merged
