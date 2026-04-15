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
├── dataset/                             # Datasets generated (CSV, XLSX, JSON, JSONL)
├── jsons/                               # JSONs used in the dataset generation
├── results_tokens/                      # Token files per LLM (token/cost analysis)
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

- **metrics/bert/**: BERTScore F1 evaluation (semantic similarity via transformer embeddings)
  - Accepts JSON or XLSX inputs (auto-converts JSON to XLSX if needed)
  - Outputs standardized comparison sheets with per-vulnerability and aggregate statistics
- **metrics/rouge/**: ROUGE-L evaluation (longest common subsequence-based metrics)
  - Accepts JSON or XLSX inputs (auto-converts JSON to XLSX if needed)
  - Provides token-level similarity assessment
- **metrics/common/**: Shared utilities (normalization, matching, CLI parsing)
- **metrics/plot/**: Chart generation with visualization of model comparison

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
