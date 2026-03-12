# Architecture and Code Structure

This document describes the organization and main components of MulitaMiner.

## Project Structure

```
MulitaMiner/
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
├── results_runs_xlsx/                   # XLSX results (run_experiments.py)
├── plot_runs/                           # Generated charts (metrics visualization)
└── temp_blocks/                         # Temporary vulnerability blocks (intermediate parsing)
```

## Main Components

### Interface Scripts

- **main.py**: Main CLI with modern arguments and full orchestration
- **chunk_validator.py**: Chunk analysis and validation tool

### Processing System

- **src/utils/processing.py**: Chunking engine with automatic token calculation
- **src/utils/llm_utils.py**: Smart LLM loading with optimized configurations per model
- **src/utils/pdf_loader.py**: Optimized text extraction with layout preservation
- **src/utils/chunking.py**: Chunk calculation and optimization logic

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
- **src/converters/xlsx_converter.py**: Excel export with advanced formatting

### Metrics System

- **metrics/bert/**: BERTScore evaluation
- **metrics/rouge/**: ROUGE evaluation
- **metrics/common/**: Shared utilities (normalization, matching)
- **metrics/plot/**: Chart generation

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
