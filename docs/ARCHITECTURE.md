# Architecture and Code Structure

This document describes the organization and main components of TMM.

## Project Structure

```
TMM/
├── main.py                              # Main CLI script (entry point for a single extraction)
├── requirements.txt                     # Python dependencies (pip)
├── pyproject.toml / uv.lock             # Python dependencies (uv)
├── README.md                            # Documentation
├── tools/
│   ├── run_experiments.py               # Massive execution and automated evaluation (benchmarks)
│   ├── batch_pdf_extractor.py           # Batch PDF extraction (one LLM, all PDFs in a directory)
│   ├── TMM_metrics_run.py               # Consolidated multi-LLM/multi-version metrics report
│   ├── run_metrics.py                   # Post-extraction metrics pass (used by run_experiments.py)
│   ├── process_results.py               # Chart and statistics generation (metrics visualization)
│   ├── plot_evaluation.py               # Additional evaluation plotting
│   ├── dataset_generator.py             # Dataset consolidation (CSV/XLSX/JSON/JSONL)
│   ├── summarize_vulnerabilities.py     # Terminal summary of an extraction JSON
│   ├── chunk_validator.py               # Chunk analysis and validation tool
│   ├── count_loc.py                     # Lines-of-code counter
│   └── _evaluation_common.py            # Shared helpers for the scripts above
├── src/
│   ├── __init__.py
│   ├── configs/
│   │   ├── llms/                        # LLM configurations (10 JSON files: 6 cloud + 4 local)
│   │   ├── scanners/                    # Scanner configurations (JSON: openvas, tenable, nessus, qualys, rapid7, cais_*)
│   │   ├── schema/                      # Canonical field-category schema (JSON)
│   │   └── templates/                   # Prompt templates (TXT, per scanner/format)
│   ├── converters/
│   │   ├── base_converter.py            # Base converter class
│   │   ├── conversions.py               # Shared conversion helpers
│   │   ├── csv_converter.py             # CSV/TSV export logic
│   │   └── xlsx_converter.py            # Excel export logic
│   ├── model_management/                # LLM provider abstraction
│   │   ├── llm_factory.py               # Builds the right client from a config's `provider`
│   │   ├── llm_processing.py            # Request/response orchestration per call
│   │   ├── config_loader.py             # Loads/validates LLM JSON configs (env var substitution)
│   │   ├── prompts.py                   # Prompt assembly
│   │   ├── tokenizer_utils.py           # Tokenizer selection (tiktoken/huggingface)
│   │   ├── validation.py                # Response validation
│   │   └── providers/                   # openai_provider.py, ollama_provider.py, lm_studio_provider.py, huggingface_provider.py, base_provider.py
│   ├── scanner_strategies/              # Modular scanner strategies (Strategy Pattern)
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
│       ├── extractors.py                # Field extraction helpers
│       ├── llm_debug.py                 # Debug logging of raw LLM responses
│       ├── pdf_loader.py                # PDF text extraction and layout preservation (pdfplumber; optional marker-pdf path)
│       ├── processing.py                # Response extraction and content sanitization
│       ├── profile_registry.py          # Profile and scanner registration
│       ├── reporting.py                 # Execution summary and final report generation
│       └── tokens_cost.py               # Token usage and cost calculation
├── metrics/
│   ├── __init__.py
│   ├── scorers/                         # Per-field scoring functions (bertscore, rouge_l, token_f1, set_f1, exact_match, presence)
│   ├── pipelines/                       # compare_extractions.py, coverage.py, schema_check.py, confusion_severity.py
│   ├── aggregators/                     # multi_run.py, version_compare.py, bootstrap_ci.py, statistical_tests.py, discovery.py
│   ├── entity/                          # Entity-level comparison (compare_extractions_entity.py)
│   ├── interrater/                      # Inter-rater agreement (kappa.py)
│   ├── common/                          # aligner.py, matching.py, normalization.py, field_mapper.py, schema_canonicalizer.py, sheet_resolver.py, io.py, cli.py, config.py
│   └── plot/                            # Chart/report generation: charts/ (per chart type), templates/ (jinja2), png.py, report.py, comparison_report.py
├── baselines/                           # Curated ground-truth baselines (PDF + XLSX) used by the minimum test and Claims
├── dockers/                             # The 129 OpenVAS PDF reports used for the V1/V2/V3 experiment
├── artifacts/                           # Per-version extraction datasets and consolidated metrics reports
├── imgs/                                # Documentation images
└── docs/                                # Documentation files
```

## Main Components

### Interface Scripts

- **main.py**: Main CLI with modern arguments and full single-report orchestration
- **tools/batch_pdf_extractor.py**: Runs `main.py` once per PDF in a directory, for one LLM
- **tools/run_experiments.py**: Orchestrates extraction + metrics across multiple LLMs/runs, with checkpoint support
- **tools/chunk_validator.py**: Chunk analysis and validation tool

### Processing System

- **src/utils/processing.py**: Response extraction and content sanitization
- **src/utils/pdf_loader.py**: Optimized text extraction with layout preservation
- **src/utils/chunking.py**: Chunk calculation and optimization logic
- **src/utils/reporting.py**: Final execution summary and report generation

### Model Management

- **src/model_management/llm_factory.py**: Builds the right client for a config's `provider` (OpenAI-compatible API, Ollama, LM Studio, Hugging Face)
- **src/model_management/providers/**: One module per provider backend
- **src/model_management/config_loader.py**: Loads LLM JSON configs from `src/configs/llms/` and substitutes `${API_KEY_*}` from `.env`

### Specialized Strategies

- **src/scanner_strategies/**: Modular scanner strategies for different report types
  - `base.py`: Base class for scanner strategies
  - `openvas.py`: OpenVAS custom strategy
  - `tenablewas.py`: Tenable WAS custom strategy
  - `registry.py`: Strategy registry (maps scanner to logic)
  - `consolidation.py`: Central consolidation logic

### Configuration System

- **src/configs/llms/**: LLM provider configurations (JSON) — 6 cloud (DeepSeek, GPT-4, GPT-5, Llama3, Llama4, Qwen3) + 4 local (Gemma4, Mistral, Qwen3.5 via Ollama; Granite4 via LM Studio)
- **src/configs/scanners/**: Scanner processing rules (JSON)
- **src/configs/schema/**: Canonical field-category schema used by the metrics battery
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

- **metrics/scorers/**: Per-field scoring functions (BERTScore, ROUGE-L, Token-F1, Set-F1, exact match, presence)
- **metrics/pipelines/compare_extractions.py**: Compares one extraction against a baseline, accepting JSON or XLSX (auto-converts JSON to XLSX if needed)
- **metrics/pipelines/coverage.py, confusion_severity.py, schema_check.py**: Coverage, severity confusion matrix, and schema-validity checks
- **metrics/aggregators/**: Cross-run and cross-version aggregation, bootstrap confidence intervals, statistical tests (Wilcoxon)
- **metrics/entity/**: Entity-level (vulnerability-level) comparison
- **metrics/interrater/**: Cohen's kappa for inter-rater agreement on curated baselines
- **metrics/common/**: Shared utilities (alignment, matching, normalization, schema canonicalization, CLI parsing)
- **metrics/plot/**: Chart and HTML report generation

## Key Features

### Intelligent Extraction

- **Automatic extraction** of vulnerabilities from security PDF reports
- **Multi-scanner support**: OpenVAS, Tenable WAS, Nessus, Qualys, Rapid7, and CAIS-normalized variants
- **Automatic validation** of extracted data with normalization
- **Robust retry system** with smart chunk subdivision

### Optimized Chunking System

- **Automatic token calculation** based on each LLM's specific limits
- **Dynamic chunk size optimization** per model
- **Integrated validation** with `tools/chunk_validator.py` for quality analysis

### Advanced Consolidation

- **TenableWAS**: Smart merging of vulnerability instances and base findings
- **OpenVAS**: Grouping by name similarity and characteristics
- **CAIS**: Consolidation by definitions with specialized fields

### Multi-LLM Support

- **10 LLM configurations** in `src/configs/llms/`:
  - **Cloud (API key required)**: DeepSeek, GPT-4, GPT-5, Llama 3, Llama 4, Qwen3 (Groq)
  - **Local (self-hosted, no API key)**: Gemma4, Mistral, Qwen3.5 (Ollama), Granite4 (LM Studio)

### Multi-Format Export and Logs

- **Structured JSON** (main format)
- **CSV/TSV** with customizable delimiters
- **XLSX** (Excel) with advanced formatting
- **Visual layout preserved** in .txt file
- **Detailed logs**:
  - `*_removed_log.txt`: Vulnerabilities removed due to missing description/essential fields
  - `*_duplicates_removed_log.txt`: Vulnerabilities removed as exact duplicates
  - `*_merge_log.txt`: Vulnerabilities actually merged
