# Architecture and Code Structure

This document describes the organization and main components of MulitaMiner.

## Project Structure

```
MulitaMiner/
├── main.py                          # thin entry point → mulitaminer.cli:main
├── pyproject.toml                   # dependencies + tooling (single source of truth)
├── .env.example                     # API-key template (copy to .env)
├── README.md  CLAUDE.md  LICENSE
│
├── src/mulitaminer/                 # the installable package (pip install -e .)
│   ├── cli.py                       # parse args, validate, dispatch
│   ├── cli_args.py                  # argparse definitions (+ --output-dir nesting under outputs/)
│   ├── pipeline/                    # end-to-end extraction
│   │   ├── orchestrator.py          # run_extraction: input → blocks → chunks → LLM → JSON
│   │   ├── save.py                  # consolidate + filter + dump
│   │   └── metrics_dispatch.py      # METRIC_SCRIPTS registry + run_metrics_only
│   ├── readers/                     # input formats — Open/Closed via a registry
│   │   ├── base.py                  # InputReader ABC + RawDocument + get_reader()
│   │   ├── pdf.py                   # PdfReader (@register for .pdf)
│   │   ├── extractors.py            # pdfplumber / marker PDF backends
│   │   └── pdf_extraction.py            # PDF text + visual-layout extraction
│   ├── chunking/                    # split block text into LLM-sized chunks
│   │   ├── tokens.py                # TokenChunk, splitters, build_prompt, smart_chunk_vulnerabilities
│   │   ├── retry.py                 # invoke + validate + retry/redivide
│   │   ├── errors.py                # fatal-API-error detection (quota/auth → re-raise)
│   │   └── block_creation.py        # session blocks from extracted text
│   ├── llm/                         # providers + config + prompts (was model_management)
│   │   ├── config_loader.py         # load_llm / load_profile (+ pydantic validation)
│   │   ├── llm_factory.py  prompts.py  validation.py  tokenizer_utils.py
│   │   └── providers/               # openai, ollama, lm_studio, huggingface
│   ├── scanners/                    # scanner strategies (was scanner_strategies)
│   │   └── base.py  registry.py  consolidation.py  openvas.py  tenablewas.py
│   ├── writers/                     # output formats (was converters): csv, xlsx, conversions
│   ├── validators/                  # cais_validator.py
│   ├── reporting/                   # final report, tokens_cost (+ LLM_PRICES), llm_debug, usage_log
│   ├── experiments/                 # runner.py + checkpoint.py (batch experiment runs)
│   ├── utils/                       # gpu_sampler.py (residual)
│   └── configs/
│       ├── constants.py             # SSOT: output paths + chunking tunables
│       ├── schemas.py               # pydantic LLMConfig / ScannerConfig
│       └── llms/  scanners/  prompts/  schema/   # JSON configs + TXT prompts
│
├── metrics/                         # independent evaluation subsystem (no package dep)
│   ├── scorers/                     # bertscore, rouge_l, token_f1, set_f1, exact_match, presence
│   ├── pipelines/                   # compare_extractions (unified bert/rouge/token_f1),
│   │                                #   coverage, schema_check, confusion_severity
│   ├── entity/  interrater/  aggregators/  common/
│   └── plot/                        # charts/ + report builders + metrics.py CLI
│
├── tools/                           # thin CLI scripts (logic lives in the package)
│   ├── run_experiments.py  run_metrics.py  batch_pdf_extractor.py
│   └── chunk_validator.py  summarize_vulnerabilities.py  dataset_generator.py
├── tests/                           # pytest (unit + MockLLM)
├── resources/baselines/            # ground-truth baselines (<scanner>/<target>.xlsx + .pdf)
├── outputs/                        # ALL run artifacts (gitignored)
│   └── runs/ tokens/ visual_layouts/ debug/ plots/ checkpoints/ tmp/
├── archive/                        # parked notes + raw data (gitignored)
└── docs/                           # this documentation
```

## Main Components

### Interface Scripts

- **main.py**: 12-line wrapper around `mulitaminer.cli:main`
- **mulitaminer/cli.py**: arg parsing, validation, dispatch (extraction vs `--metrics-only`)
- **mulitaminer/pipeline/orchestrator.py**: the full extraction flow
- **tools/chunk_validator.py**: chunk analysis and validation tool

### Processing System

- **mulitaminer/readers/**: input layer — `get_reader(path)` dispatches by extension to a `RawDocument` (PDF today; CSV/XML/JSON are additive)
- **mulitaminer/chunking/**: `tokens.py` (split + prompt build), `retry.py` (invoke/validate/redivide), `errors.py` (fatal-error detection)
- **mulitaminer/pipeline/save.py**: consolidation, validity filtering, JSON dump
- **mulitaminer/reporting/**: execution summary + Markdown final report, token/cost accounting

### Specialized Strategies

- **mulitaminer/scanners/**: modular scanner strategies for different report types
  - `base.py`: base class for scanner strategies
  - `openvas.py` / `tenablewas.py`: scanner-specific strategies
  - `registry.py`: strategy registry (maps scanner → logic)
  - `consolidation.py`: central consolidation logic

### Configuration System

- **mulitaminer/configs/llms/**: LLM provider configurations (JSON)
- **mulitaminer/configs/scanners/**: scanner processing rules (JSON)
- **mulitaminer/configs/prompts/**: prompt templates (TXT)
- **mulitaminer/configs/{constants,schemas}.py**: tunable-constant SSOT + pydantic config validation

### Export System

- **mulitaminer/writers/**: output-format writers (was `converters/`)
  - `csv_converter.py`: CSV/TSV export with customizable settings
  - `xlsx_converter.py`: Excel export with advanced formatting and automatic cache management
  - `conversions.py`: dispatch for `--convert`

**Cache System**: The XLSX converter automatically caches converted files with the same name as the source JSON:

- `report.json` → `report.xlsx` (created once, reused if JSON unchanged)
- Checks file modification times to determine if reconversion is needed
- Particularly useful for metrics evaluation where multiple runs compare the same extraction

### Metrics System

The `metrics/` package is independent of `mulitaminer` (it consumes extraction
JSON/XLSX, not the package internals).

- **metrics/scorers/**: pure `score(pred, ref)` functions — `bertscore`, `rouge_l`, `token_f1`, `set_f1`, `exact_match`, `presence`
- **metrics/pipelines/**: `compare_extractions.py` (unified — runs any scorer via `--scorer`, replacing the old `metrics/bert` + `metrics/rouge` scripts), plus `coverage.py`, `schema_check.py`, `confusion_severity.py`
- **metrics/entity/**, **metrics/interrater/**: field-level F1 and inter-annotator agreement
- **metrics/aggregators/**: multi-run aggregation + statistical tests
- **metrics/common/**: shared IO, aligner, field mapping
- **metrics/plot/**: `charts/` + the HTML report builders, driven by `metrics.plot.metrics`

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
