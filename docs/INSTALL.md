# Installation Guide

This document provides detailed installation instructions for MulitaMiner.

## System Requirements

- **Python**: 3.11+
- **RAM**: 4GB+ recommended for large PDF processing
- **OS**: Windows, Linux, or macOS

## Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AnonShield/MulitaMiner.git
cd MulitaMiner
```

### 2. Install Dependencies

#### Recommended: uv (fast, modern Python package manager)

[uv](https://docs.astral.sh/uv/) automatically creates the virtual environment and installs all dependencies in one command:

```bash
# Install uv (if not already installed)

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```bash
# Create virtual environment and install all dependencies
uv sync
```

```bash
# Activate the virtual environment

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

#### Alternative: pip + venv

The project is an installable package, so install it editable with `pip install -e .`
(this reads `pyproject.toml` and also makes `import mulitaminer` work everywhere):

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate
pip install -e .

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional extras: `pip install -e ".[dev]"` (pytest/ruff/mypy) and
`pip install -e ".[hf-local]"` (local HuggingFace GPU inference).

## Main Python Dependencies

### Core - LLM Framework and Processing

```pip-requirements
langchain==0.3.28          # Main framework for LLMs
langchain-core==0.3.84     # Langchain core
langchain-openai==0.3.35   # OpenAI integration
langchain-ollama==0.3.10   # Ollama integration
tiktoken==0.12.0           # Tokenization (OpenAI models)
python-dotenv==1.2.2       # Environment variables
pydantic>=2,<3             # Config validation (fail-fast on malformed JSON)
```

### PDF Processing - Optimized Extraction

```pip-requirements
pdfplumber==0.11.9         # PDF text extraction
```

### UI/UX - Progress Bars and Feedback

```pip-requirements
tqdm==4.67.3               # Progress bars
```

### Data Processing - Merge and Normalization

```pip-requirements
deepmerge==1.1.1           # Dictionary merge
```

### Export Formats - CSV, XLSX

```pip-requirements
pandas==2.3.3              # DataFrames and manipulation
openpyxl==3.1.5            # Excel export
```

### Metrics Evaluation and Visualization

```pip-requirements
rapidfuzz==3.14.5          # Fuzzy matching
bert-score==0.3.13         # BERTScore
rouge-score==0.1.2         # ROUGE
torch==2.11.0              # Required for BERTScore
numpy==1.26.4              # Numeric operations
scikit-learn==1.8.0        # ML utilities (BERTScore dependency)
scipy==1.13.1              # Wilcoxon stats + Hungarian matching
matplotlib==3.10.8         # Visualization
seaborn==0.13.2            # Visualization
```

### Report Generation

```pip-requirements
jinja2==3.1.6              # HTML report generation
kaleido==1.2.0             # Static image export for charts
```

> **Note:** All versions are pinned in `pyproject.toml` (the single source of truth; `requirements.txt` was removed). `uv sync` and `pip install -e .` both read it. The deterministic lock for paper reproducibility lives in `uv.lock`.
> **Note:** The project forces UTF-8 encoding on Windows/Linux to avoid character errors.

## Verifying Installation

After installation, verify that everything is correctly installed:

```bash
# Check Python version

# Windows
python --version

# Linux/macOS
python3 --version
```

```bash
# Check if main dependencies are installed

# Windows
python -c "import langchain; import pdfplumber; import tiktoken; print('Core dependencies OK')"

# Linux/macOS
python3 -c "import langchain; import pdfplumber; import tiktoken; print('Core dependencies OK')"
```

```bash
# Check if metrics dependencies are installed

# Windows
python -c "import bert_score; import rouge_score; print('Metrics dependencies OK')"

# Linux/macOS
python3 -c "import bert_score; import rouge_score; print('Metrics dependencies OK')"
```

## Development (tests & linting)

Install the dev tools (pytest, ruff, mypy) and run them from the project root.
There's no wrapper script — `pytest` is configured in `pyproject.toml`, so it
finds the suite on its own.

The test suite exercises the `metrics.*` package too, so development needs the
`metrics` extra alongside `dev`:

```bash
pip install -e ".[metrics,dev]"      # or: uv sync --extra metrics --extra dev

# Run the test suite
python -m pytest             # all tests
python -m pytest -v          # verbose (one line per test)
python -m pytest tests/unit/test_chunking.py   # a single file
python -m pytest --cov=mulitaminer             # with coverage

# Lint (static analysis — does not run the code)
ruff check src tests         # report issues
ruff check . --fix           # auto-fix what it can
```

### Dependency extras

Core install (`pip install .`) is **extraction only** — kept lean. Heavier
capabilities are opt-in extras:

| Extra | Adds | Use it for |
|-------|------|------------|
| _(none)_ | extraction runtime | running `main.py` against a PDF |
| `metrics` | BERTScore/ROUGE/torch, charts, stats | `tools/run_metrics.py`, experiments, plots |
| `marker` | Marker PDF backend | the `--md` extraction path |
| `full` | `metrics` + `marker` | research (everything above) |
| `hf-local` | transformers/accelerate/bitsandbytes | running HF models in-process on a GPU |
| `dev` | pytest/ruff/mypy | development |

## Docker

Two images are built from a single `Dockerfile` (select with `--target`):

```bash
# Common-user image — extraction only, lean (no metrics/ML stack):
docker build --target extraction -t mulitaminer:extraction .

# Research image — extraction + experiments + metrics + charts + Marker.
# Torch defaults to CPU; add --build-arg TORCH_INDEX=.../cu128 for a GPU build:
docker build --target full -t mulitaminer:full .
```

Run it — API keys come in at runtime (never baked into the image), inputs and
outputs are bind-mounted:

```bash
docker run --rm --env-file .env \
  -v "$PWD/input:/app/input" -v "$PWD/outputs:/app/outputs" \
  mulitaminer:extraction --input /app/input/report.pdf --scanner openvas --llm gpt4
```

The `full` image runs any script (`ENTRYPOINT python`), e.g.
`docker run --rm mulitaminer:full tools/run_experiments.py ...`.

See [DOCKER.md](DOCKER.md) for the full guide — API keys, custom LLM/scanner
configs without rebuilding (`MULITA_CONFIG_DIR`), and local-LLM networking.

## Next Steps

After installation:

1. Configure your API keys (see [CONFIG.md](CONFIG.md))
2. Run the minimum test (see [README.md](../README.md#minimum-test))
3. Explore usage examples (see [USAGE.md](USAGE.md))
