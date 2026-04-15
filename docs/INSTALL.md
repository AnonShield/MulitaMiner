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

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Main Python Dependencies

### Core - LLM Framework and Processing

```pip-requirements
langchain==0.3.28          # Main framework for LLMs
langchain-core==0.3.84     # Langchain core
langchain-openai==0.3.35   # OpenAI integration
langchain-ollama==0.3.10   # Ollama integration
tiktoken==0.12.0           # Tokenization (OpenAI models)
python-dotenv==1.2.2       # Environment variables
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
matplotlib==3.10.8         # Visualization
seaborn==0.13.2            # Visualization
```

### Report Generation

```pip-requirements
jinja2==3.1.6              # HTML report generation
kaleido==1.2.0             # Static image export for charts
```

> **Note:** All versions are pinned in both `pyproject.toml` and `requirements.txt` for stability. `uv sync` reads from `pyproject.toml`; `pip install -r requirements.txt` uses the flat file — both install the same packages.
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

## Next Steps

After installation:

1. Configure your API keys (see [CONFIG.md](CONFIG.md))
2. Run the minimum test (see [README.md](../README.md#minimum-test))
3. Explore usage examples (see [USAGE.md](USAGE.md))
