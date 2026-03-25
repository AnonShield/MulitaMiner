# Installation Guide

This document provides detailed installation instructions for MulitaMiner.

## System Requirements

- **Python**: 3.8+ (recommended: Python 3.10+)
- **RAM**: 4GB+ recommended for large PDF processing
- **OS**: Windows, Linux, or macOS

## Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AnonShield/MulitaMiner.git
cd MulitaMiner
```

### 2. Virtual Environment (Highly Recommended)

```bash
# Windows
python3 -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Main Python Dependencies

### Core - LLM Framework and Processing

```pip-requirements
langchain>=0.1.0,<0.3.0          # Main framework for LLMs
langchain-openai>=0.1.0,<0.2.0   # OpenAI integration
langchain-core>=0.1.0,<0.2.0     # Langchain core
tiktoken>=0.5.1,<0.7.0           # Tokenization
python-dotenv>=0.21.0            # Environment variables
```

### PDF Processing - Optimized Extraction

```pip-requirements
pdfplumber>=0.10.0,<0.12.0       # PDF text extraction
```

### UI/UX - Progress Bars and Feedback

```pip-requirements
tqdm>=4.0.0,<5.0.0               # Progress bars
```

### Data Processing - Merge and Normalization

```pip-requirements
deepmerge>=1.1.0,<2.0.0          # Dictionary merge
```

### Export Formats - CSV, XLSX

```pip-requirements
pandas>=1.3.0,<3.0.0             # DataFrames and manipulation
openpyxl>=3.0.0,<4.0.0           # Excel export
```

### Metrics Evaluation and Visualization

```pip-requirements
rapidfuzz>=3.0.0,<4.0.0          # Fuzzy matching
bert-score>=0.3.0,<0.4.0         # BERTScore
rouge-score>=0.1.0                # ROUGE
torch>=1.10.0,<3.0.0             # Required for BERTScore
numpy>=1.21.0,<2.0.0             # Numeric operations
matplotlib>=3.4.0,<4.0.0         # Visualization
seaborn>=0.11.0,<1.0.0           # Visualization
```

> **Note:** For XLSX/CSV export and metrics evaluation, install all dependencies above.
> **Note:** The project forces UTF-8 encoding on Windows/Linux to avoid character errors.

## Verifying Installation

After installation, verify that everything is correctly installed:

```bash
# Check Python version
python3 --version

# Check if main dependencies are installed
python3 -c "import langchain; import pdfplumber; import tiktoken; print('Core dependencies OK')"

# Check if metrics dependencies are installed
python3 -c "import bert_score; import rouge_score; print('Metrics dependencies OK')"
```

## Next Steps

After installation:

1. Configure your API keys (see [CONFIG.md](CONFIG.md))
2. Run the minimum test (see [README.md](../README.md#teste-mínimo))
3. Explore usage examples (see [USAGE.md](USAGE.md))
