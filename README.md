<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/MulitaMiner_logo_light.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/MulitaMiner_logo_dark.png">
    <img src="assets/MulitaMiner_logo_light" width="500" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

_Automated · Structured · Multi-LLM_

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-orange)
![update](https://img.shields.io/badge/last%20update-Mar%202026-lightgrey)

</div>

# MulitaMiner

**MulitaMiner** is an automated tool for extracting and structuring vulnerabilities from heterogeneous PDF reports produced by security scanners. Its LLM-based pipeline combines adaptive chunking and scanner-aware prompting to convert unstructured findings into consistent, analysis-ready vulnerability records, with standardized outputs and quality validation.

As a key contribution, a dataset of approximately **6,700 vulnerabilities** extracted from **129 OpenVAS reports** is provided, demonstrating the tool's capability and serving as a reference for future research. Extraction quality was validated against structured baselines using BERTScore and ROUGE-L metrics, achieving **Recall of 96.18%**, **Precision of 91.06%**, and **F1-score of 0.9355**.

**Use Cases:**

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Enterprise Integration**: Support for CAIS formats for corporate systems
- **Research and Development**: Comparative evaluation of different LLMs

## README Structure

- [Considered Badges](#considered-badges)
- [Basic Information](#basic-information)
- [Dependencies](#dependencies)
- [Security Concerns](#security-concerns)
- [Installation](#installation)
- [Minimum Test](#minimum-test)
- [Experiments](#experiments)
- [Documentation](#documentation)
- [LICENSE](#license)

## Considered Badges

The following badges are considered for evaluation: **Available**, **Functional**, **Sustainable**, and **Reproducible**.

## Basic Information

### Execution Environment

| Component   | Requirement                                      |
| ----------- | ------------------------------------------------ |
| **OS**      | Windows 10+, Linux (Ubuntu 20.04+), macOS 10.15+ |
| **Python**  | 3.8+ (recommended: 3.10+)                        |
| **RAM**     | 4GB+ (8GB recommended for large PDFs)            |
| **Disk**    | 500MB for dependencies + space for outputs       |
| **Network** | Internet connection required for LLM API calls   |

### Supported LLMs

| Provider | Models                |
| -------- | --------------------- |
| OpenAI   | GPT-4, GPT-5          |
| Groq     | Llama3, Llama4, Qwen3 |
| DeepSeek | deepseek-chat         |

## Dependencies

### Main Dependencies

```
langchain>=0.1.0,<0.3.0          # LLM framework
langchain-openai>=0.1.0,<0.2.0   # OpenAI integration
tiktoken>=0.5.1,<0.7.0           # Tokenization
pdfplumber>=0.10.0,<0.12.0       # PDF extraction
python-dotenv>=0.21.0,<2.0.0     # Environment variables
tqdm>=4.0.0,<5.0.0               # Progress bars
pandas>=1.3.0,<3.0.0             # Data manipulation
openpyxl>=3.0.0,<4.0.0           # Excel export
```

### Metrics Evaluation (Optional)

```
bert-score>=0.3.0,<0.4.0         # BERTScore
rouge-score>=0.1.0,<0.2.0        # ROUGE
torch>=1.10.0,<3.0.0             # PyTorch (required for BERTScore)
rapidfuzz>=3.0.0,<4.0.0          # Fuzzy matching
```

**Third-party resources:**

- LLM API keys from providers (OpenAI, Groq, DeepSeek)
- Sample PDF reports from security scanners (OpenVAS, Tenable WAS)

See [docs/INSTALL.md](docs/INSTALL.md) for complete dependency details.

## Security Concerns

**API Keys**: The tool requires LLM API keys configured in a `.env` file. Never commit this file to public repositories.

**PDF Processing**: The tool processes PDF files locally. No data is sent to external services except for the LLM API calls (text chunks for vulnerability extraction).

**Network**: The tool makes HTTPS requests to LLM APIs. Ensure your network allows outbound connections to:

- `api.openai.com` (OpenAI)
- `api.groq.com` (Groq)
- `api.deepseek.com` (DeepSeek)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AnonShield/MulitaMiner.git
cd MulitaMiner
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

Create/edit the `.env` file:

```env
API_KEY_GPT4 = "your-openai-api-key"
API_KEY_LLAMA3 = "your-groq-api-key"
API_KEY_DEEPSEEK = "your-deepseek-api-key"
```

See [docs/CONFIG.md](docs/CONFIG.md) for all configuration options.

## Minimum Test

After installation, run this minimal test to verify the setup:

### 1. Verify Dependencies

```bash
python -c "import langchain; import pdfplumber; import tiktoken; print('Dependencies OK')"
```

### 2. Run Extraction (with sample PDF)

```bash
# Basic extraction using Groq
python main.py pdfs/sample_report.pdf --scanner openvas --llm llama3

# Expected output:
# - JSON file with extracted vulnerabilities
# - Visual layout .txt file
```

### 3. Verify Output

Check the generated JSON file for extracted vulnerabilities:

```bash
# Windows
type openvas_sample_report.json

# Linux/Mac
cat openvas_sample_report.json
```

**Expected result**: JSON array with vulnerability objects containing fields like `Name`, `description`, `severity`, `cvss`, etc.

### 4. Test with Metrics (Optional)

```bash
python main.py pdfs/sample_report.pdf --scanner openvas --llm llama3 --evaluate --baseline-file metrics/baselines/openvas/sample_baseline.xlsx
```

## Experiments

This section describes how to reproduce the main claims from the paper.

### Claim #1: Multi-LLM Vulnerability Extraction

**Description**: MulitaMiner extracts vulnerabilities from PDF reports using multiple LLM providers (DeepSeek, GPT-4/5, LLaMa 3/4) with optimized chunking.

**Configuration**: Edit `.env` with API keys for desired providers.

**Execution**:

```bash
# Extract using DeepSeek (best cost-benefit in the paper)
python main.py pdfs/OpenVAS_JuiceShop.pdf --scanner openvas --llm deepseek --convert xlsx

# Extract using other LLMs for comparison
python main.py pdfs/OpenVAS_JuiceShop.pdf --scanner openvas --llm gpt4 --convert xlsx
python main.py pdfs/OpenVAS_JuiceShop.pdf --scanner openvas --llm llama3 --convert xlsx
```

**Expected time**: 2-10 minutes per PDF (depends on size and LLM)

**Expected resources**: ~500MB RAM, network bandwidth for API calls

**Expected result**: JSON/XLSX files with extracted vulnerabilities containing fields like `Name`, `description`, `severity`, `cvss`, `port`, `references`, etc.

### Claim #2: Quality Evaluation with BERTScore/ROUGE-L

**Description**: The tool evaluates extraction quality against ground truth baselines using BERTScore and ROUGE-L metrics, with similarity scores categorized as: Highly Similar (≥0.7), Moderately Similar (0.6-0.7), Low Similarity (0.4-0.6), and Divergent (<0.4).

**Configuration**: Baseline files are in `metrics/baselines/openvas/`.

**Execution**:

```bash
# Extract and evaluate with BERTScore
python main.py pdfs/OpenVAS_JuiceShop.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --evaluation-method bert

# Or evaluate with ROUGE-L
python main.py pdfs/OpenVAS_JuiceShop.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --evaluation-method rouge
```

**Expected time**: 2-10 minutes for extraction + ~30 seconds for evaluation

**Expected resources**: ~2GB RAM (for BERTScore model loading)

**Expected result**: Similarity metrics printed to console showing distribution across categories, with DeepSeek achieving consistently high scores.

### Claim #3: Large-Scale Reproducibility with Checkpointing

**Description**: MulitaMiner supports batch experiments across multiple reports, LLMs, and runs with checkpoint support to resume interrupted executions.

**Configuration**: Edit `tools/run_experiments.py` to configure baselines, LLMs, scanners, and number of runs.

**Execution**:

```bash
# Run full experiment suite (creates checkpoint automatically)
python tools/run_experiments.py

# Resume interrupted execution from checkpoint
python tools/run_experiments.py --checkpoint-file run_checkpoints_YYYY-MM-DDTHH-MM-SS.json

# Generate similarity distribution charts
python tools/process_results.py
```

**Expected time**: Varies by configuration (hours for full paper reproduction)

**Expected resources**: ~2GB RAM, stable network connection

**Expected result**: Organized results in `results_runs/` and `results_runs_xlsx/`, similarity charts in `plot_runs/`.

---

For detailed experiment configurations and paper results, see [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).

## Documentation

Detailed documentation is organized in separate files:

| Document                                           | Description                         |
| -------------------------------------------------- | ----------------------------------- |
| [docs/INSTALL.md](docs/INSTALL.md)                 | Detailed installation guide         |
| [docs/USAGE.md](docs/USAGE.md)                     | Complete usage guide with examples  |
| [docs/CONFIG.md](docs/CONFIG.md)                   | API keys and token configuration    |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)       | Code structure and components       |
| [docs/EXTENSIBILITY.md](docs/EXTENSIBILITY.md)     | Adding new scanners and LLMs        |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors and optimization tips |
| [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)         | Experimental validation details     |

## LICENSE

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

- **Permitted use**: Free for use, modification, distribution, and sublicensing, including for commercial purposes.
- **Notice**: Provided "as is", without warranties. The user is responsible for use and secure configuration of data and keys.

See the [LICENSE](LICENSE) file for the full license text.
