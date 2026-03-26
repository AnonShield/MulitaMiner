<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_light.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_dark.png">
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

As a key contribution, a dataset of **6,700 vulnerabilities** extracted from **129 OpenVAS reports** is provided, serving as a reference for future research. The dataset was evaluated against ground-truth records via host/IP and vulnerability name matching, achieving **Recall of 96.18%**, **Precision of 91.06%**, and **F1-score of 0.9355**. Additionally, the extraction tool was validated against structured baselines from 3 reports using BERTScore and ROUGE-L semantic similarity metrics.

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
Lista de dependências principais:
langchain>=0.1.0,<0.3.0          # LLM framework
langchain-openai>=0.1.0,<0.2.0   # OpenAI integration
tiktoken>=0.5.1,<0.7.0           # Tokenization
pdfplumber>=0.10.0,<0.12.0       # PDF extraction
python-dotenv>=0.21.0            # Environment variables
tqdm>=4.0.0,<5.0.0               # Progress bars
pandas>=1.3.0,<3.0.0             # Data manipulation
openpyxl>=3.0.0,<4.0.0           # Excel export
```

### Metrics Evaluation (Optional)

```
bert-score>=0.3.0,<0.4.0         # BERTScore
rouge-score>=0.1.0                # ROUGE
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

### 1. Run Extraction

```bash
# Basic extraction using Groq

# Windows
python main.py --input test\openvas\OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test

# Linux/macOS
python main.py --input test/openvas/OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test
```

**Expected result**: openvas_test.json with extracted vulnerabilities and visual_layout.txt file

### 2. Verify Output

Check the generated JSON file for extracted vulnerabilities:

```bash
python tools/summarize_vulnerabilities.py --input openvas_test.json
```

**Expected result**: Terminal print with summary of all extracted vulnerabilities in tabular format.

## Experiments

This section describes how to reproduce the main claims from the paper.

> **Note**: The execution times are based on AMD Ryzen 5 5600G, 32GB RAM, 1TB SSD, Windows 11. Actual times may vary depending on system specifications, network latency, and API response times.

### Claim #1: Multi-LLM Vulnerability Extraction

**Description**: MulitaMiner extracts vulnerabilities from PDF reports using multiple LLM providers (DeepSeek, GPT-4, LLaMa 3, etc).

**Configuration**: Edit `.env` with API keys for desired providers.

**Execution**:

```bash
# Extract using DeepSeek (best cost-benefit in the paper) and other LLMs for comparison

# Windows
python main.py --input test\openvas\OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test_deepseek
python main.py --input test\openvas\OpenVAS_JuiceShop.pdf --llm gpt4 --scanner openvas --allow-duplicates --output-file openvas_test_gpt4
python main.py --input test\openvas\OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test_llama3

# Linux/macOS
python main.py --input test/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test_deepseek
python main.py --input test/openvas/OpenVAS_JuiceShop.pdf --llm gpt4 --scanner openvas --allow-duplicates --output-file openvas_test_gpt4
python main.py --input test/openvas/OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test_llama3
```

**Expected time**: ~12 minutes for all extractions

- Deepseek: ~6 minutes
- GPT4: ~5 minutes
- LLAMA3: ~45 seconds

**Expected result**: openvas_test<llm_name>.json files with extracted vulnerabilities containing fields like `Name`, `description`, `severity`, `cvss`, `port`, `references`, etc.

### Claim #2: Quality Evaluation with BERTScore/ROUGE-L

**Description**: The tool evaluates extraction quality against ground truth baselines using BERTScore and ROUGE-L metrics, with similarity scores categorized as: Highly Similar (≥0.7), Moderately Similar (0.6-0.7), Low Similarity (0.4-0.6), and Divergent (<0.4).

**Execution**:

```bash
# Evaluate with BERTScore and ROUGE-L

# Windows
python metrics/bert/compare_extractions_bert.py --baseline-file test\openvas\OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --model deepseek --output-dir results_bert --allow-duplicates
python metrics/rouge/compare_extractions_rouge.py --baseline-file test\openvas\OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --model deepseek --output-dir results_rouge --allow-duplicates

# Linux/macOS
python metrics/bert/compare_extractions_bert.py --baseline-file test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --model deepseek --output-dir results_bert --allow-duplicates
python metrics/rouge/compare_extractions_rouge.py --baseline-file test/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --model deepseek --output-dir results_rouge --allow-duplicates
```

**Expected time**: ~15 seconds for BERT and ~3 seconds for ROUGE

**Expected result**: XLSX files with BERTScore and ROUGE-L metrics in ./results_bert and ./results_rouge directories.

### Claim #3: Large-Scale Reproducibility

**Description**: MulitaMiner supports batch experiments across multiple reports, LLMs, and runs with checkpoint support to resume interrupted executions.

**Execution**:

```bash
# Run full experiment suite

# Windows
python tools/run_experiments.py --input-dir test\openvas --llms deepseek --scanners openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates true

# Linux/macOS
python tools/run_experiments.py --input-dir test/openvas --llms deepseek --scanners openvas --evaluation-methods bert rouge --runs-per-model 5 --allow-duplicates true
```

**Expected time**: ~40 minutes

**Expected result**: Organized results in `results_runs/` with extracted vulnerabilities (JSON/XLSX per run), BERTScore and ROUGE-L evaluation reports, and a final aggregated report with token usage and cost estimation. Charts and visualizations (heatmaps, stacked similarity plots) are saved in `plot_runs/`.

> **Note**:
> For practical reasons (time, token cost, and infrastructure), this experiment does not use the same set of reports and LLMs as the paper. Here, a simplified version was used: only 1 report and 1 LLM (deepseek), chosen for its cost-effectiveness and performance.

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
