<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_light.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_dark.png">
    <img src="imgs/MulitaMiner_logo_light.png" width="500" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

_Automated · Structured · Multi-LLM_

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Last commit](https://img.shields.io/github/last-commit/AnonShield/MulitaMiner)

</div>

# MulitaMiner

**MulitaMiner** is an automated tool for extracting and structuring vulnerabilities from heterogeneous PDF reports produced by security scanners. Its LLM-based pipeline combines adaptive chunking and scanner-aware prompting to convert unstructured findings into consistent, analysis-ready vulnerability records, with standardized outputs and quality validation.

It also supports quality evaluation of the extraction against ground-truth baselines, combining deterministic per-field metrics with semantic similarity (BERTScore and ROUGE-L).

**Use Cases:**

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Enterprise Integration**: Support for CAIS formats for corporate systems
- **Research and Development**: Comparative evaluation of different LLMs

## README Structure

- [Basic Information](#basic-information)
- [Dependencies](#dependencies)
- [Security Concerns](#security-concerns)
- [Installation](#installation)
- [Minimum Test](#minimum-test)
- [Experiments](#experiments)
- [Documentation](#documentation)
- [LICENSE](#license)

## Basic Information

### Execution Environment

| Component   | Requirement                                      |
| ----------- | ------------------------------------------------ |
| **OS**      | Windows 10+, Linux (Ubuntu 20.04+), macOS 10.15+ |
| **Python**  | 3.11+                                            |
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

All dependencies are declared in **`pyproject.toml`** (single source of truth)
and installed with `pip install -e .` — see [Installation](#installation). Key
libraries:

- **Core (extraction)**: `langchain` + `langchain-openai`/`langchain-ollama`, `pdfplumber`, `tiktoken`, `pydantic` (config validation), `python-dotenv`, `pandas` + `openpyxl` (XLSX export), `rapidfuzz`. Kept lean so the common-user setup stays small.
- **Optional extras**: `.[metrics]` (`bert-score`, `rouge-score`, `torch`, `scikit-learn`, `scipy`, `matplotlib`/`seaborn`/`jinja2` — evaluation & charts), `.[marker]` (Marker PDF backend), `.[full]` (= metrics + marker, for research), `.[hf-local]` (local HuggingFace GPU inference), `.[dev]` (pytest, ruff, mypy).

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

### 3. Install the Package

MulitaMiner is an installable package (`src/mulitaminer/`). Install it editable
so `python main.py` and the `tools/` scripts work from anywhere:

```bash
pip install -e .
```

> Core install is **extraction only**. Add extras as needed: `.[metrics]`
> (evaluation + charts), `.[full]` (research = metrics + Marker), `.[metrics,dev]`
> (development — tests cover the metrics package). See [docs/INSTALL.md](docs/INSTALL.md).

### 4. Configure API Keys

Copy the template and fill in your keys (`.env` is gitignored):

```bash
cp .env.example .env
```

```env
API_KEY_GPT4="your-openai-api-key"
API_KEY_LLAMA3="your-groq-api-key"
API_KEY_DEEPSEEK="your-deepseek-api-key"
```

See [docs/CONFIG.md](docs/CONFIG.md) for all configuration options.

## Minimum Test

After installation, run this minimal test to verify the setup:

### 1. Run Extraction

```bash
# Basic extraction using Groq (baselines live under resources/)
python main.py --input resources/baselines/openvas/OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test
```

**Expected result**: `outputs/runs/openvas_test.json` with extracted vulnerabilities,
plus the visual-layout dump in `outputs/visual_layouts/`. (All run artifacts live
under the gitignored `outputs/` tree; a relative `--output-dir` is nested there too.)

### 2. Verify Output

Check the generated JSON file for extracted vulnerabilities:

```bash
python tools/summarize_vulnerabilities.py --input outputs/runs/openvas_test.json
```

**Expected result**: Terminal print with summary of all extracted vulnerabilities in tabular format.

## Experiments

This section shows how to run the tool end-to-end with a few examples.

> **Note**: The execution times are based on AMD Ryzen 5 5600G, 32GB RAM, 1TB SSD, Windows 11. Actual times may vary depending on system specifications, network latency, and API response times.

### Example 1: Multi-LLM Vulnerability Extraction

**Description**: MulitaMiner extracts vulnerabilities from PDF reports using multiple LLM providers (DeepSeek, GPT-4, LLaMa 3, etc).

**Configuration**: Edit `.env` with API keys for desired providers.

**Execution**:

```bash
# Extract using DeepSeek (best cost-benefit in the paper) and other LLMs for comparison
python main.py --input resources/baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test_deepseek
python main.py --input resources/baselines/openvas/OpenVAS_JuiceShop.pdf --llm gpt4 --scanner openvas --allow-duplicates --output-file openvas_test_gpt4
python main.py --input resources/baselines/openvas/OpenVAS_JuiceShop.pdf --llm llama3 --scanner openvas --allow-duplicates --output-file openvas_test_llama3
```

**Expected time**: ~12 minutes for all extractions

- Deepseek: ~6 minutes
- GPT4: ~5 minutes
- LLAMA3: ~45 seconds

**Expected result**: openvas_test<llm_name>.json files with extracted vulnerabilities containing fields like `Name`, `description`, `severity`, `cvss`, `port`, `references`, etc.

### Example 2: Quality Evaluation with BERTScore/ROUGE-L

**Description**: The tool evaluates extraction quality against ground truth baselines using BERTScore and ROUGE-L metrics, with similarity scores categorized as: Highly Similar (≥0.7), Moderately Similar (0.6-0.7), Low Similarity (0.4-0.6), and Divergent (<0.4).

**Execution**:

Metrics run **inline** during extraction — pass `--metrics` plus the ground-truth
`--baseline-path`. (The standalone `metrics/bert/…`/`metrics/rouge/…` scripts were
unified into `metrics/pipelines/compare_extractions.py`, dispatched by name.)

```bash
# Extract + evaluate with BERTScore and ROUGE-L in one command
python main.py --input resources/baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates \
    --output-file openvas_test_deepseek \
    --baseline-path resources/baselines/openvas/OpenVAS_JuiceShop.xlsx \
    --metrics bert rouge
```

Use `--metrics all` for the full suite (schema, bert, rouge, token_f1, field_f1,
severity, coverage). To (re-)run metrics on an existing results tree without
re-calling the LLM, use `python tools/run_metrics.py --root <dir> --methods all`.

**Expected time**: ~15 seconds for BERT and ~3 seconds for ROUGE

**Expected result**: BERTScore and ROUGE-L XLSX reports written next to the
extraction JSON under `outputs/runs/`.

### Example 3: Large-Scale Reproducibility

**Description**: MulitaMiner supports batch experiments across multiple reports, LLMs, and runs with checkpoint support to resume interrupted executions.

**Execution**:

```bash
# Run full experiment suite (point --input-dir at a folder of matching .pdf/.xlsx pairs)
python tools/run_experiments.py --input-dir resources/baselines/openvas --llm deepseek --scanner openvas --metrics bert rouge --runs-per-model 5 --allow-duplicates
```

**Expected time**: ~40 minutes

**Expected result**: Organized results in `outputs/runs/` with extracted vulnerabilities (JSON per run; pass `--convert xlsx` to also emit XLSX), BERTScore and ROUGE-L evaluation reports, an `aggregated_metrics.xlsx` summary, and a Markdown final report with token usage and cost estimation. Charts and the interactive HTML report are saved in `outputs/plots/`.

> **Note**:
> For practical reasons (time, token cost, and infrastructure), this experiment does not use the same set of reports and LLMs as the paper. Here, a simplified version was used: only 1 report and 1 LLM (deepseek), chosen for its cost-effectiveness and performance.

---

For detailed experiment configurations and paper results, see [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).

## Documentation

Detailed documentation is organized in separate files:

| Document                                           | Description                          |
| -------------------------------------------------- | ------------------------------------ |
| [docs/INSTALL.md](docs/INSTALL.md)                 | Detailed installation guide          |
| [docs/DOCKER.md](docs/DOCKER.md)                   | Running the two Docker images        |
| [docs/USAGE.md](docs/USAGE.md)                     | Complete usage guide with examples   |
| [docs/CONFIG.md](docs/CONFIG.md)                   | API keys and token configuration     |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)       | Code structure and components        |
| [docs/PRIORITIZATION.md](docs/PRIORITIZATION.md)   | Remediation queue: KEV/EPSS + SSVC   |
| [docs/EXTENSIBILITY.md](docs/EXTENSIBILITY.md)     | Adding new scanners and LLMs         |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors and optimization tips  |
| [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)         | Experimental validation details      |
| [docs/INVENTORY.md](docs/INVENTORY.md)             | Container inventory and distribution |

## LICENSE

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

- **Permitted use**: Free for use, modification, distribution, and sublicensing, including for commercial purposes.
- **Notice**: Provided "as is", without warranties. The user is responsible for use and secure configuration of data and keys.

See the [LICENSE](LICENSE) file for the full license text.
