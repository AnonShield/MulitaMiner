<div align="center">


**MulitaMiner: An LLM-Based Tool for Structuring Vulnerability
Scanner Reports**

_Automated · Structured · Multi-LLM_

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-orange)
![update](https://img.shields.io/badge/last%20update-Aug%202026-lightgrey)

[![Watch the demo video](https://img.youtube.com/vi/HHt8c_PofC0/maxresdefault.jpg)](https://www.youtube.com/watch?v=HHt8c_PofC0)

</div>


**MulitaMiner** Vulnerability scanners produce heterogeneous, vendor-specific PDF
reports that hinder automated analysis and vulnerability management. We present
MulitaMiner, an open-source tool that uses LLMs to extract structured records from these
reports into a canonical 18-field schema via a segment-prompt-validate pipeline.
Evaluated on 129 OpenVAS reports (6,343 findings) across three pipeline versions
and five LLMs, MulitaMiner raises aggregate correctness from 67.5% to 78.3% and cuts
omission from 14.1% to 2.8%; DeepSeek offers the best balance, tying for the
lowest omission (2.7%) and posting the lowest hallucination (4.1%). MulitaMiner turns
archived scanner PDFs into queryable data for CSIRT triage, prioritization, and
tracking.




**Use Cases:**

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Research and Development**: Comparative evaluation of different LLMs

## README Structure

- [Considered Badges](#considered-badges)
- [Repository Structure](#repository-structure)
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

## Repository Structure

| Path            | Description                                                          |
| ---------------- | --------------------------------------------------------------------- |
| `main.py`        | CLI entry point for a single PDF extraction                          |
| `src/`           | Extraction pipeline: LLM/scanner configs, converters, scanner strategies, chunking and PDF-loading utilities |
| `metrics/`       | Evaluation battery: scorers, comparison pipelines, aggregators, entity/inter-rater checks, plotting |
| `tools/`         | Orchestration scripts: batch extraction, consolidated metrics report, dataset/report generation |
| `docs/`          | Detailed documentation (installation, usage, architecture, experiments, etc.) |
| `baselines/`     | Curated ground-truth baselines (PDF + XLSX) used by the minimum test and Claims |
| `dockers/`       | The 129 OpenVAS PDF reports used for the multi-version (V1/V2/V3) experiment |
| `artifacts/`     | Per-version extraction datasets and consolidated metrics reports (`v1/`, `v2/`, `v3/`) |
| `imgs/`          | Documentation images                                                  |

## Basic Information

### Execution Environment

| Component   | Requirement                                      |
| ----------- | ------------------------------------------------ |
| **OS**      | Windows 10+, Linux (Ubuntu 20.04+), macOS 10.15+ |
| **Python**  | 3.11+                                             |
| **RAM**     | 4GB+ (8GB recommended for large PDFs)            |
| **Disk**    | 500MB for dependencies + space for outputs       |
| **Network** | Internet connection required for LLM API calls   |

### Supported LLMs

**Cloud (API key required):**

| Provider | Models                              |
| -------- | ------------------------------------ |
| OpenAI   | GPT-4 (`gpt-4o-mini`), GPT-5 (`gpt-5-mini`) |
| Groq     | Llama3, Llama4, Qwen3                |
| DeepSeek | `deepseek-coder`                     |

**Local (no API key; requires a local server running):**

| Provider  | Models                          |
| --------- | -------------------------------- |
| Ollama    | Gemma4, Mistral, Qwen3.5         |
| LM Studio | Granite4                         |

Local models are not required to reproduce the paper's claims; see [docs/EXTENSIBILITY.md](docs/EXTENSIBILITY.md) for provider details.

## Dependencies

### Main Dependencies

```
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
rouge-score>=0.1.0               # ROUGE
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

```git clone -b MulitaMiner-TMM https://github.com/tooltmm-png/TMM.git```

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

Copy `.env.example` to `.env` and fill in the key(s) for the provider(s) you'll use:

```bash
cp .env.example .env
```

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"
```

> **For reviewers**: the DeepSeek API key used to produce the results in the paper is provided in the appendix submitted to HotCRP, and can also be requested through the HotCRP messaging channel. Only a DeepSeek key is needed to reproduce Claims #1 and #2 below (Claim #3 uses pre-computed CSVs and makes no API calls).

See [docs/CONFIG.md](docs/CONFIG.md) for all configuration options.

## Minimum Test

After installation, run this minimal test to verify the setup:

### 1. Run Extraction

```bash
# Basic extraction using DEEPSEEK

# Windows
python main.py --input baselines\openvas\OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test

# Linux/macOS
python3 main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test
```

**Expected result**: openvas_test.json with extracted vulnerabilities and visual_layout.txt file

### 2. Verify Output

Check the generated JSON file for extracted vulnerabilities:

```bash
# Windows
python tools/summarize_vulnerabilities.py --input openvas_test.json

# Linux/macOS
python3 tools/summarize_vulnerabilities.py --input openvas_test.json
```

**Expected result**: Terminal print with summary of all extracted vulnerabilities in tabular format.

## Experiments

This section describes how to reproduce the main claims from the paper.

> **Note**: The execution times are based on AMD Ryzen 5 5600G, 32GB RAM, 1TB SSD, Windows 11. Actual times may vary depending on system specifications, network latency, and API response times.

> **For reviewers**: Claims #1 and #2 require a DeepSeek API key (see [Configure API Keys](#4-configure-api-keys)); Claim #3 needs no API key.

### Claim #1: Multi-LLM Vulnerability Extraction

**Description**: MulitaMiner extracts vulnerabilities from PDF reports using multiple LLM providers (DeepSeek, GPT-4, LLaMa 3, etc). The test report is OWASP Juice Shop (34 vulnerabilities in the curated baseline).

**Configuration**: Edit `.env` with API keys for desired providers.

**Execution**:

```bash
# Extract using DeepSeek (best cost-benefit in the paper)

# Windows
python main.py --input baselines\openvas\OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test_deepseek

# Linux/macOS
python3 main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test_deepseek
```

**Expected time**: ~6 minutes (single DeepSeek extraction over the API)

**Expected resources**: Network-bound (LLM API calls); no GPU required. One DeepSeek extraction call over the API.

**Expected result**: `openvas_test_deepseek.json` with extracted vulnerabilities containing fields like `Name`, `description`, `severity`, `cvss`, `port`, `references`, etc. Run `python tools/summarize_vulnerabilities.py --input openvas_test_deepseek.json` to print a terminal summary; on a real DeepSeek/JuiceShop run this looks like:

```
SEVERITY   | NAME                                               | CVSS    | PORT/PROTO | CVE
========================================================================================================================
HIGH       | SMTP too long line                                 | CVSS 7.5 | 25/tcp     | N/A
MEDIUM     | Check if Mailserver answer to VRFY and EXPN requests | CVSS 5.0 | 25/tcp     | N/A
LOG        | Postfix SMTP Server Detection                      | CVSS 0.0 | 25/tcp     | N/A
...        | (37 records extracted total)
========================================================================================================================
Total vulnerabilities: 37
```

### Claim #2: Quality Evaluation with BERTScore/ROUGE-L

**Description**: The tool evaluates extraction quality against ground truth baselines using BERTScore and ROUGE-L metrics, with similarity scores categorized as: Highly Similar (≥0.7), Moderately Similar (0.6-0.7), Low Similarity (0.4-0.6), and Divergent (<0.4).

**Execution**:

```bash
# Evaluate with BERTScore and ROUGE-L

# Windows
python metrics\pipelines\compare_extractions.py --baseline-file baselines\openvas\OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --llm deepseek --output-dir results_bert --allow-duplicates --scorer bertscore
python metrics\pipelines\compare_extractions.py --baseline-file baselines\openvas\OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --llm deepseek --output-dir results_rouge --allow-duplicates --scorer rouge_l

# Linux/macOS
python3 metrics/pipelines/compare_extractions.py --baseline-file baselines/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --llm deepseek --output-dir results_bert --allow-duplicates --scorer bertscore
python3 metrics/pipelines/compare_extractions.py --baseline-file baselines/openvas/OpenVAS_JuiceShop.xlsx --extraction-file openvas_test_deepseek.json --llm deepseek --output-dir results_rouge --allow-duplicates --scorer rouge_l
```

**Expected time**: ~15 seconds for BERTScore (plus a one-time model download on first use) and ~3 seconds for ROUGE-L

**Expected resources**: ~2 GB RAM during the BERTScore pass (PyTorch); ~300 MB extra disk for the DistilBERT model on first use. ROUGE-L is CPU-only and lightweight.

**Expected result**: XLSX files with BERTScore and ROUGE-L metrics in `./results_bert` and `./results_rouge`. Real console output from this exact command pair, run against the DeepSeek/JuiceShop extraction:

```
Loading BERTScore model: distilbert-base-uncased...
BERTScore model loaded successfully!
[BERTSCORE] matched=34/37, fields scored=12
[BERTSCORE] saved -> results_bert\bert_comparison_vulnerabilities_deepseek.xlsx

[ROUGE_L] matched=34/37, fields scored=12
[ROUGE_L] saved -> results_rouge\rouge_comparison_vulnerabilities_deepseek.xlsx
```

### Claim #3: Consolidated Multi-LLM Metrics Report (TMM_metrics_run.py)

**Description**: TMM consolidates metrics for multiple LLM extractions against a single ground-truth baseline into one XLSX report, with per-field tables (ROUGE-L, Token-F1, Soft-F1, CVSS/Port/Protocol/Severity exact match) and comparison charts/heatmaps across all versions.

**Execution**:

```bash
# All versions combined (V1+V2+V3, 15 LLM x version entries in one report)

# Windows
python tools/TMM_metrics_run.py `
  --baseline baselines/native/vulnnet_scans_openvas.csv `
  --versions TMMv1:artifacts/v1/openvas_129_dockers/deepseek_v1.csv:deepseek `
             TMMv1:artifacts/v1/openvas_129_dockers/gpt4_v1.csv:gpt4 `
             TMMv1:artifacts/v1/openvas_129_dockers/gpt5_v1.csv:gpt5 `
             TMMv1:artifacts/v1/openvas_129_dockers/llama3_v1.csv:llama3 `
             TMMv1:artifacts/v1/openvas_129_dockers/llama4_v1.csv:llama4 `
             TMMv2:artifacts/v2/openvas_129_dockers/deepseek_v2.csv:deepseek `
             TMMv2:artifacts/v2/openvas_129_dockers/gpt4_v2.csv:gpt4 `
             TMMv2:artifacts/v2/openvas_129_dockers/gpt5_v2.csv:gpt5 `
             TMMv2:artifacts/v2/openvas_129_dockers/llama3_v2.csv:llama3 `
             TMMv2:artifacts/v2/openvas_129_dockers/llama4_v2.csv:llama4 `
             TMMv3:artifacts/v3/openvas_129_dockers/deepseek_v3.csv:deepseek `
             TMMv3:artifacts/v3/openvas_129_dockers/gpt4_v3.csv:gpt4 `
             TMMv3:artifacts/v3/openvas_129_dockers/gpt5_v3.csv:gpt5 `
             TMMv3:artifacts/v3/openvas_129_dockers/llama3_v3.csv:llama3 `
             TMMv3:artifacts/v3/openvas_129_dockers/llama4_v3.csv:llama4 `
  --xlsx artifacts/TMM_metrics_all_versions.xlsx

# Linux/macOS
python3 tools/TMM_metrics_run.py \
  --baseline baselines/native/vulnnet_scans_openvas.csv \
  --versions TMMv1:artifacts/v1/openvas_129_dockers/deepseek_v1.csv:deepseek \
             TMMv1:artifacts/v1/openvas_129_dockers/gpt4_v1.csv:gpt4 \
             TMMv1:artifacts/v1/openvas_129_dockers/gpt5_v1.csv:gpt5 \
             TMMv1:artifacts/v1/openvas_129_dockers/llama3_v1.csv:llama3 \
             TMMv1:artifacts/v1/openvas_129_dockers/llama4_v1.csv:llama4 \
             TMMv2:artifacts/v2/openvas_129_dockers/deepseek_v2.csv:deepseek \
             TMMv2:artifacts/v2/openvas_129_dockers/gpt4_v2.csv:gpt4 \
             TMMv2:artifacts/v2/openvas_129_dockers/gpt5_v2.csv:gpt5 \
             TMMv2:artifacts/v2/openvas_129_dockers/llama3_v2.csv:llama3 \
             TMMv2:artifacts/v2/openvas_129_dockers/llama4_v2.csv:llama4 \
             TMMv3:artifacts/v3/openvas_129_dockers/deepseek_v3.csv:deepseek \
             TMMv3:artifacts/v3/openvas_129_dockers/gpt4_v3.csv:gpt4 \
             TMMv3:artifacts/v3/openvas_129_dockers/gpt5_v3.csv:gpt5 \
             TMMv3:artifacts/v3/openvas_129_dockers/llama3_v3.csv:llama3 \
             TMMv3:artifacts/v3/openvas_129_dockers/llama4_v3.csv:llama4 \
  --xlsx artifacts/TMM_metrics_all_versions.xlsx
```

**Expected time**: ~10-16 minutes (15 version x LLM entries against the full 6,343-row native baseline; ~1 minute per entry, validated with a single-LLM run)

**Expected resources**: CPU-only, no GPU required; a few hundred MB RAM and negligible extra disk per entry processed (pure CSV comparison, no network access needed).

**Expected result**: `artifacts/TMM_metrics_all_versions.xlsx` with one sheet per metric/chart (overview heatmap, per-version and per-LLM breakdowns, per-field ROUGE-L/Token-F1/Soft-F1, CVSS/Port/Protocol/Severity confusion matrices) comparing all 15 version x LLM entries (V1/V2/V3 x DeepSeek/GPT-4/GPT-5/LLaMa 3/LLaMa 4) against `baselines/native/vulnnet_scans_openvas.csv`. Real console output for the DeepSeek/V3 entry (repeated once per entry):

```
  [TMMv3] Loading data...
  [TMMv3] Name mapping: 1265/1266 LLM names matched
  [TMMv3] Pairs: 5859 (host+name matched)
  [TMMv3] description                    ROUGE-L=0.9347  Soft-F1=0.9373
  [TMMv3] severity Exact=1.0000  F1-macro=1.0000
  OK

Saved -> artifacts/TMM_metrics_all_versions.xlsx
Done.  ->  artifacts/TMM_metrics_all_versions.xlsx
```

> **Note**: The [`dockers/`](dockers/) folder contains the original PDF reports used to produce each per-version extraction, consolidated per version under `artifacts/<version>/openvas_129_dockers/` (e.g. [`artifacts/v3/openvas_129_dockers/`](artifacts/v3/openvas_129_dockers/)). See [docs/INVENTORY.md](docs/INVENTORY.md) for the full list of the 129 scanned Docker targets.

---

For detailed experiment configurations, see [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md).

## Documentation

Detailed documentation is organized in separate files:

| Document                                           | Description                          |
| -------------------------------------------------- | ------------------------------------ |
| [docs/INSTALL.md](docs/INSTALL.md)                 | Detailed installation guide          |
| [docs/USAGE.md](docs/USAGE.md)                     | Complete usage guide with examples   |
| [docs/CONFIG.md](docs/CONFIG.md)                   | API keys and token configuration     |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)       | Code structure and components        |
| [docs/EXTENSIBILITY.md](docs/EXTENSIBILITY.md)     | Adding new scanners and LLMs         |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors and optimization tips  |
| [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)         | Experimental validation details      |
| [docs/INVENTORY.md](docs/INVENTORY.md)             | Container inventory and distribution |

## LICENSE

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

- **Permitted use**: Free for use, modification, distribution, and sublicensing, including for commercial purposes.
- **Notice**: Provided "as is", without warranties. The user is responsible for use and secure configuration of data and keys.

See the [LICENSE](LICENSE) file for the full license text.
