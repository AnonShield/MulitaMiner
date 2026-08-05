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

This artifact accompanies the paper **"MulitaMiner: A Multi-Version Evaluation of LLM-Based Vulnerability Report Extraction"** (SBSeg 2026, main track). The paper evaluates three successive versions of the pipeline (V1, V2, V3) with five LLMs on three manually curated baselines (217 vulnerabilities), totaling **450 independent runs**. Without changing the underlying models, **Exact Record Match rises from 37.5% to 90.4%** and **vulnerability-level omission falls from 20.5% to 1.7%**, showing that pipeline engineering, not model substitution, is the primary lever for extraction quality.

This repository contains the **V3** pipeline (the version described in Section 3 of the paper). The two earlier versions are shipped as source snapshots in [versions/](versions/), so the version-progression claim can be reproduced end to end from this single repository.

**Use Cases:**

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Enterprise Integration**: Support for CAIS formats for corporate systems
- **Research and Development**: Comparative evaluation of different LLMs

## README Structure

Key directories for artifact evaluation:

| Directory                  | Content                                                          |
| -------------------------- | ---------------------------------------------------------------- |
| [claims/](claims/)         | One script per claim (`.sh` for Linux/macOS, `.bat` for Windows) |
| [versions/](versions/)     | V1 and V2 pipeline snapshots as zips (used by Claim 2)           |
| [baselines/](baselines/)   | Curated ground-truth baselines (PDF report + XLSX annotation)    |
| [docs/](docs/)             | Detailed documentation (install, usage, architecture)            |

Sections of this README:

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

> **Note**: all experiment claims below use **DeepSeek only** (the API key provided for evaluation). The other providers are supported by the tool but are not needed to reproduce the claims.

## Dependencies

### Main Dependencies

All versions are pinned in [requirements.txt](requirements.txt). Core extraction:

```
langchain==0.3.28                # LLM framework
langchain-core==0.3.84
langchain-openai==0.3.35         # OpenAI-compatible APIs (incl. DeepSeek)
langchain-ollama==0.3.10         # Local execution backend
tiktoken==0.12.0                 # Tokenization
pdfplumber==0.11.9               # PDF extraction
json-repair==0.59.5              # Recovery of malformed LLM outputs
python-dotenv==1.2.2             # Environment variables
pandas==2.3.3 / openpyxl==3.1.5  # Data manipulation and XLSX export
```

### Metrics Evaluation

```
bert-score==0.3.13               # BERTScore (downloads DistilBERT on first use)
rouge-score==0.1.2               # ROUGE-L
torch==2.11.0                    # Required by BERTScore
rapidfuzz==3.14.5                # Fuzzy record alignment
scipy==1.13.1 / scikit-learn==1.8.0
```

The V1/V2 snapshots used by Claim 2 have their own (older) dependencies; the claim script installs them automatically in a separate virtual environment.

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
git clone -b V3 https://github.com/AnonShield/MulitaMiner.git
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

Copy [.env.example](.env.example) to `.env` at the repository root and fill in the DeepSeek key:

```bash
# Windows
copy .env.example .env

# Linux/macOS
cp .env.example .env
```

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"   # required for the experiment claims
```

Only the DeepSeek key is required to reproduce the claims; the other keys in the example file are optional.

See [docs/CONFIG.md](docs/CONFIG.md) for all configuration options.

## Minimum Test

After installation (including the `.env` file with the DeepSeek key), run a single extraction of the smallest report (OWASP Juice Shop) and summarize it in the terminal:

```bash
# Windows
python main.py --input baselines\openvas\OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test --output-dir claims\out\minimum_test
python tools\summarize_vulnerabilities.py --input claims\out\minimum_test\openvas_test.json

# Linux/macOS
python3 main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file openvas_test --output-dir claims/out/minimum_test
python3 tools/summarize_vulnerabilities.py --input claims/out/minimum_test/openvas_test.json
```

**Expected time**: ~3 minutes

**Expected result**: a terminal table listing approximately 34 extracted vulnerabilities, e.g.:

```text
SEVERITY   | NAME                                               | CVSS     | PORT/PROTO | CVE
==============================================================================================
HIGH       | SMTP too long line                                 | CVSS 7.5 | 25/tcp     | N/A
MEDIUM     | Check if Mailserver answer to VRFY and EXPN ...    | CVSS 5.0 | 25/tcp     | N/A
LOG        | Postfix SMTP Server Detection                      | CVSS 0.0 | 25/tcp     | N/A
...
```

## Experiments

This section describes how to reproduce the main claims from the paper. Each claim has a ready-to-run script in [claims/](claims/) (`.bat` for Windows, `.sh` for Linux/macOS), to be executed from the repository root with the virtual environment active. Outputs are written to `claims/out/`.

Both claims use **DeepSeek only**, the API key provided for evaluation (configure `.env` as shown in [Installation](#installation)).

> **Note on execution times**: based on AMD Ryzen 5 5600G, 32GB RAM, 1TB SSD, Windows 11. Actual times may vary depending on system specifications, network latency, and API response times.

> **Note on variability**: LLM decoding is stochastic and hosted models are updated by their providers over time, so single-run results are expected to deviate by a few percentage points from the reference values below (reference values are means of 10 runs from the paper's evaluation). What validates each claim is the trend, not the exact figure: in the paper's full evaluation (5 LLMs × 3 baselines × 10 runs per configuration), all headline differences between versions hold with non-overlapping 95% bootstrap confidence intervals, e.g. Exact Record Match 37.5% [34.3, 40.7] (V1) → 88.0% [86.9, 89.2] (V2) → 90.4% [89.3, 91.5] (V3), and vulnerability-level omission 20.5% [16.2, 25.2] → 8.1% [6.5, 9.9] → 1.7% [1.4, 2.0].

### Claim #1: Structured Extraction with Quantitative Evaluation (V3 pipeline)

**Description**: MulitaMiner (V3) extracts structured vulnerability records from a heterogeneous scanner PDF using scanner-aware adaptive chunking, and evaluates the result against a manually curated ground truth with the full metric battery of the paper (Section 4.2): schema check, BERTScore, ROUGE-L, Token-F1, Field-F1, severity confusion, and coverage (Exact Record Match, hallucination and omission rates). The test report is OWASP Juice Shop (34 vulnerabilities in the curated baseline).

**Execution**:

```bash
# Windows
claims\claim1_extraction_metrics.bat

# Linux/macOS
bash claims/claim1_extraction_metrics.sh
```

**Expected time**: ~5 minutes (~3 for the extraction; the first metrics run also downloads the DistilBERT model used by BERTScore)

**Expected resources**: ~2 GB RAM during the metric pass (PyTorch/BERTScore); ~300 MB extra disk for the DistilBERT model on first use; one DeepSeek extraction over the API (a fraction of a US dollar in tokens)

**Expected result**: a terminal table listing the extracted vulnerabilities (approximately 34 records following the canonical 18-field schema: `Name`, `description`, `severity`, `cvss`, `port`, `protocol`, `references`, etc.), followed by a terminal metric summary. Reference values for DeepSeek on JuiceShop under V3 (mean of 10 runs in the paper's evaluation): Exact Record Match in the 0.90-0.95 range, field-level omission in the 3-6% range, severity macro-F1 ≥ 0.9. The underlying extraction JSON and metric reports are also written to `claims/out/results_runs_v3/` for inspection.

Example terminal output from a real run (values vary slightly between runs, see the variability note):

```text
SEVERITY   | NAME                                               | CVSS     | PORT/PROTO | CVE
==============================================================================================
HIGH       | SMTP too long line                                 | CVSS 7.5 | 25/tcp     | N/A
MEDIUM     | Check if Mailserver answer to VRFY and EXPN ...    | CVSS 5.0 | 25/tcp     | N/A
LOG        | Postfix SMTP Server Detection                      | CVSS 0.0 | 25/tcp     | N/A
...        | (~34 records)                                      |          |            |

=== Metric summary (V3, DeepSeek, JuiceShop) ===

Target: OpenVAS_JuiceShop | LLM: deepseek
Metric                       V3
-------------------------------
Exact Record Match         0.94
Field omission             4.2%
Field hallucination        1.9%
Vuln omission              0.0%
Matched pairs                34
Severity macro-F1          0.93
```

### Claim #2: Pipeline Versioning Drives Extraction Quality (V1 → V2 → V3)

**Description**: The paper's central claim. The same report is extracted with the three pipeline versions using the same LLM (DeepSeek), and all outputs are evaluated with the same V3 metric battery. V1 and V2 are unpacked from [versions/](versions/) and run in a dedicated legacy virtual environment created automatically by the script. If the V3 run from Claim 1 is not found, the script executes Claim 1 first.

**Execution**:

```bash
# Windows
claims\claim2_version_progression.bat

# Linux/macOS
bash claims/claim2_version_progression.sh
```

**Expected time**: ~10 minutes (legacy dependency install + two extractions + metrics)

**Expected resources**: ~2 GB RAM during the metric pass; ~500 MB extra disk for the unpacked V1/V2 snapshots and their virtual environment; two DeepSeek extractions over the API (a fraction of a US dollar in tokens)

**Expected result**: a terminal table comparing the three versions side by side on the same extraction task. Reference values for DeepSeek on JuiceShop (mean of 10 runs in the paper's evaluation):

| Metric               | V1   | V2   | V3   |
| -------------------- | ---- | ---- | ---- |
| Exact Record Match   | 0.21 | 0.91 | 0.94 |
| Field-level omission | 13%  | 5%   | 4%   |

Single-run values may deviate from the table (e.g. V1 Exact Record Match anywhere in the 0.15-0.25 range, see the variability note above). What validates the claim is the ordering: V1 scores far below V2 and V3 on Exact Record Match, and omission falls monotonically from V1 to V3, reproducing at small scale the aggregate result of the paper (Table 3: ERM 37.5% → 88.0% → 90.4%).

Example terminal output from a real run:

```text
=== Cross-version summary (DeepSeek, JuiceShop) ===

Target: OpenVAS_JuiceShop | LLM: deepseek
Metric                       V1        V2        V3
---------------------------------------------------
Exact Record Match         0.15      0.94      0.94
Field omission            13.9%      4.4%      4.2%
Field hallucination       16.3%      3.2%      1.9%
Vuln omission              0.0%      0.0%      0.0%
Matched pairs                34        34        34
Severity macro-F1          0.84      1.00      0.93

Expected trend (paper, Table 3): Exact Record Match rises and
omission falls from V1 to V3. Single-run values vary (stochastic
LLM decoding); the ordering across versions is what validates the claim.
```

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
