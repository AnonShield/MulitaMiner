<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_light.png">
    <img src="imgs/MulitaMiner_logo_light.png" width="500" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

_Automated · Structured · Multi-LLM_

![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-orange)
![update](https://img.shields.io/badge/last%20update-Mar%202026-lightgrey)

</div>

# MulitaMiner

**MulitaMiner** is an automated tool for extracting and structuring vulnerabilities from heterogeneous PDF reports produced by security scanners. Its LLM-based pipeline combines adaptive chunking and scanner-aware prompting to convert unstructured findings into consistent, analysis-ready vulnerability records, with standardized outputs and quality validation.

## Paper

**MulitaMiner: A Multi-Version Evaluation of LLM-Based Vulnerability Report Extraction**
SBSeg 2026, Main Track.

> **Abstract.** Security teams face 131 new CVEs per day, yet the National Vulnerability Database fails to enrich 44% of new submissions, leaving practitioners without the structured metadata required to prioritize remediation. MulitaMiner closes this gap: an LLM-based pipeline for structured vulnerability extraction from heterogeneous scanner PDFs, hardened across three successive versions (V1–V3) that evolve from a functional baseline, to scanner-aware segmentation, and finally to per-LLM tuning with few-shot prompting. We evaluate five LLMs (DeepSeek, GPT-4, GPT-5, LLaMA 3, LLaMA 4) on three manually curated baselines across 450 independent runs. Without changing the underlying models, Exact Record Match rises from 37.5% to 90.4%, vulnerability-level omission falls by an order of magnitude (20.5% → 1.7%), and cross-model variance in field-level omission collapses from 41.8 to 2.9 percentage points, all with non-overlapping 95% bootstrap confidence intervals. These results establish that pipeline engineering, not model substitution, is the primary lever for extraction quality: under a well-engineered pipeline, LLM choice becomes a question of cost and latency rather than accuracy.

**Purpose of this artifact.** This branch (`V3`) contains the pipeline version described in Section 3 of the paper, plus everything needed to reproduce its two central claims. The two earlier pipeline versions are shipped as source snapshots in [versions/](versions/), so the V1 → V2 → V3 progression can be reproduced end to end from this single repository.

> ⚠️ This repository also hosts a **different artifact** for another paper, on branch [`slms`](../../tree/slms) (WTICG 2026, local LLMs). Make sure you are on the branch that matches the paper you are reviewing.

**Use Cases:**

- **Security Analysis**: Automated extraction of vulnerabilities from scanner reports
- **Enterprise Integration**: Support for CAIS formats for corporate systems
- **Research and Development**: Comparative evaluation of different LLMs

## README Structure

Key directories for artifact evaluation:

| Path                                     | Content                                                              |
| ---------------------------------------- | -------------------------------------------------------------------- |
| [main.py](main.py)                       | CLI entry point: extraction, format conversion and metric evaluation |
| [claims/](claims/)                       | One script per claim (`.sh` for Linux/macOS, `.bat` for Windows)     |
| [versions/](versions/)                   | V1 and V2 pipeline snapshots as zips (used by Claim 2)               |
| [baselines/](baselines/)                 | Curated ground-truth baselines (PDF report + XLSX annotation)        |
| [src/](src/)                             | Pipeline: PDF extraction, chunking, scanner strategies, LLM providers |
| [metrics/](metrics/)                     | Metric battery: scorers, pipelines and cross-run aggregators         |
| [tools/](tools/)                         | Batch orchestration (`run_experiments.py`, `run_metrics.py`)         |
| [docs/](docs/)                           | Detailed documentation (install, usage, architecture)                |
| [requirements.txt](requirements.txt) · [pyproject.toml](pyproject.toml) | Pinned dependencies (both install the same set)   |
| [.env.example](.env.example)             | Template for the API key file                                        |

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
| **Python**  | 3.11 or 3.12                      |
| **RAM**     | 4GB+ (8GB recommended for large PDFs)            |
| **Disk**    | 500MB for dependencies + space for outputs       |
| **Network** | Internet connection required for LLM API calls   |

A [Dockerfile](Dockerfile) with the interpreter and dependencies already pinned is provided as an alternative, see [Alternative: Docker](#alternative-docker).

### Supported LLMs

| Provider | Models                |
| -------- | --------------------- |
| OpenAI   | GPT-4, GPT-5          |
| Groq     | Llama3, Llama4, Qwen3 |
| DeepSeek | deepseek-coder        |

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

**API Keys**: The tool requires LLM API keys configured in a `.env` file. Never commit this file to public repositories. The Docker image does not embed it either: `.env` is excluded from the build context by [.dockerignore](.dockerignore) and mounted read-only at run time.

**PDF Processing**: PDF parsing, chunking and all metric computation happen locally.

**Report content leaves the machine**: extraction works by sending the report text to the configured LLM provider. That text includes whatever the scanner wrote, typically **IP addresses, hostnames, open ports and vulnerability descriptions**, which together map the attack surface of the scanned target. Use the bundled sample reports for evaluation, and for real assessments prefer a local backend (Ollama, LM Studio or Hugging Face, all supported) so nothing reaches a third party.

**Network**: The tool makes HTTPS requests to LLM APIs. Ensure your network allows outbound connections to:

- `api.openai.com` (OpenAI)
- `api.deepseek.com` (DeepSeek)

## Installation

### 1. Clone the Repository

```bash
git clone -b V3 https://github.com/AnonShield/MulitaMiner.git
cd MulitaMiner
```

### 2. Create Virtual Environment

MulitaMiner runs on **Python 3.11 or 3.12**. Python 3.13+ is not supported: the pinned `numpy`/`scipy` releases publish no wheels for it and `pip` would try to compile them from source.

```bash
# Windows (use py -3.12 for Python 3.12)
py -3.11 -m venv .venv
.venv\Scripts\activate

# Linux/Mac (use python3.12 for Python 3.12)
python3.11 -m venv .venv
source .venv/bin/activate
```

Check the interpreter before installing:

```bash
python -c "import sys; print(sys.version)"   # must report 3.11.x or 3.12.x
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

### Alternative: Docker

If no supported interpreter is available locally, the bundled [Dockerfile](Dockerfile) pins Python 3.11 and installs the same requirements:

```bash
docker build -t mulitaminer .
```

The build takes a few minutes and produces a large image (~3 GB): besides the CPU build of PyTorch, it bakes in the DistilBERT model used by BERTScore, so the metric phase of the claims does not depend on downloading it from the network at run time.

The image never contains your API key: [.dockerignore](.dockerignore) keeps `.env` out of the build context, and the file is mounted read-only when the container runs. Two mounts are used below: `.env` carries the DeepSeek key into the container, and `claims/out` keeps the generated outputs on the host.

```bash
# Minimum test
docker run --rm -it \
  -v "$PWD/.env:/app/.env:ro" \
  -v "$PWD/claims/out:/app/claims/out" \
  mulitaminer \
  python main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek \
    --scanner openvas --allow-duplicates --output-file openvas_test \
    --output-dir claims/out/minimum_test

# Claim 1 (Claim 2 is the same command with claim2_version_progression.sh)
docker run --rm -it \
  -v "$PWD/.env:/app/.env:ro" \
  -v "$PWD/claims/out:/app/claims/out" \
  mulitaminer \
  bash claims/claim1_extraction_metrics.sh
```

On Windows PowerShell, replace `$PWD` with `${PWD}` and the trailing `\` with a backtick.

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

Both claims use **DeepSeek only**, the API key provided for evaluation (configure `.env` as shown in [Installation](#installation)). Both scripts also run inside the Docker image, see [Alternative: Docker](#alternative-docker).

> **Note on execution times**: based on AMD Ryzen 5 5600G, 32GB RAM, 1TB SSD, Windows 11. Actual times may vary depending on system specifications, network latency, and API response times.

> **Note on variability**: LLM decoding is stochastic and hosted models are updated by their providers over time, so single-run results are expected to deviate by a few percentage points from the reference values below (reference values are means of 10 runs from the paper's evaluation). What validates each claim is the trend, not the exact figure: in the paper's full evaluation (5 LLMs × 3 baselines × 10 runs per configuration), all headline differences between versions hold with non-overlapping 95% bootstrap confidence intervals, e.g. Exact Record Match 37.5% [34.3, 40.7] (V1) → 88.0% [86.9, 89.2] (V2) → 90.4% [89.3, 91.5] (V3), and vulnerability-level omission 20.5% [16.2, 25.2] → 8.1% [6.5, 9.9] → 1.7% [1.4, 2.0]. The claims below run **one extraction per version**, so that the artifact can be evaluated in minutes instead of the hours the full 450-run evaluation takes; every reference value they are compared against is a mean of 10 runs.

### Claim #1: Structured Extraction with Quantitative Evaluation (V3 pipeline)

**Description**: MulitaMiner (V3) extracts structured vulnerability records from a heterogeneous scanner PDF using scanner-aware adaptive chunking, and evaluates the result against a manually curated ground truth with the full metric battery of the paper (Section 4.2): schema check, BERTScore, ROUGE-L, Token-F1, Field-F1, severity confusion, and coverage (Exact Record Match, hallucination and omission rates). The test report is OWASP Juice Shop (34 vulnerabilities in the curated baseline).

**Execution**:

```bash
# Windows
claims\claim1_extraction_metrics.bat

# Linux/macOS
bash claims/claim1_extraction_metrics.sh
```

**Expected time**: ~5 minutes (~3 for the extraction; on a native install the first metrics run also downloads the DistilBERT model used by BERTScore, which the Docker image already carries)

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

Single-run values may deviate from the table (e.g. V1 Exact Record Match anywhere in the 0.15-0.25 range, see the variability note above). What validates the claim is the ordering: V1 scores far below V2 and V3 on Exact Record Match, reproducing at small scale the aggregate result of the paper (Table 3: ERM 37.5% → 88.0% → 90.4%).
