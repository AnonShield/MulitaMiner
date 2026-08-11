<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="imgs/MulitaMiner_logo_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="imgs/MulitaMiner_logo_light.png">
    <img src="imgs/MulitaMiner_logo_light.png" width="500" alt="MulitaMiner logo">
  </picture>

**Vulnerability Extraction from Security Reports using LLMs**

_On-Premise · Local SLMs · Privacy-Preserving_

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![backend](https://img.shields.io/badge/backend-Ollama-lightgrey)

</div>

# MulitaMiner: local LLMs for vulnerability extraction

**MulitaMiner** extracts and structures vulnerabilities from heterogeneous PDF reports produced by security scanners. This artifact evaluates whether the extraction can run **entirely on-premise**, so that reports never leave the organization, without losing the quality of a cloud API.

## Paper

**On-Premise vs. Cloud: Local LLMs for Vulnerability Extraction from Security Scanner Reports**
WTICG 2026.

> **Abstract.** Cloud LLMs extract structured data from vulnerability-scanner reports accurately, but each report maps an organization's attack surface, so routing it to a third-party API trades confidentiality for that accuracy. We evaluate nine local models (4B to 21B) against a DeepSeek cloud reference on three ground-truth baselines. The best local model, on a consumer GPU, trails the cloud by only 1.2 points in free-text fidelity and matches it on structured fields; the spread across local models far exceeds this gap, making model choice the decisive factor for private, on-premise extraction.

**Purpose of this artifact.** This branch (`slms`) reproduces the comparison at reviewer scale: the same pipeline, the same prompts and the same baseline are run with the cloud reference and with the best local model of the paper, and both are scored by the identical metric battery.

> ⚠️ This repository also hosts a **different artifact** for another paper, on branch [`V3`](../../tree/V3) (SBSeg 2026 main track, cloud pipeline versions). Make sure you are on the branch that matches the paper you are reviewing.

## README Structure

| Path | Content |
| ---- | ------- |
| [main.py](main.py) | CLI entry point: extraction, conversion and metric evaluation |
| [claims/](claims/) | Claim script (`.sh` for Linux/macOS, `.bat` for Windows) and helpers |
| [baselines/](baselines/) | Ground-truth baselines (PDF report + XLSX annotation) |
| [src/configs/llms/](src/configs/llms/) | One JSON per model: endpoint, context window, chunking |
| [src/](src/) | Pipeline: PDF extraction, chunking, scanner strategies, LLM providers |
| [metrics/](metrics/) | Metric battery: scorers, pipelines and aggregators |
| [docs/](docs/) | Detailed documentation |
| [.env.example](.env.example) | Template for the API key file |

Sections of this README:

- [Considered Badges](#considered-badges)
- [Basic Information](#basic-information)
- [Dependencies](#dependencies)
- [Security Concerns](#security-concerns)
- [Installation](#installation)
- [Minimum Test](#minimum-test)
- [Experiments](#experiments)
- [LICENSE](#license)

## Considered Badges

The following badges are considered for evaluation: **Available**, **Functional**, **Sustainable**, and **Reproducible**.

## Basic Information

The artifact compares two execution modes, and their requirements differ:

| Component | Cloud reference (DeepSeek) | Local model (Llama 3.1 8B) |
| --------- | -------------------------- | ---------------------------- |
| **Hardware** | Any machine | GPU with **8 GB+ VRAM** recommended |
| **RAM** | 4 GB | 8 GB (16 GB if running on CPU) |
| **Disk** | 500 MB (dependencies) | + ~4.9 GB for the model weights |
| **Network** | Required (API calls) | Only to download the model once |
| **API key** | Required | Not needed |

**OS**: Windows 10+, Linux (Ubuntu 20.04+) or macOS 10.15+. **Python**: 3.11+.

Ollama selects its compute backend automatically (CUDA, ROCm or Vulkan depending on the card), and falls back to CPU when no GPU is usable, which works but is much slower. Peak memory for `llama3.1:8b` at the paper's 16,000-token context window is about 7 GB; cards with less VRAM still run it, offloading the remaining layers to CPU.

## Dependencies

### Python

All versions are pinned in [requirements.txt](requirements.txt) and [pyproject.toml](pyproject.toml). The core of the extraction is `langchain`, `pdfplumber`, `tiktoken` and `json-repair`; the metric battery adds `bert-score`, `rouge-score`, `torch`, `rapidfuzz` and `scipy`.

## Security Concerns

**Why this paper exists.** Scanner reports describe an organization's attack surface: IP addresses, hostnames, open ports, service versions and exploitable weaknesses. Sending them to a third-party API discloses exactly that. The local path exists so nothing leaves the machine.

**Cloud reference.** Reproducing the comparison requires running the cloud side too, which does send the report text to the DeepSeek API. The bundled baselines are public, intentionally vulnerable applications (Juice Shop, bBWA, Artifactory), so no real attack surface is exposed by the evaluation. For real assessments, use the local path.

**API keys.** Configured in a `.env` file, which is git-ignored. Never commit it.

**Ollama.** The default install listens on `localhost` only. Do not expose port 11434 to a network: the Ollama API has no authentication and allows pulling and **deleting** models.

## Installation

### 1. Clone the repository

```bash
git clone -b slms https://github.com/AnonShield/MulitaMiner.git
cd MulitaMiner
```

### 2. Create a virtual environment and install

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

### 3. Configure the API key

Copy [.env.example](.env.example) to `.env` and fill in the DeepSeek key:

```bash
# Windows
copy .env.example .env

# Linux/macOS
cp .env.example .env
```

Only `API_KEY_DEEPSEEK` is required. The local model needs no key.

### 4. Start Ollama

The local model is served by [Ollama](https://ollama.com), pinned to the version used in the paper. The simplest route on any hardware is the native installer from [ollama.com/download](https://ollama.com/download), which detects NVIDIA, AMD or CPU-only on its own.

With Docker, pick the line that matches the machine. All three bind to `127.0.0.1`, so the server stays unreachable from the network:

```bash
# NVIDIA, needs the NVIDIA Container Toolkit on the host
docker run -d --gpus=all -v ollama:/root/.ollama \
  -p 127.0.0.1:11434:11434 --name ollama ollama/ollama:0.30.0

# AMD (ROCm)
docker run -d --device /dev/kfd --device /dev/dri -v ollama:/root/.ollama \
  -p 127.0.0.1:11434:11434 --name ollama ollama/ollama:0.30.0-rocm

# No GPU, runs on the CPU
docker run -d -v ollama:/root/.ollama \
  -p 127.0.0.1:11434:11434 --name ollama ollama/ollama:0.30.0
```

Without a GPU the extraction still completes, but the local step goes from a couple of minutes to hours.

**You do not need to pull the model or configure anything.** The claim script checks the server, downloads `llama3.1:8b` if it is missing, and sends the context window and chunking parameters of the paper on every request. To verify the setup on its own:

```bash
python claims/check_ollama.py llama31_local
```

## Minimum Test

Two quick checks, in this order.

### 1. Local backend

```bash
python claims/check_ollama.py llama31_local
```

**Expected result**: `[CHECK] All required models are available.` The model is downloaded automatically if missing, so the first run of this check may take a few minutes.

### 2. Pipeline and API key

Extract the smallest baseline with the cloud reference and summarize it:

```bash
# Windows
python main.py --input baselines\openvas\OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file minimum_test --output-dir claims\out\minimum_test
python tools\summarize_vulnerabilities.py --input claims\out\minimum_test\minimum_test.json

# Linux/macOS
python3 main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf --llm deepseek --scanner openvas --allow-duplicates --output-file minimum_test --output-dir claims/out/minimum_test
python3 tools/summarize_vulnerabilities.py --input claims/out/minimum_test/minimum_test.json
```

**Expected time**: 10 to 20 minutes, depending on the API load at the time

**Expected result**: a terminal table listing roughly 34 extracted vulnerabilities:

```text
SEVERITY   | NAME                                               | CVSS     | PORT/PROTO | CVE
==============================================================================================
HIGH       | SMTP too long line                                 | CVSS 7.5 | 25/tcp     | N/A
MEDIUM     | Check if Mailserver answer to VRFY and EXPN ...    | CVSS 5.0 | 25/tcp     | N/A
LOG        | Postfix SMTP Server Detection                      | CVSS 0.0 | 25/tcp     | N/A
...
```

## Experiments

> **Note on execution times**: the local model was run on an NVIDIA RTX 5080. Cloud latency varies with provider load, so treat the figure below as an order of magnitude rather than a fixed cost.

> **Note on variability**: expect your numbers to differ from the ones below, and do not read small deviations as a reproduction failure. Three sources of variation apply here.
>
> **The cloud endpoint drifts.** Hosted models are updated and load-balanced by their providers, so the DeepSeek side varies over time as well, independently of anything in this repository.
>
> **The hardware matters.** The same model, at the same version and with the same prompts, can emit slightly different text on different GPUs, so the local side shifts a little from machine to machine.
>
> **Scale.** The paper reports means over **5 runs on 3 baselines** (15 extractions per model). This claim runs **once on the smallest baseline**, to keep the API cost and the local GPU time within what a review can reasonably spend, so a single run naturally lands a little off any average.

### Claim #1: A local SLM matches the cloud on structured extraction

**Description**: the same pipeline, prompts and baseline are run with the cloud reference (`deepseek-v4-flash`) and with a local model served by Ollama (`llama3.1:8b`), and both are scored by the identical metric battery. This reproduces, at reviewer scale, the paper's central result: on-premise extraction matches the cloud on the deterministic fields and on schema conformance, and the residual gap sits in the free-text fields.

The paper evaluates nine local models; this claim runs one of them. `llama3.1:8b` was chosen because it needs the least VRAM of the pool (6.9 GB) and is the fastest to extract a report, so the claim stays runnable on modest hardware.

**Execution**:

```bash
# Windows
claims\claim1_local_vs_cloud.bat

# Linux/macOS
bash claims/claim1_local_vs_cloud.sh
```

**Expected time**: **10 to 20 min** for the cloud extraction (our own runs of this baseline took 11 min 37 s and 20 min, the difference being API load), plus **~1 min** for the metric pass, with a one-off DistilBERT download on the first run.

The local extraction is the part that varies most with the machine: about **2 to 3 min** on a recent NVIDIA card (2 min 25 s on an RTX 5080), around **20 min** on a mid-range or AMD one (22 min on a Radeon RX 6600 via Vulkan), and hours on CPU alone. A slow local step is expected, not a hang.

**Expected resources**: ~7 GB VRAM for the local model, plus ~2 GB RAM for the metric battery; one DeepSeek extraction over the API (a few cents)

**Expected result**: a terminal table comparing both models, close to this one:

```text
Per-model extraction quality (single run, %)
Baseline: OpenVAS_JuiceShop

Model                        BERTScore     Ent.F1      Exact    Omiss v   Halluc v     Schema    Sev.mF1    Sev.cov
-------------------------------------------------------------------------------------------------------------------
Llama 3.1 8B                      90.3       92.8       44.1        0.0       15.0      100.0      100.0       90.7
-------------------------------------------------------------------------------------------------------------------
deepseek-v4-flash (cloud)         97.9       99.4       94.1        0.0        5.6      100.0      100.0       98.9

BERTScore covers the free-text fields; Ent.F1 the deterministic ones
(cvss, plugin, port, protocol, severity). Compare with Table 1 of the paper,
keeping in mind this is a single run on one baseline.
```

What validates the claim: **schema conformance is 100% for both** and **Entity F1 lands within a few points**, confirming that deterministic extraction (cvss, plugin, port, protocol, severity) is solved on-premise. The cloud keeps its edge in **BERTScore** and in **Exact Record Match**, which is where the paper locates the residual gap: the narrative free-text fields.

Across the paper's full evaluation (Table 1, means over 5 runs and 3 baselines) the same pattern holds for the whole pool: Entity F1 ranges from 95.6 to 99.0 for every model including the cloud, while BERTScore spreads from 78.8 to 94.2. Deterministic extraction does not separate models; free-text fidelity does.

## LICENSE

Distributed under the MIT License. See [LICENSE](LICENSE).
