# MulitaMiner - Vulnerability Extraction from Security Reports using LLMs

<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/MulitaMiner_logo_light.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/MulitaMiner_logo_dark.png">
    <img src="assets/MulitaMiner_logo_light" width="500" alt="MulitaMiner logo">
  </picture>

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-orange)
![update](https://img.shields.io/badge/last%20update-Feb%202026-lightgrey)

</div>

## Abstract

**MulitaMiner** is an automated tool designed for extracting and processing vulnerabilities from security PDF reports using Large Language Models (LLMs) with an optimized chunking system. The tool implements an intelligent token optimization system that ensures efficient processing with no exceedances, supporting multiple LLM providers and specialized scanning strategies for different security tools (OpenVAS, Tenable WAS, Nessus). It enables security analysis through automated extraction of vulnerabilities from scanner reports, enterprise integration with support for CAIS formats, and research and development with comparative evaluation of different LLMs.

## Features

### Intelligent Extraction

- **Automatic extraction** of vulnerabilities from security PDF reports
- **Multi-scanner support**: OpenVAS, Tenable WAS, Nessus, and others
- **Automatic validation** of extracted data with normalization
- **Robust retry system** with smart chunk subdivision

### Optimized Chunking System

- **Automatic token calculation** based on each LLM's specific limits
- **Dynamic chunk size optimization** per model
- **Integrated validation** with `chunk_validator.py` for quality analysis

### Multi-LLM Support

- **6 supported LLMs** with individual optimized configurations:
  - **DeepSeek**: Ultra-efficient for technical analysis
  - **GPT-4**: Balanced for general use
  - **GPT-5**: Ultra-secure for critical processing
  - **Llama 3/4**: Groq-hosted models with different profiles
  - **Qwen3**: Efficient alternative

### Advanced Consolidation

- **TenableWAS**: Smart merging of vulnerability instances and base findings
- **OpenVAS**: Grouping by name similarity and characteristics
- **CAIS**: Consolidation by definitions with specialized fields
- **Intelligent Consolidation**: Automatic merging or removal of duplicate vulnerabilities (configurable)

### Multi-Format Export and Logs

- **Structured JSON** (main format)
- **CSV/TSV** with customizable delimiters
- **XLSX** (Excel) with advanced formatting
- **Visual layout preserved** in .txt file
- **Detailed logs**:
  - `*_removed_log.txt`: Vulnerabilities removed due to missing description/essential fields
  - `*_duplicates_removed_log.txt`: Vulnerabilities removed as exact duplicates (when `--allow-duplicates`)
  - `*_merge_log.txt`: Vulnerabilities actually merged (when `--allow-duplicates` is not active)
- **Metrics Evaluation**: Automatic comparison with baselines using BERT/ROUGE

## Dependencies

### System Requirements

- **Python**: 3.8+ (recommended: Python 3.10+)
- **RAM**: 4GB+ recommended for large PDF processing

### Main Python Dependencies

#### Core - LLM Framework and Processing

```pip-requirements
langchain>=0.1.0,<0.3.0          # Main framework for LLMs
langchain-openai>=0.1.0,<0.2.0   # OpenAI integration
```

#### PDF Processing - Optimized Text Extraction

```pip-requirements
pdfplumber>=0.10.0,<0.12.0       # PDF text extraction
```

#### UI/UX - Progress Bars and Feedback

```pip-requirements
tqdm>=4.0.0,<5.0.0               # Progress bars
```

#### Data Processing - Merge and Normalization

```pip-requirements
deepmerge>=1.1.0,<2.0.0          # Complex dictionary merge
```

#### Metrics Evaluation

```pip-requirements
rapidfuzz>=3.0.0,<4.0.0          # Fuzzy string matching
bert-score>=0.3.0,<0.4.0         # BERTScore for evaluation
rouge-score>=0.1.0,<0.2.0        # ROUGE metrics
```

#### Export Formats - CSV, XLSX

```pip-requirements
pandas>=1.3.0,<3.0.0             # DataFrames and manipulation
openpyxl>=3.0.0,<4.0.0           # Excel export
```

## Security Concerns

### API Keys Management

- **Environment Variables**: API keys are stored in `.env` file and should never be committed to public repositories
- **Variable Substitution**: JSON configuration files use `${VARIABLE_NAME}` syntax to reference environment variables
- **Access Control**: Ensure proper file permissions on `.env` file (readable only by application user)

### Data Privacy

- **PDF Content**: Security reports may contain sensitive information that is sent to LLM providers
- **Local Processing**: All PDF processing and extraction is performed locally
- **External APIs**: LLM providers (OpenAI, Groq, DeepSeek) receive chunks of PDF content for processing

### Network Security

- **SSL/TLS**: All API communications use HTTPS/TLS encryption
- **API Rate Limits**: Respect provider rate limits to avoid service disruption
- **Timeout Controls**: Configurable timeouts to prevent hanging connections

### Configuration Security

- **Template Injection**: Prompt templates should be carefully validated to prevent injection attacks
- **Input Sanitization**: PDF input is processed through secure libraries (pdfplumber)
- **Output Validation**: Extracted JSON is validated before saving

## Installation

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/vulnerability-extractor.git
cd Vulnerability_Extractor
```

#### 2. Virtual Environment (Highly Recommended)

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Docker (Optional)

### Building the Docker Image

```bash
docker build -t mulitaminer .
```

### Running with Docker Compose

```bash
docker-compose up -d
```

### Docker Environment Variables

Create a `.env` file in the root directory with your API keys:

```env
API_KEY_DEEPSEEK=your-deepseek-api-key
API_KEY_GPT4=your-openai-api-key
API_KEY_GPT5=your-openai-api-key
API_KEY_LLAMA3=your-groq-api-key
API_KEY_LLAMA4=your-groq-api-key
API_KEY_QWEN3=your-groq-api-key
```

### Running Extraction in Docker

```bash
docker run -v $(pwd):/workspace -v $(pwd)/.env:/app/.env mulitaminer python main.py /workspace/report.pdf
```

## Configuration

## Configuration

### API Key Configuration

API keys are configured via **environment variables** in the `.env` file. The system supports automatic variable substitution in JSON configuration files.

#### 1. Configure the .env file

Edit the existing `.env` file with your API keys:

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"
API_KEY_GPT4 = "your-openai-api-key"
API_KEY_GPT5 = "your-openai-api-key"
API_KEY_LLAMA3 = "your-groq-api-key"
API_KEY_LLAMA4 = "your-groq-api-key"
API_KEY_QWEN3 = "your-groq-api-key"
```

#### 2. How substitution works

JSON configuration files use the `${VARIABLE_NAME}` syntax to reference variables from `.env`:

```json
{
  "api_key": "${API_KEY_DEEPSEEK}",
  "endpoint": "https://api.deepseek.com/v1",
  "model": "deepseek-coder"
}
```

**⚠️ Security:** Never commit the `.env` file to public repositories!

### Token Calculation System

```
max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

#### Formula Components

| Component              | Description             | Example       |
| ---------------------- | ----------------------- | ------------- |
| `max_tokens`           | Model's total limit     | 8192 (Llama4) |
| `reserve_for_response` | Space for LLM response  | 5000 tokens   |
| `prompt_overhead`      | Template + instructions | 600 tokens    |
| `system_overhead`      | Metadata + overhead     | 500 tokens    |
| `safety_buffer`        | Safety margin           | 600 tokens    |

#### Real Configurations per LLM

| LLM          | Total Limit | Reserve | Final Chunk | Calculated Overhead | Efficiency |
| ------------ | ----------- | ------- | ----------- | ------------------- | ---------- |
| **GPT-4**    | 12,000      | 4,000   | **7,300**   | 700 tokens          | 60.8%      |
| **GPT-5**    | 16,000      | 6,000   | **8,300**   | 1,700 tokens        | 51.9%      |
| **DeepSeek** | 4,096       | 1,500   | **1,750**   | 846 tokens          | 42.7%      |
| **Llama3**   | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |
| **Llama4**   | 8,192       | 5,000   | **1,492**   | 1,700 tokens        | 18.2%      |
| **Qwen3**    | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |

## Usage

### CLI Interface

**Basic syntax:**

```bash
python main.py <pdf_path> [options]
```

### Main Parameters

#### Required Input

- `pdf_path`: **Path to the PDF file** of the vulnerability report

#### Processing Options

| Parameter   | Description      | Default   | Examples                             |
| ----------- | ---------------- | --------- | ------------------------------------ |
| `--scanner` | Scanner strategy | `default` | `tenable`, `openvas`, `cais_tenable` |
| `--llm`     | Language Model   | `gpt4`    | `deepseek`, `llama3`, `gpt5`         |

#### Export Options

| Parameter         | Description       | Default | Examples               |
| ----------------- | ----------------- | ------- | ---------------------- |
| `--convert`       | Conversion format | `none`  | `csv`, `xlsx`, `all`   |
| `--output-file`   | Output file name  | auto    | `vulnerabilities.json` |
| `--output-dir`    | Output folder     | current | `./results`            |
| `--csv-delimiter` | CSV separator     | `,`     | `;`                    |

#### Evaluation Options

| Parameter             | Description                 | Default                    |
| --------------------- | --------------------------- | -------------------------- |
| `--evaluate`          | Enable metrics evaluation   | `false`                    |
| `--baseline-file`     | Ground truth file (.xlsx)   | required with `--evaluate` |
| `--evaluation-method` | Method: `bert` or `rouge`   | `bert`                     |
| `--allow-duplicates`  | Allow legitimate duplicates | `false`                    |

### Usage Examples

#### Basic Usage

```bash
# Standard processing with GPT-4
python main.py report.pdf
# Specific scanner
python main.py report_tenable.pdf --scanner tenable
# Specific model
python main.py report.pdf --llm deepseek
```

#### Export Formats

```bash
# CSV with custom configuration
python main.py report.pdf --convert csv --csv-delimiter ";" --csv-encoding "iso-8859-1" --output-file "vulnerabilities_en.csv"
# Full export to Excel
python main.py large_report.pdf --scanner tenable --llm gpt5 --convert xlsx --output-dir ./results
# All formats simultaneously
python main.py report.pdf --convert all --output-dir ./exports
```

#### Advanced Usage: Extraction with Metrics Evaluation

```bash
# Extract vulnerabilities and evaluate extraction quality using the 'bert' method
python main.py report_tenable.pdf --scanner tenable --convert all --evaluate --baseline-file metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx --evaluation-method bert
# Evaluation with legitimate duplicates allowed (recommended for OpenVAS)
python main.py report_openvas.pdf --scanner openvas --llm deepseek --convert xlsx --evaluate --baseline-file metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx --allow-duplicates
```

### Batch Extraction

To process all PDFs in a directory in batch:

```bash
python tools/batch_pdf_extractor.py <pdfs_directory> --convert <format> --llm <model> --scanner <scanner> [--allow-duplicates] [--output-dir <dir>]
```

Example:

```bash
python tools/batch_pdf_extractor.py pdfs --scanner openvas --LLM deepseek --allow-duplicates --output-dir jsons
```

### Output Format

The tool generates a JSON file with the vulnerabilities found. The complete format includes specific fields for different types of reports:

```json
[
  {
    "Name": "SQL Injection",
    "description": ["Detailed description of the vulnerability"],
    "cvss": ["CVSSV4 BASE SCORE - number", "CVSSv3 VECTOR - string"],
    "port": "80",
    "protocol": "tcp", 
    "severity": "HIGH",
    "references": ["List of references"],
    "source": "OPENVAS"
  }
]
```

## Experiments

MulitaMiner was validated through practical experiments with different types of reports and LLM configurations.

### Test Scenarios

#### Tenable WAS Reports

- **Tested configuration**: Scanner `tenable` + LLM `gpt4`
- **Tested documents**: Reports of 50-200 pages
- **Results**: Efficient consolidation of instances/bases, accurate plugin detection
- **Optimization**: 7300-token chunks with smart vulnerability merge

#### OpenVAS/Greenbone Reports

- **Tested configuration**: Scanner `openvas` + LLM `llama3`
- **Tested documents**: NVT reports with 100-500 vulnerabilities
- **Results**: Complete extraction of 18 specialized fields (detection_result, impact, insight)
- **Optimization**: 3492-token chunks with processing via Groq

### Token Optimization Validation

#### Experiments

```bash
# Test with 300-page document
python main.py large_report.pdf --llm gpt4
# Result: 42 chunks processed

python chunk_validator.py large_report.pdf --llm gpt4
# Analysis: Uniform distribution, 60.8% efficiency
```

#### Experiment: Comparative Performance

```bash
# Comparative test between models
python main.py test_report.pdf --llm llama4  # Maximum precision (1492 tokens)
python main.py test_report.pdf --llm gpt4    # Balanced (7300 tokens)
python main.py test_report.pdf --llm deepseek # Technical efficiency (1750 tokens)

# Results:
# - Llama4: 83 chunks, slower processing, maximum precision
# - GPT-4: 18 chunks, balanced processing, good quality
# - DeepSeek: 76 chunks, fast processing, technical quality
```

### Performance Optimization Tips

#### By Report Size

| Size             | Recommendation | Justification                       |
| ---------------- | -------------- | ----------------------------------- |
| **< 50 pages**   | GPT-4/GPT-5    | Larger chunks, efficient processing |
| **50-200 pages** | Llama3/Qwen3   | Optimal balancing                   |
| **> 200 pages**  | Llama4         | More precise incremental processing |

#### By Analysis Type

| Scenario                | Best LLM    | Why?                              |
| ----------------------- | ----------- | --------------------------------- |
| **Technical Analysis**  | DeepSeek    | Specialized in code/security      |
| **Critical Processing** | GPT-5       | Maximum security and precision    |
| **Economy**             | Llama3/Groq | Efficient                         |
| **Debugging**           | Llama4      | Maximum precision in small chunks |

## Code Structure

```
Vulnerability_Extractor/
├── main.py                              # Main CLI script (entry point for extraction)
├── requirements.txt                     # Python dependencies
├── README.md                            # Documentation
├── chunk_validator.py                   # Chunk validator (standalone tool for chunk analysis)
├── batch_pdf_extractor.py               # Batch PDF extraction (processes multiple PDFs)
├── tools/
│   ├── run_experiments.py               # Massive execution and automated evaluation (benchmarks)
│   ├── process_results.py               # Chart and statistics generation (metrics visualization)
│   ├── dataset_generator.py             # Dataset consolidation (CSV/XLSX/JSON/JSONL)
│   ├── sum_tokens_cost_all_llms.py      # Sums tokens and estimates costs per LLM (cost analysis)
│   ├── calc_tokens_cost.py              # Calculates tokens/cost for a specific LLM (single model)
│   ├── prepare_metrics_input.py         # Generates combined files for metrics (preprocessing)
│   └── chunk_validator.py               # (link to root, for compatibility)
├── src/
│   ├── __init__.py
│   ├── configs/
│   │   ├── llms/                        # LLM configurations (JSON files for models)
│   │   ├── scanners/                    # Scanner configurations (JSON)
│   │   └── templates/                   # Prompt templates (TXT)
│   ├── converters/
│   │   ├── base_converter.py            # Base converter class
│   │   ├── csv_converter.py             # CSV/TSV export logic
│   │   └── xlsx_converter.py            # Excel export logic
│   ├── scanner_strategies/              # Modular scanner strategies
│   │   ├── __init__.py
│   │   ├── base.py                      # Base class for scanner strategies
│   │   ├── consolidation.py             # Central consolidation logic
│   │   ├── openvas.py                   # OpenVAS custom strategy
│   │   ├── registry.py                  # Strategy registry (maps scanner to logic)
│   │   └── tenablewas.py                # Tenable WAS custom strategy
│   └── utils/
│       ├── block_creation.py            # Block creation and parsing logic
│       ├── cais_validator.py            # CAIS format validation
│       ├── chunking.py                  # Chunk calculation and optimization
│       ├── cli_args.py                  # CLI argument parsing
│       ├── convertions.py               # Data conversion helpers
│       ├── llm_utils.py                 # LLM loading and configuration
│       ├── pdf_loader.py                # PDF text extraction and layout preservation
│       ├── processing.py                # Main processing pipeline
│       └── profile_registry.py          # Profile and scanner registration
├── metrics/
│   ├── __init__.py
│   ├── baselines/
│   │   ├── openvas/                     # Baseline files for OpenVAS
│   │   └── tenable/                     # Baseline files for Tenable WAS
│   ├── bert/
│   │   └── compare_extractions_bert.py  # BERTScore evaluation script
│   ├── rouge/
│   │   └── compare_extractions_rouge.py # ROUGE evaluation script
│   ├── common/
│   │   ├── cli.py                       # CLI for metrics
│   │   ├── config.py                    # Metrics configuration
│   │   ├── matching.py                  # Matching logic for metrics
│   │   └── normalization.py             # Normalization utilities
│   └── plot/
│       ├── __init__.py
│       ├── __main__.py                  # CLI entry for plotting
│       ├── charts.py                    # Chart generation logic
│       └── utils.py                     # Plotting utilities
├── data/                                # Datasets generated (CSV, XLSX, JSON, JSONL)
├── jsons/                               # JSONs used in the dataset generation
├── results_tokens/                      # Token files per LLM (token/cost analysis)
├── results_runs/                        # Experimental run results (run_experiments.py)
├── results_runs_xlsx/                   # XLSX results (run_experiments.py)µ
├── plot_runs/                           # Generated charts (metrics visualization)
└── temp_blocks/                         # Temporary vulnerability blocks (intermediate parsing)
```

### Main Components

#### Interface Scripts

- **main.py**: Main CLI with modern arguments and full orchestration
- **chunk_validator.py**: Chunk analysis and validation tool

#### Processing System

- **processing.py**: Chunking engine with automatic token calculation
- **utils.py**: Smart LLM loading with optimized configurations per model
- **pdf_loader.py**: Optimized text extraction with layout preservation

#### Specialized Strategies

- **scanner_strategies.py**: Specialized processing logic per report type
- **profile_registry.py**: Profile/scanner registration and discovery system
- **cais_validator.py**: Specific validation for CAIS format

#### Export System

- **base_converter.py**: Base framework for converters
- **csv_converter.py**: CSV/TSV export with customizable settings
- **xlsx_converter.py**: Excel export with advanced formatting

## Extensibility

### Adding a new scanner

MulitaMiner was designed to be easily expanded, allowing integration of new scanners (extraction tools) without changing the system core. See the recommended flow:

1. **Create a prompt template**
   - Add a file in `src/configs/templates/` (e.g., `rapid7_prompt.txt`).
   - The template should explain to the LLM how to extract vulnerabilities from the report, mapping fields to the standard JSON format.
   - Check existing templates for examples.

**Prompt template example:**

```txt
You will receive a vulnerability report. Extract each vulnerability as a JSON object with the following fields:
{
  "Name": "Vulnerability name",
  "description": "Detailed description",
  "severity": "Severity (LOW/MEDIUM/HIGH/CRITICAL)",
  "asset": "Affected asset",
  "name_consolidated": "Consolidated name for deduplication (e.g., Name + asset)"
}
Separate each vulnerability by line. Do not include any extra text.
```

2. **Create a scanner profile**

- Add a JSON file in `src/configs/scanners/` (e.g., `rapid7.json`).
- Define: scanner name, template path, consolidation fields (`consolidation_field`), duplicate rules, retry parameters, etc.

3. **(Optional) Custom block logic**

- If the report has no clear separators, or requires special grouping (e.g., by asset, plugin, section), implement a function in `src/utils/block_creation.py`.
- Integrate in the `create_session_blocks_from_text` method.

4. **(Optional) Custom consolidation logic (strategy for allow_duplicates)**

- If the scanner needs special rules to group/merge vulnerabilities (e.g., merge by asset, plugin, custom field), create a class in a new `.py` file inside `src/scanner_strategies/` (e.g., `mycustomscanner.py`).
- Your class must inherit from `ScannerStrategy` (see `base.py`) and implement the method `consolidate_all(self, vulns, allow_duplicates=True, profile_config=None)`.
- Register your class in the system by adding it to the dictionary in `src/scanner_strategies/registry.py`.

5. **Testing and validation**

- Run extractions with `main.py` using the new scanner.
- Use `chunk_validator.py` to validate chunk division and data integrity.
- Check if the extracted fields are correct and if the JSON follows the expected standard.

### Adding a new LLM

The system accepts any model compatible with the OpenAI API, just create a JSON configuration file in `src/configs/llms/`.

**Configuration example:**

```json
{
  "api_key": "${API_KEY_ANTHROPIC}",
  "endpoint": "https://api.anthropic.com/v1",
  "model": "claude-3-haiku-20240307",
  "temperature": 0,
  "max_tokens": 4096,
  "timeout": 60,
  "reserve_for_response": 3000,
  "prompt_overhead": 300,
  "system_overhead": 200,
  "safety_buffer": 200,
  "max_chunk_size": 2396,
  "calculation_formula": "max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer"
}
```

**Important fields:**

- `api_key`: API key (use `${VARIABLE_NAME}` to reference variables from .env)
- `endpoint`: Endpoint URL
- `model`: Model name
- Chunking and safety parameters

### Extension Points

- `src/configs/llms/`: New LLM providers
- `src/configs/scanners/`: New processing strategies  
- `src/configs/templates/`: New extraction templates
- `src/converters/`: New export formats

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).

- **Permitted use:** free for use, modification, distribution, and sublicensing, including for commercial purposes.
- **Notice:** provided "as is", without warranties. The user is responsible for use and secure configuration of data and keys.

See the [LICENSE](LICENSE) file for the full license text.
