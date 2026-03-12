# Configuration Guide

This document covers all configuration options for MulitaMiner.

## API Key Configuration

API keys are configured via **environment variables** in the `.env` file. The system supports automatic variable substitution in JSON configuration files.

### 1. Configure the .env file

Edit the existing `.env` file with your API keys:

```env
API_KEY_DEEPSEEK = "your-deepseek-api-key"
API_KEY_GPT4 = "your-openai-api-key"
API_KEY_GPT5 = "your-openai-api-key"
API_KEY_LLAMA3 = "your-groq-api-key"
API_KEY_LLAMA4 = "your-groq-api-key"
API_KEY_QWEN3 = "your-groq-api-key"
```

### 2. How substitution works

JSON configuration files use the `${VARIABLE_NAME}` syntax to reference variables from `.env`:

```json
{
  "api_key": "${API_KEY_DEEPSEEK}",
  "endpoint": "https://api.deepseek.com/v1",
  "model": "deepseek-coder"
}
```

> **⚠️ Security:** Never commit the `.env` file to public repositories!

## Token Calculation System

The system uses precise mathematical calculations to determine optimal chunk sizes for each LLM:

```
max_chunk_size = max_tokens - reserve_for_response - prompt_overhead - system_overhead - safety_buffer
```

### Formula Components

| Component              | Description             | Example       |
| ---------------------- | ----------------------- | ------------- |
| `max_tokens`           | Model's total limit     | 8192 (Llama4) |
| `reserve_for_response` | Space for LLM response  | 5000 tokens   |
| `prompt_overhead`      | Template + instructions | 600 tokens    |
| `system_overhead`      | Metadata + overhead     | 500 tokens    |
| `safety_buffer`        | Safety margin           | 600 tokens    |

### Real Configurations per LLM

| LLM          | Total Limit | Reserve | Final Chunk | Calculated Overhead | Efficiency |
| ------------ | ----------- | ------- | ----------- | ------------------- | ---------- |
| **GPT-4**    | 12,000      | 4,000   | **7,300**   | 700 tokens          | 60.8%      |
| **GPT-5**    | 16,000      | 6,000   | **8,300**   | 1,700 tokens        | 51.9%      |
| **DeepSeek** | 4,096       | 1,500   | **1,750**   | 846 tokens          | 42.7%      |
| **Llama3**   | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |
| **Llama4**   | 8,192       | 5,000   | **1,492**   | 1,700 tokens        | 18.2%      |
| **Qwen3**    | 8,192       | 4,000   | **3,492**   | 700 tokens          | 42.6%      |

**Calculated Overhead** = (Total Limit - Reserve) - Final Chunk

### Value Interpretation

- **Overhead varies by LLM**: More complex templates require more space
- **Reserve for response**: Based on real tests of model verbosity
- **Efficiency**: Percentage of the total limit used for chunk processing

> **Note:** The values in the tables are based on practical tests and benchmarks with major LLM providers (OpenAI, Groq, DeepSeek). They reflect real usage scenarios but may vary depending on the model, prompt template, and provider updates.

## LLM Configuration Files

LLM configurations are stored in `src/configs/llms/`. Each JSON file defines:

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

### Important Fields

- `api_key`: API key (use `${VARIABLE_NAME}` to reference variables from .env)
- `endpoint`: Endpoint URL
- `model`: Model name
- `temperature`: Creativity level (0 = deterministic)
- `max_tokens`: Maximum tokens for the model
- `reserve_for_response`: Space reserved for LLM output
- `max_chunk_size`: Calculated optimal chunk size

## Scanner Configuration Files

Scanner configurations are stored in `src/configs/scanners/`. Each JSON file defines processing rules:

- Scanner name and type
- Template path for prompts
- Consolidation fields for deduplication
- Retry parameters
- Field mappings

## Supported LLM Providers

### Tested Models

- **OpenAI**: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`, `gpt-5`
- **Groq**: `llama-3.1-8b-instant`, `llama-4`, `mixtral-8x7b-32768`, `qwen3`
- **Anthropic**: `claude-3-haiku`, `claude-3-sonnet`
- **DeepSeek**: `deepseek-chat`, `deepseek-coder`
- Any API compatible with OpenAI format

### Optimization Recommendations

| Report Size  | Recommended LLM | Justification                       |
| ------------ | --------------- | ----------------------------------- |
| < 50 pages   | GPT-4/GPT-5     | Larger chunks, efficient processing |
| 50-200 pages | Llama3/Qwen3    | Optimal balancing                   |
| > 200 pages  | Llama4          | More precise incremental processing |

| Analysis Type       | Best LLM    | Why?                              |
| ------------------- | ----------- | --------------------------------- |
| Technical Analysis  | DeepSeek    | Specialized in code/security      |
| Critical Processing | GPT-5       | Maximum security and precision    |
| Economy             | Llama3/Groq | Efficient                         |
| Debugging           | Llama4      | Maximum precision in small chunks |
