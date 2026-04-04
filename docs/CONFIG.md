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

The MulitaMiner system uses a **two-phase approach** for token management:

### Phase 1: Chunking Strategy (Fixed Values)

The system uses **hardcoded values** in `extract_vulns_from_blocks()`:

```python
# Chunking phase uses fixed limits regardless of LLM config
token_chunks = get_token_based_chunks(block_text, max_tokens=4096, profile_config=profile_config)
split_text_to_subchunks(tc.page_content, target_size=8000, profile_config=profile_config)
```

**Actual chunking formula:**
```
chunk_size = 4096 - reserve_for_response (default: 1000) = ~3096 tokens per chunk
```

### Phase 2: Runtime Validation (Dynamic)

Each chunk is validated using **actual LLM limits** from config files:

```python
total_tokens = prompt_tokens + chunk_tokens + response_tokens
validation_limit = max_tokens - 500  # 500-token safety buffer
```

**Validation components:**

| Component       | Source                           | Default/Example  |
| --------------- | -------------------------------- | ---------------- |
| `prompt_tokens` | Dynamic (calculated from template) | 800 tokens       |
| `chunk_tokens`  | Dynamic (actual content)         | Varies           |
| `response_tokens` | Dynamic (LLM response)          | Varies           |
| `max_tokens`    | LLM config file                  | 4096-16000       |
| `safety_buffer` | Hardcoded                        | 500 tokens       |

### Current LLM Configurations vs Implementation

**⚠️ IMPORTANT:** Chunking uses FIXED 4096-token limit regardless of LLM config!

| LLM          | Config max_tokens | Config Reserve | **Actual Chunking** | Validation Limit | Efficiency |
| ------------ | ----------------- | -------------- | ------------------- | ---------------- | ---------- |
| **GPT-4**    | 12,000            | 4,000          | **~3,096**          | 11,500           | ~26%       |
| **GPT-5**    | 16,000            | 7,000          | **~3,096**          | 15,500           | ~19%       |
| **DeepSeek** | 4,096             | 1,500          | **~3,096**          | 3,596            | ~75%       |
| **Llama3**   | 8,192             | 4,000          | **~3,096**          | 7,692            | ~38%       |
| **Llama4**   | 8,192             | 5,000          | **~3,096**          | 7,692            | ~38%       |
| **Qwen3**    | 5,000             | 3,000          | **~3,096**          | 4,500            | ~62%       |

**Key Findings:**
- All models use the **same chunking size** (~3,096 tokens)
- LLM-specific configs are **only used for validation**
- High-capacity models (GPT-4/5) are **severely underutilized**
- Only DeepSeek and Qwen3 achieve reasonable efficiency

### Implementation Reality

**Chunking Phase (block_creation.py):**
```python
# FIXED VALUES - ignores LLM configs completely
max_tokens = 4096  # hardcoded
reserve = 1000     # default if not specified in get_token_based_chunks
chunk_size = 4096 - 1000 = 3096 tokens
```

**Validation Phase (validate_json_and_tokens):**
```python
# Uses ACTUAL LLM config values
prompt_tokens = len(tokenize(prompt_template)) or 800  # dynamic
chunk_tokens = len(tokenize(chunk_content))           # actual content
response_tokens = len(tokenize(llm_response))         # actual response
total_tokens = prompt_tokens + chunk_tokens + response_tokens

# Validation against LLM-specific limit
if total_tokens > (llm_config.max_tokens - 500):
    flag_for_redivision = True
```

> **🔍 Discovery**: The `max_chunk_size` values in LLM config files are **unused**! The system ignores model-specific chunking limits and uses a one-size-fits-all approach.

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
  "max_chunk_size": 2396,
  "note": "max_chunk_size is IGNORED by implementation",
  "actual_chunking": "Fixed 4096-token limit, chunk_size = 4096 - reserve (default: 1000)",
  "validation_only": "max_tokens used only for runtime validation <= (max_tokens - 500)"
}
```

### Important Fields

- `api_key`: API key (use `${VARIABLE_NAME}` to reference variables from .env)
- `endpoint`: Endpoint URL
- `model`: Model name
- `temperature`: Creativity level (0 = deterministic)
- `max_tokens`: **Used ONLY for validation** (runtime limit checking)
- `reserve_for_response`: **Used for chunking calculation** (4096 - this value)
- `max_chunk_size`: **⚠️ IGNORED by implementation** (documentation artifact)

**Reality Check:**
- **Chunking**: Uses hardcoded 4096-token base regardless of `max_tokens`
- **Validation**: Uses `max_tokens` from config to check final token count
- **Efficiency**: High-capacity models are underutilized due to fixed chunking

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
