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

## Token Calculation

MulitaMiner automatically calculates optimal chunk sizes based on:

### Calculation Strategy

```
max_chunk_size = max_tokens - reserve_for_response
```

The system then uses the tokenizer (tiktoken or HuggingFace) to:

1. Count tokens accurately per model
2. Split documents intelligently (respecting marker boundaries)
3. Ensure each chunk fits within token limits

### Examples

| Model            | Max Tokens | Reserve | Effective Chunk |
| ---------------- | ---------- | ------- | --------------- |
| gpt-4o-mini      | 14,500     | 3,500   | ~14,000 tokens  |
| gpt-5-mini       | 16,000     | 5,000   | ~10,000 tokens  |
| deepseek-coder   | 8,192      | 3,500   | ~7,500 tokens   |
| granite-4-tiny   | 1,500      | 600     | ~4,000 tokens   |
| mistral (Ollama) | 20,000     | 3,500   | ~15,000 tokens  |

> **Note:** Actual chunk size may be slightly less to keep vulnerability records intact (splits at marker boundaries, not mid-record)

## LLM Configuration Files

LLM configurations are stored in `src/configs/llms/`. Each JSON file defines model settings with automatic provider detection.

### Modern Configuration Structure

Current JSON files use a simplified, provider-aware structure:

**Example 1: Remote API (OpenAI)**

```json
{
  "api_key": "${API_KEY_GPT4}",
  "endpoint": "https://api.openai.com/v1",
  "model": "gpt-4o-mini-2024-07-18",
  "temperature": 0.0,
  "max_completion_tokens": 14500,
  "max_chunk_size": 14000,
  "reserve_for_response": 3500,
  "tokenizer": {
    "type": "tiktoken",
    "model": "cl100k_base"
  }
}
```

**Example 2: Local (LLM Studio - Granite)**

```json
{
  "provider": "lm_studio",
  "model": "ibm/granite-4-h-tiny",
  "endpoint": "http://localhost:1234/v1",
  "temperature": 0.0,
  "max_tokens": 1500,
  "max_chunk_size": 4000,
  "reserve_for_response": 600,
  "timeout": 180,
  "tokenizer": {
    "type": "huggingface",
    "model": "ibm-granite/granite-4.0-h-tiny"
  }
}
```

**Example 3: Local (Ollama)**

```json
{
  "provider": "ollama",
  "model": "mistral",
  "endpoint": "http://localhost:11434",
  "temperature": 0.0,
  "max_tokens": 4096,
  "max_chunk_size": 2800,
  "reserve_for_response": 1000,
  "timeout": 120,
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
  }
}
```

### Important Fields

- **`api_key`** _(optional for local)_: Use `${VAR_NAME}` for .env substitution
- **`provider`** _(optional, default `"openai"`)_: Which backend to use —
  `"openai"` (any OpenAI-compatible API: OpenAI, DeepSeek, Groq, …), `"ollama"`,
  `"lm_studio"`, or `"huggingface"` (alias `"hf"`). Omit it only for
  OpenAI-compatible endpoints; **local backends must set it explicitly**.
- **`endpoint`**: Service URL
- **`model`**: Model identifier
- **`temperature`**: 0.0 for deterministic (recommended), higher for creative
- **`max_tokens`** or **`max_completion_tokens`**: Total token limit
- **`max_chunk_size`**: Chunk size for document processing
- **`reserve_for_response`**: Tokens reserved for model output
- **`timeout`**: Request timeout (important for local models)
- **`tokenizer`**: Specifies how to count tokens
  - Type: `"tiktoken"` (OpenAI models) or `"huggingface"` (open models)
  - Model: Tokenizer model ID (must match LLM)

### Provider Resolution

The provider is taken from the `"provider"` field. If omitted, it defaults to
`"openai"` (which handles any OpenAI-compatible endpoint — OpenAI, DeepSeek,
Groq, …). There is no endpoint sniffing: a local backend (Ollama, LM Studio)
**must** declare `"provider"` explicitly, e.g. `"provider": "ollama"`.

The name is resolved through the provider registry (`init_llm`), so a custom
provider added via `@register_provider("name")` is available the same way — see
[EXTENSIBILITY.md → Create Custom Provider](EXTENSIBILITY.md#option-3-create-custom-provider).

## Scanner Configuration Files

Scanner configurations are stored in `src/configs/scanners/`. Each JSON file defines processing rules:

- Scanner name and type
- Template path for prompts
- Consolidation fields for deduplication
- Retry parameters
- Field mappings

## Supported LLM Providers

### System-Level Providers Available

The system supports multiple provider types. Set `"provider"` to one of:

| Provider      | Type         | Endpoint                     | Location | `"provider"` value       |
| ------------- | ------------ | ---------------------------- | -------- | ------------------------ |
| `openai`      | Remote API   | any OpenAI-compatible API    | Cloud    | `"openai"` (or omit)     |
| `ollama`      | Local        | localhost:11434              | Local    | `"ollama"`               |
| `lm_studio`   | Local        | localhost:1234 (default)     | Local    | `"lm_studio"`            |
| `huggingface` | Remote/Local | api-inference.huggingface.co | Variable | `"huggingface"` / `"hf"` |