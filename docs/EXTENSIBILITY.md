# Extensibility Guide

This document explains how to extend MulitaMiner with new scanners and LLM providers.

## Adding a New Scanner

MulitaMiner was designed to be easily expanded, allowing integration of new scanners (extraction tools) without changing the system core.

### 1. Create a Prompt Template

Add a file in `src/configs/templates/` (e.g., `rapid7_prompt.txt`).

The template should explain to the LLM how to extract vulnerabilities from the report, mapping fields to the standard JSON format. Check existing templates for examples.

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

### 2. Create a Scanner Profile

Add a JSON file in `src/configs/scanners/` (e.g., `rapid7.json`).

Define: scanner name, template path, consolidation fields (`consolidation_field`), duplicate rules, retry parameters, etc.

### 3. (Optional) Custom Block Logic

If the report has no clear separators, or requires special grouping (e.g., by asset, plugin, section):

- Implement a function in `src/utils/block_creation.py`
- Integrate in the `create_session_blocks_from_text` method

**If not implemented:** The system divides the text into sequential chunks based on the LLM's token limit. This works well for structured reports, but may mix vulnerabilities in more complex ones.

### 4. (Optional) Custom Consolidation Logic

If the scanner needs special rules to group/merge vulnerabilities:

1. Create a class in a new `.py` file inside `src/scanner_strategies/` (e.g., `mycustomscanner.py`)
2. Inherit from `ScannerStrategy` (see `base.py`)
3. Implement the method `consolidate_all(self, vulns, allow_duplicates=True, profile_config=None)`
4. Register your class in `src/scanner_strategies/registry.py`

The key you use to register must match the scanner name declared in your profile JSON.

**Important:** The custom function name must be strictly `vulnerability_processing_logic`:

```python
def vulnerability_processing_logic(self, vulns, allow_duplicates=True, profile_config=None):
    # ... your vulnerability processing logic ...
```

### Deduplication and Merge Behavior

The `consolidation_field` defines which field will be used to identify duplicates (e.g., "Name", "Name+asset"). If there is custom logic, it always prevails.

| Scanner Type | `--allow-duplicates` **disabled**          | `--allow-duplicates` **enabled**               |
| ------------ | ------------------------------------------ | ---------------------------------------------- |
| **Generic**  | Removes duplicates by consolidation field  | Keeps all duplicates                           |
| **Custom**   | Advanced merge/grouping (scanner strategy) | Simple deduplication (key defined in strategy) |

**How custom strategies are selected:**

- For OpenVAS, the custom strategy is used only when `allow_duplicates=True` (maximum granularity, recommended)
- For Tenable WAS, the custom strategy is used only when `allow_duplicates=False` (smart merge, recommended)
- In all other cases, the default logic using `consolidation_field` is applied

> **Note:** `--allow-duplicates` preserves occurrences when repetition represents services, ports, or distinct instances.

### 5. Testing and Validation

- Run extractions with `main.py` using the new scanner
- Use `chunk_validator.py` to validate chunk division and data integrity
- Check if the extracted fields are correct and if the JSON follows the expected standard

**Practical summary:** For most cases, just create the template and JSON profile. Optional steps are recommended for scanners with complex reports or specific grouping rules.

---

## Adding a New LLM

The system accepts any model compatible with the OpenAI API. Just create a JSON configuration file in `src/configs/llms/`.

### Configuration Example

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
- Chunking and safety parameters

### Tested Models

- **OpenAI**: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`
- **Groq**: `llama-3.1-8b-instant`, `mixtral-8x7b-32768`
- **Anthropic**: `claude-3-haiku`, `claude-3-sonnet`
- **DeepSeek**: `deepseek-chat`
- Any API compatible with OpenAI format

---

## Extension Points

| Extension Point           | Location                  | Purpose                      |
| ------------------------- | ------------------------- | ---------------------------- |
| New LLM providers         | `src/configs/llms/`       | Add new model configurations |
| New processing strategies | `src/configs/scanners/`   | Define scanner behavior      |
| New extraction templates  | `src/configs/templates/`  | Custom prompts for LLMs      |
| New export formats        | `src/converters/`         | Add CSV, XLSX, etc.          |
| New scanner strategies    | `src/scanner_strategies/` | Custom consolidation logic   |

### Automatic Validation

- **Token calculation**: automatic for new LLMs
- **Template validation**: JSON format check
- **Scanner test**: `chunk_validator.py` for debugging
- **Integration test**: end-to-end extraction with real documents

The system was designed to grow organically, maintaining compatibility with existing configurations and facilitating integration of new security tools and LLMs.
