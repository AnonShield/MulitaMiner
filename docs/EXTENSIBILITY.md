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
3. Implement the method `vulnerability_processing_logic(self, vulns, allow_duplicates=True, profile_config=None)` - this is where your consolidation/deduplication logic goes
4. (Optional) Override `get_consolidation_report()` to provide structured information about your consolidation process
5. Register your class in `src/scanner_strategies/registry.py`

The key you use to register must match the scanner name declared in your profile JSON.

#### Required Method: `vulnerability_processing_logic`

```python
def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
    """
    Your consolidation/merge/deduplication logic here.

    Args:
        vulns: List of vulnerability dictionaries
        allow_duplicates: Flag indicating deduplication preference (your strategy can ignore this)
        profile_config: Scanner profile configuration dict

    Returns:
        List of consolidated vulnerabilities
    """
    # Example: group by (Name, port, protocol) and keep most complete
    if not vulns:
        return []

    from collections import defaultdict
    grouped = defaultdict(list)
    for v in vulns:
        key = (v.get('Name', ''), v.get('port'), v.get('protocol'))
        grouped[key].append(v)

    result = []
    for group in grouped.values():
        # Keep the most complete (most fields filled)
        most_complete = max(group, key=lambda v: sum(1 for val in v.values() if val))
        result.append(most_complete)

    return result
```

#### Optional Method: `get_consolidation_report`

Override this method to provide detailed, human-readable information about your consolidation process. This report will be included in the consolidation log file.

```python
def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
    """
    Return structured information about the consolidation process.

    Returns a dict with keys:
        - strategy_name: Name of your strategy
        - description: Human-readable description
        - input_count: Vulnerabilities before consolidation
        - output_count: Vulnerabilities after consolidation
        - removed: Number removed during consolidation
        - reason: Why vulnerabilities were removed (e.g., "duplicate merge", "invalid description")
        - note: (optional) Additional context
    """
    return {
        'strategy_name': 'MyCustomScanner merge',
        'description': 'Groups vulnerabilities by (Name, port, protocol), keeps most complete',
        'input_count': input_count,
        'output_count': output_count,
        'removed': removed,
        'reason': 'duplicate consolidation',
        'note': 'Custom logic for MyCustomScanner vulnerability format'
    }
```

**Example:** See `src/scanner_strategies/openvas.py` for a complete implementation.

### Understanding the Consolidation Pipeline

The consolidation process has **two stages**:

1. **Strategy-Specific Consolidation**: Your custom logic processes vulnerabilities and may remove/merge some
2. **Description Validation Filtering**: Vulnerabilities with empty/invalid descriptions are removed

Each stage is logged separately and clearly in the consolidation report, so users understand exactly what happened to their data.

### Consolidation Log Output

The system generates a detailed, human-readable consolidation log (e.g., `output_deduplication_log.txt`) showing:

```
======================================================================
CONSOLIDATION & DEDUPLICATION REPORT
======================================================================

Strategy: OpenVAS custom merge
Description: Groups vulnerabilities by (Name, port, protocol), keeps most complete

INPUT VULNERABILITIES: 46

PROCESSING STAGE 1: Strategy-Specific Consolidation
  Result: 36 vulnerabilities
  Removed: 10 (duplicate merge)
  Note: This is the custom OpenVAS consolidation strategy

PROCESSING STAGE 2: Description Validation Filter
  Removed: 0 (empty or invalid descriptions)
  Result: 36 vulnerabilities

OUTPUT FINAL: 36 vulnerabilities (valid & saved)
```

This modular structure allows your custom strategy to be easily understood by users.

### Deduplication and Merge Behavior

The `consolidation_field` in your scanner profile defines which field will be used for default deduplication (e.g., "Name", "Name+asset"). If you provide a custom strategy, it always takes precedence.

| Scenario                                      | Behavior                                                       |
| --------------------------------------------- | -------------------------------------------------------------- |
| Custom strategy + `allow_duplicates=False`    | Your custom logic runs (you can respect the flag or ignore it) |
| Custom strategy + `allow_duplicates=True`     | Your custom logic runs (you can respect the flag or ignore it) |
| No custom strategy + `allow_duplicates=False` | Removes duplicates by `consolidation_field`                    |
| No custom strategy + `allow_duplicates=True`  | Keeps all vulnerabilities unchanged                            |

**Important:** Your strategy receives the `allow_duplicates` flag, but is free to interpret it as you wish. For example:

- OpenVAS ignores it and always performs consolidation (the flag is just informational)
- A future strategy might use it to switch between aggressive and conservative merging

> **Note:** `--allow-duplicates` at the CLI level is meant to preserve occurrences when repetition represents services, ports, or distinct instances. Your custom strategy decides how to interpret this for your specific scanner format.

### 5. Testing and Validation

- Run extractions with `main.py` using the new scanner
- Check the consolidation log file (`*_deduplication_log.txt`) to verify your strategy's behavior:
  - Verify input/output counts match your expectations
  - Check the "PROCESSING STAGE" details
  - Review "Detail: Vulnerability Groups" to ensure correct grouping
- Use `chunk_validator.py` to validate chunk division and data integrity
- Check if the extracted fields are correct and if the JSON follows the expected standard

**Practical summary:** For most cases, just create the template and JSON profile. Custom consolidation is recommended for scanners with complex reports or specific grouping/merging rules. Always implement `get_consolidation_report()` if you have custom logic, so users understand what your strategy does.

### Real-World Example: Adding a Custom Strategy

Suppose you want to add support for "MyCorp Scanner" which has a unique format where vulnerabilities can be grouped by asset ID:

**Step 1: Create the strategy** (`src/scanner_strategies/mycorp.py`):

```python
from typing import List, Dict
from .base import ScannerStrategy
from collections import defaultdict

class MyCorporpStrategy(ScannerStrategy):
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        if not vulns:
            return []

        # Group by (Name, asset_id) - MyCorp specific format
        grouped = defaultdict(list)
        for v in vulns:
            key = (v.get('Name', ''), v.get('asset_id', 'unknown'))
            grouped[key].append(v)

        # Merge: keep the one with most information
        result = []
        for group in grouped.values():
            best = max(group, key=lambda v: len([x for x in v.values() if x]))
            result.append(best)

        return result

    def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
        return {
            'strategy_name': 'MyCorp Scanner merge',
            'description': 'Groups by (Name, asset_id) and keeps most complete',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'asset-based deduplication',
            'note': 'MyCorp uses asset_id for vulnerability tracking'
        }
```

**Step 2: Register it** (`src/scanner_strategies/registry.py`):

```python
from .mycorp import MyCorporpStrategy

SCANNER_STRATEGIES = {
    'openvas': OpenVASStrategy(),
    'tenable': TenableWASStrategy(),
    'mycorp': MyCorporpStrategy(),  # Add this line
}
```

**Step 3: Create profile** (`src/configs/scanners/mycorp.json`):

```json
{
  "reader": "MyCorp",
  "template": "mycorp_prompt.txt",
  "consolidation_field": "Name",
  "allow_duplicates_default": false
}
```

**Step 4: Test:**

```bash
./main.py --input report.txt --scanner mycorp --llm gpt-4
```

Check the log file to verify consolidation worked correctly!

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
