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

MulitaMiner segments reports into **blocks** (preserving report structure) before dividing into **chunks** (respecting token limits). This ensures the LLM processes related vulnerabilities together.

- **OpenVAS** example: Blocks group by `(severity, port, protocol)` — naturally preserving report sessions
- **Tenable** example: Blocks group by severity — logically grouping related vulnerabilities
- **Default behavior:** If no custom logic, creates a single block with entire report

**If your scanner has a unique report structure** (e.g., grouped by asset, plugin family, or custom sections), implement custom block logic in your `ScannerStrategy` subclass:

#### In your strategy file (e.g., `src/scanner_strategies/mynewscanner.py`):

```python
class MyNewScannerStrategy(ScannerStrategy):
    scanner_name = 'mynewscanner'
    requires_visual_layout = False  # Set to True if you need visual layout

    def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
        """Optional: Extract context from visual layout."""
        # Your custom logic here
        return initial_context_lines, severity, port, protocol

    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple) -> List[Dict]:
        """Optional: Create custom blocks."""
        # Your block creation logic here
        # Return list of {'file': path, 'port': port, 'protocol': protocol, 'severity': severity}
        return blocks
```

Then register in `src/scanner_strategies/registry.py`:

```python
from .mynewscanner import MyNewScannerStrategy

SCANNER_STRATEGIES = {
    'openvas': OpenVASStrategy(),
    'tenable': TenableWASStrategy(),
    'mynewscanner': MyNewScannerStrategy(),  # ← Add here
}
```

**If not implemented:** The base class provides default behavior:

- Returns empty visual context (backward compatible)
- Creates a single block with the entire report text

### 4. (Optional) Custom Consolidation Logic

If your scanner needs special rules to group/merge vulnerabilities, implement a **modular activation system** that gives users control over when custom consolidation activates:

#### Step 1: Create Your Strategy Class

1. Create a class in a new `.py` file inside `src/scanner_strategies/` (e.g., `mycustomscanner.py`)
2. Inherit from `ScannerStrategy` (see `base.py`)
3. Register your class in `src/scanner_strategies/registry.py`

The key you use to register must match the scanner name declared in your profile JSON.

#### Step 2: Implement `get_custom_activation_value()` (REQUIRED)

This method defines **WHEN** your custom consolidation activates:

```python
def get_custom_activation_value(self) -> bool | set | list | tuple | None:
    """
    Define when custom consolidation activates based on --allow-duplicates flag.
    
    Returns:
        bool:              Activates when flag matches (True or False)
        set/list/tuple:    Activates for multiple flag values (e.g., {True, False})
        None:              No custom consolidation (always use default)
    
    Examples:
        return True           # Custom runs when --allow-duplicates is provided
        return False          # Custom runs when --allow-duplicates is NOT provided
        return {True, False}  # Custom runs in BOTH cases (but with different logic)
        return None           # No custom (always use default deduplication)
    """
    # Example: activate custom when user wants NO duplicates
    return False
```

**Behavior Matrix:**

| Your Custom Activation | CLI Flag | Result |
|------------------------|----------|--------|
| `True` | `--allow-duplicates` | ✅ Runs CUSTOM |
| `True` | (no flag) | Runs DEFAULT |
| `False` | `--allow-duplicates` | Runs DEFAULT |
| `False` | (no flag) | ✅ Runs CUSTOM |
| `{True, False}` | `--allow-duplicates` | ✅ Runs CUSTOM (True logic) |
| `{True, False}` | (no flag) | ✅ Runs CUSTOM (False logic) |
| `None` | Any | Always DEFAULT |

#### Step 3: Implement `vulnerability_processing_logic()` (REQUIRED)

```python
def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
    """
    Your consolidation/merge/deduplication logic here.

    Args:
        vulns: List of vulnerability dictionaries
        allow_duplicates: Current flag value (for reference in dual-custom scenarios)
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

#### Step 4: Implement `get_consolidation_report()` (OPTIONAL)

Override this method to provide detailed information about your consolidation process:

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

#### Advanced Example: Dual Custom (Different Logic per Flag)

If you need DIFFERENT logic depending on the flag value:

```python
def get_custom_activation_value(self) -> bool | set | list | tuple | None:
    return {True, False}  # Activate in BOTH cases

def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
    if allow_duplicates is True:
        # Logic A: Keep all distinct names, merge by port
        return self._merge_by_port(vulns)
    else:
        # Logic B: Keep all distinct names+plugin, strong consolidation
        return self._consolidate_by_plugin(vulns)

def _merge_by_port(self, vulns):
    # Your Port-based merge logic
    pass

def _consolidate_by_plugin(self, vulns):
    # Your plugin-based consolidation logic
    pass
```

**Examples:** See `src/scanner_strategies/openvas.py` and `src/scanner_strategies/tenablewas.py` for complete implementations.

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
# Windows
python main.py --input report.txt --scanner mycorp --llm gpt-4

# Linux/macOS
python3 main.py --input report.txt --scanner mycorp --llm gpt-4
```

Check the log file to verify consolidation worked correctly!

---

## Adding a New LLM

MulitaMiner supports multiple LLM providers with a flexible, extensible architecture:

### Provider Types

| Provider Type                | Complexity | Setup                      | Examples                      |
| ---------------------------- | ---------- | -------------------------- | ----------------------------- |
| Cloud API (OpenAI, DeepSeek) | Easy       | JSON config only           | gpt-4, deepseek-coder, Groq   |
| Local (Ollama or LLM Studio) | Medium     | Install tool + JSON config | mistral, granite, neural-chat |
| Custom Provider              | Hard       | Python class + JSON config | Proprietary API, special case |

### Option 1: Add Cloud API Model

Create JSON in `src/configs/llms/`. **For full field reference and more examples, see [CONFIG.md](CONFIG.md#llm-configuration-files).**

Quick example - Create `src/configs/llms/myapi.json`:

```json
{
  "api_key": "${API_KEY_MYSERVICE}",
  "endpoint": "https://api.myservice.com/v1",
  "model": "mymodel-v2",
  "temperature": 0.0,
  "max_completion_tokens": 8000,
  "max_chunk_size": 6000,
  "reserve_for_response": 1500,
  "tokenizer": {
    "type": "tiktoken",
    "model": "cl100k_base"
  }
}
```

Add to `.env`: `API_KEY_MYSERVICE=your-api-key`

Use: `python main.py --input scan.pdf --llm myapi --scanner myscanner`

### Option 2: Add Local Model

Create JSON in `src/configs/llms/`. **For setup instructions, see [CONFIG.md → Local LLMs Setup](CONFIG.md#local-llms-setup).**

Quick example - Create `src/configs/llms/mylocal.json`:

```json
{
  "provider": "ollama",
  "model": "neural-chat",
  "endpoint": "http://localhost:11434",
  "temperature": 0.0,
  "max_tokens": 4096,
  "max_chunk_size": 3000,
  "reserve_for_response": 1000,
  "timeout": 120,
  "tokenizer": {
    "type": "huggingface",
    "model": "Intel/neural-chat-7b-v3-3"
  }
}
```

Use: `python main.py --input scan.pdf --llm mylocal --scanner myscanner`

### Option 3: Create Custom Provider

For proprietary APIs or specialized inference backends not covered by built-in providers.

#### Step 1: Create Provider Class

File: `src/model_management/providers/myprovider.py`

```python
from .base_provider import BaseLLMProvider

class MyproviderProvider(BaseLLMProvider):
    """Custom provider for MyService API."""

    def __init__(self, config: dict):
        self.config = config
        self.llm = MyServiceClient(
            endpoint=config["endpoint"],
            api_key=config.get("api_key"),
            model=config["model"],
            temperature=config["temperature"]
        )

    def invoke(self, prompt: str) -> str:
        """Send prompt and return response text."""
        response = self.llm.request(prompt)
        # Must return string, not Message object
        return response.content if hasattr(response, 'content') else str(response)

    def get_model_name(self) -> str:
        return self.config.get("model", "unknown")
```

#### Step 2: Create Config JSON

File: `src/configs/llms/myprovider.json`

```json
{
  "provider": "myprovider",
  "endpoint": "https://api.myservice.com/v1",
  "api_key": "${API_KEY_MYSERVICE}",
  "model": "mymodel-v2",
  "temperature": 0.0,
  "max_tokens": 4096,
  "max_chunk_size": 3000,
  "reserve_for_response": 500,
  "timeout": 60,
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B"
  }
}
```

#### Step 3: Use It

System auto-discovers the provider:

```bash
python main.py --input scan.pdf --llm myprovider --scanner myscanner
```

**How it works:**

1. Loads `myprovider.json` → sees `"provider": "myprovider"`
2. Auto-imports `MyproviderProvider` from `myprovider_provider.py`
3. Instantiates and uses it

#### Class Naming Convention

- File: `src/model_management/providers/{name}_provider.py`
- Class: `{Name}Provider` (capitalize first letter)

Examples:

- `groq_provider.py` → `GroqProvider`
- `anthropic_provider.py` → `AnthropicProvider`
- `myservice_provider.py` → `MyserviceProvider`

---

## Extension Points

| Extension Point          | Location                          | Purpose                    |
| ------------------------ | --------------------------------- | -------------------------- |
| New LLM (config)         | `src/configs/llms/`               | Add model via JSON         |
| New LLM provider (code)  | `src/model_management/providers/` | Custom backend/API support |
| New scanner strategy     | `src/scanner_strategies/`         | Custom consolidation logic |
| New scanner (config)     | `src/configs/scanners/`           | Define scanner behavior    |
| New extraction templates | `src/configs/templates/`          | Custom prompts for LLMs    |
