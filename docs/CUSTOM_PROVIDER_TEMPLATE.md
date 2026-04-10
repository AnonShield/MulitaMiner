# Creating Custom LLM Providers

This guide explains how to add support for new LLM APIs or services that aren't implemented by default.

## Overview

MulitaMiner uses a Provider Pattern architecture. Built-in providers include:

- OpenAI (GPT-4, GPT-3.5)
- Ollama (Local models)
- HuggingFace (Open models)

You can add new providers by creating a simple Python class.

## Template Provider Implementation

### Step 1: Create Provider File

Create a new file in `src/model_management/providers/`:

```python
# src/model_management/providers/anthropic_provider.py

from .base_provider import BaseLLMProvider


class AnthropicProvider(BaseLLMProvider):
    """
    Provider for Anthropic Claude models.

    Supports Claude API with streaming and non-streaming responses.
    """

    def __init__(self, config: dict):
        """
        Initialize Anthropic provider.

        Args:
            config: Configuration dict with:
                - api_key: Anthropic API key
                - model: Model name (e.g., "claude-3-opus-20240229")
                - max_tokens: Maximum tokens in response (optional)
        """
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. "
                "Install with: pip install anthropic"
            )

        self.config = config
        self.client = anthropic.Anthropic(api_key=config["api_key"])
        self.model_name = config.get("model", "claude-3-opus-20240229")
        self.max_tokens = config.get("max_tokens", 4096)

    def invoke(self, prompt: str) -> str:
        """
        Send prompt to Claude and return response text.

        Args:
            prompt: The prompt to send

        Returns:
            Response text from Claude
        """
        try:
            message = self.client.messages.create(
                model=self.model_name,
                max_tokens=self.max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return message.content[0].text
        except Exception as e:
            raise RuntimeError(
                f"Anthropic API call failed. Error: {str(e)}"
            ) from e

    def get_model_name(self) -> str:
        """Return the model identifier."""
        return self.model_name
```

### Step 2: Create Configuration File

Create a JSON configuration file in `src/configs/llms/`:

```json
{
  "type": "anthropic",
  "model": "claude-3-opus-20240229",
  "api_key": "${ANTHROPIC_API_KEY}",
  "max_tokens": 4096,
  "max_chunk_size": 3000,
  "reserve_for_response": 1000,
  "tokenizer": {
    "type": "huggingface",
    "model": "Xenova/claude-tokenizer"
  }
}
```

### Step 3: Use Your Provider

```bash
# Set environment variable
export ANTHROPIC_API_KEY="your-key-here"

# Use with MulitaMiner
python main.py --input scan.pdf --llm anthropic
```

## Provider Interface

All providers must extend `BaseLLMProvider` and implement:

```python
from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):

    @abstractmethod
    def invoke(self, prompt: str) -> str:
        """
        Send prompt to LLM and return response as string.

        Must return plain string, not Message objects.
        """
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Return model identifier for logging/tracking."""
        pass
```

## Common Patterns

### Handling API Keys from Environment

```python
import os

api_key = config.get("api_key")
if api_key and api_key.startswith("${"):
    # Already substituted during config loading
    pass
else:
    api_key = os.getenv("MY_API_KEY")
```

### Error Handling

Always wrap errors in descriptive messages:

```python
def invoke(self, prompt: str) -> str:
    try:
        # API call
        response = self.api.call(prompt)
        return response.text
    except ConnectionError as e:
        raise RuntimeError(
            f"Failed to connect to service. "
            f"Check endpoint and network. Error: {e}"
        ) from e
    except ValueError as e:
        raise RuntimeError(
            f"Invalid response format. Error: {e}"
        ) from e
```

### Tokenizer Configuration

Choose the appropriate tokenizer in your JSON config:

```json
{
  "tokenizer": {
    "type": "tiktoken",
    "model": "cl100k_base"
  }
}
```

Or:

```json
{
  "tokenizer": {
    "type": "huggingface",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
  }
}
```

## Full Example: Together AI Provider

```python
# src/model_management/providers/together_provider.py

from .base_provider import BaseLLMProvider


class TogetherProvider(BaseLLMProvider):
    """Provider for Together AI open models."""

    def __init__(self, config: dict):
        try:
            from together import Together
        except ImportError:
            raise ImportError(
                "together package not installed. "
                "Install with: pip install together"
            )

        self.config = config
        self.client = Together(api_key=config["api_key"])
        self.model_name = config.get(
            "model",
            "meta-llama/Llama-2-7b-chat-hf"
        )
        self.max_tokens = config.get("max_tokens", 2048)

    def invoke(self, prompt: str) -> str:
        try:
            response = self.client.complete(
                model=self.model_name,
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.config.get("temperature", 0.7),
            )
            return response.output.choices[0].text
        except Exception as e:
            raise RuntimeError(
                f"Together AI request failed. Error: {str(e)}"
            ) from e

    def get_model_name(self) -> str:
        return self.model_name
```

## Debugging Your Provider

Add logging to understand execution:

```python
import sys
from tqdm import tqdm


class MyProvider(BaseLLMProvider):
    def invoke(self, prompt: str) -> str:
        tqdm.write(f"[MyProvider] Sending prompt ({len(prompt)} chars)")

        try:
            response = self.api.call(prompt)
            tqdm.write(f"[MyProvider] Response received ({len(response)} chars)")
            return response
        except Exception as e:
            tqdm.write(f"[MyProvider] ERROR: {e}")
            raise
```

## Testing Your Provider

```python
# test_provider.py

from src.model_management import load_llm, init_llm

# Load config
config = load_llm("your-custom-llm")

# Initialize provider
llm = init_llm(config)

# Test
prompt = "What is vulnerability?"
response = llm.invoke(prompt)
print(f"Model: {llm.get_model_name()}")
print(f"Response: {response}")
```

## Troubleshooting

### "Unknown LLM type" Error

```
ValueError: Unknown LLM type: 'myservice'
```

**Check:**

1. File named `myservice_provider.py` exists
2. Class named `MyserviceProvider` exists
3. Class extends `BaseLLMProvider`
4. Config has `"type": "myservice"`

### Provider Import Error

```
ModuleNotFoundError: No module named 'mylib'
```

**Solution:**

```bash
pip install mylib

# And handle in __init__:
try:
    import mylib
except ImportError:
    raise ImportError("mylib not installed. pip install mylib")
```

### "invoke() must return str" Error

Ensure `invoke()` returns string, not Message/Response objects:

```python
# Wrong:
return response.message  # Still a Message object

# Right:
return response.message.text  # Extract text
# or
return str(response)  # Convert to string
```

## Best Practices

1. **Handle Missing Dependencies:**

   ```python
   try:
       import optional_library
   except ImportError:
       raise ImportError("Optional package not installed. "
                        "Install with: pip install optional_library")
   ```

2. **Validate Configuration:**

   ```python
   required_keys = ["api_key", "model"]
   for key in required_keys:
       if key not in config:
           raise ValueError(f"Missing required config: '{key}'")
   ```

3. **Use Descriptive Error Messages:**

   ```python
   raise RuntimeError(
       f"Service connection failed at {endpoint}. "
       f"Check network and credentials. "
       f"Error: {original_error}"
   )
   ```

4. **Support Configuration Flexibly:**
   ```python
   self.model = config.get("model") or config.get("model_id") or "default"
   ```

## Adding to Documentation

Update `docs/CUSTOM_PROVIDERS.md` with:

````markdown
## {Service Name} Provider

**File:** `src/model_management/providers/{service}_provider.py`

### Setup

1. Install client:
   ```bash
   pip install {package}
   ```
````

2. Get API key from {service website}

3. Configure `src/configs/llms/{service}.json`

4. Use:
   ```bash
   python main.py --llm {service}
   ```

### Performance

| Metric  | Value            |
| ------- | ---------------- |
| Speed   | X seconds/prompt |
| Cost    | $X per 1M tokens |
| Quality | Good/Excellent   |

```

## Support

For questions or issues with your custom provider, provide:

1. Provider code
2. Configuration JSON (without API keys)
3. Error message and full traceback
4. What service/model you're integrating
```
