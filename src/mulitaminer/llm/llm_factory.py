"""
LLM initialization and factory pattern.

Factory function to create LLM provider instances based on configuration.
Supports multiple backends: OpenAI, Ollama, HuggingFace, and custom providers.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .providers.base_provider import BaseLLMProvider


def init_llm(llm_config: dict) -> "BaseLLMProvider":
    """
    Factory function to create an LLM provider from configuration.

    The provider is resolved by name through the provider registry (providers
    self-register via ``@register_provider`` — see providers/base_provider.py),
    not a hand-maintained if/elif chain. Built-in providers: openai, ollama,
    huggingface (+ alias hf), lm_studio. A custom provider is added by dropping
    a new ``providers/<name>_provider.py`` with the decorator — no edit here.

    Args:
        llm_config: Configuration dict with a 'provider' key (default: openai).

    Returns:
        BaseLLMProvider: Instantiated provider instance.

    Raises:
        ValueError: If the named provider isn't registered.
    """
    # Importing the providers package runs every @register_provider decorator.
    from . import providers  # noqa: F401
    from .providers.base_provider import get_provider_factory, registered_providers

    # Default to openai for backward compatibility (all provider-less configs
    # point at OpenAI-compatible endpoints: OpenAI/DeepSeek/Groq).
    provider_name = llm_config.get("provider", "openai").lower()
    factory = get_provider_factory(provider_name)

    if factory is None:
        raise ValueError(
            f"Unknown LLM provider: '{provider_name}'\n\n"
            f"Registered providers: {', '.join(registered_providers())}\n\n"
            f"To add support for '{provider_name}':\n"
            f"1. Create: src/mulitaminer/llm/providers/{provider_name}_provider.py\n"
            f"2. Define a BaseLLMProvider subclass decorated with "
            f"@register_provider('{provider_name}')\n"
            f"3. Implement methods: invoke(prompt) and get_model_name()\n"
            f"4. See docs/EXTENSIBILITY.md (Create Custom Provider) for a template."
        )

    return factory(llm_config)
