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
    Factory function to create LLM provider based on configuration.
    
    Detects the LLM provider and instantiates the appropriate provider.
    Built-in providers: openai, ollama, huggingface
    Custom providers can be added in the providers/ directory.
    
    Args:
        llm_config: Configuration dict with 'provider' key
    
    Returns:
        BaseLLMProvider: Instantiated provider instance
    
    Raises:
        ValueError: If provider is unsupported or provider cannot be loaded
        RuntimeError: If provider initialization fails
    """
    
    # Detect LLM provider (default to openai for backward compatibility)
    llm_provider = llm_config.get("provider", "openai").lower()
    
    # Route to correct built-in provider
    if llm_provider == "openai":
        from .providers.openai_provider import OpenAIProvider
        return OpenAIProvider(llm_config)
    
    elif llm_provider == "ollama":
        from .providers.ollama_provider import OllamaProvider
        return OllamaProvider(llm_config)
    
    elif llm_provider == "huggingface" or llm_provider == "hf":
        # Check if api_key is provided to decide between remote or local
        api_key = llm_config.get("api_key")
        
        if api_key:
            # Use HuggingFace Inference API (remote)
            from .providers.huggingface_provider import HuggingFaceRemoteProvider
            return HuggingFaceRemoteProvider(llm_config)
        else:
            # Use transformers library locally
            from .providers.huggingface_provider import HuggingFaceLocalProvider
            return HuggingFaceLocalProvider(llm_config)
    
    # Try to load custom provider
    else:
        try:
            # Attempt to dynamically import custom provider
            # Replace hyphens with underscores for module name
            safe_provider_name = llm_provider.replace("-", "_")
            module_name = f"src.model_management.providers.{safe_provider_name}_provider"
            provider_class_name = f"{safe_provider_name.capitalize()}Provider"
            
            module = __import__(module_name, fromlist=[provider_class_name])
            ProviderClass = getattr(module, provider_class_name)
            return ProviderClass(llm_config)
            
        except (ImportError, AttributeError) as e:
            raise ValueError(
                f"Unknown LLM provider: '{llm_provider}'\n\n"
                f"Built-in options: openai, ollama, huggingface\n\n"
                f"To add support for '{llm_provider}':\n"
                f"1. Create: src/model_management/providers/{llm_provider}_provider.py\n"
                f"2. Define class: class {llm_provider.capitalize()}Provider(BaseLLMProvider)\n"
                f"3. Implement methods: invoke(prompt) and get_model_name()\n"
                f"4. See docs/CUSTOM_PROVIDER_TEMPLATE.md for a template.\n"
                f"\nError details: {str(e)}"
            ) from e
