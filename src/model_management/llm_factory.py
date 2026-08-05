"""Factory for LLM provider instances (OpenAI, Ollama, HuggingFace, custom)."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .providers.base_provider import BaseLLMProvider


def init_llm(llm_config: dict) -> "BaseLLMProvider":
    """Instantiate the provider named by llm_config['provider'].

    Built-in: openai, ollama, huggingface. Other names are resolved
    dynamically from providers/<name>_provider.py.
    """
    llm_provider = llm_config.get("provider", "openai").lower()

    if llm_provider == "openai":
        from .providers.openai_provider import OpenAIProvider
        return OpenAIProvider(llm_config)
    
    elif llm_provider == "ollama":
        from .providers.ollama_provider import OllamaProvider
        return OllamaProvider(llm_config)
    
    elif llm_provider == "huggingface" or llm_provider == "hf":
        # api_key present -> Inference API (remote); absent -> local transformers
        api_key = llm_config.get("api_key")

        if api_key:
            from .providers.huggingface_provider import HuggingFaceRemoteProvider
            return HuggingFaceRemoteProvider(llm_config)
        else:
            from .providers.huggingface_provider import HuggingFaceLocalProvider
            return HuggingFaceLocalProvider(llm_config)

    else:
        try:
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
