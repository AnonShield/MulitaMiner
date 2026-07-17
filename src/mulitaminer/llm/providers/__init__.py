"""
LLM Providers - Implementations of different LLM backends.

Includes built-in providers for OpenAI, Ollama, and HuggingFace.
Custom providers can be added by creating a new file in this directory.
"""

# Importing every provider module here runs their @register_provider
# decorators, so importing this package is what populates the factory registry.
from .base_provider import (
    BaseLLMProvider,
    get_provider_factory,
    register_provider,
    registered_providers,
)
from .openai_provider import OpenAIProvider
from .ollama_provider import OllamaProvider
from .huggingface_provider import HuggingFaceRemoteProvider, HuggingFaceLocalProvider
from .lm_studio_provider import Lm_studioProvider

__all__ = [
    'BaseLLMProvider',
    'get_provider_factory',
    'register_provider',
    'registered_providers',
    'OpenAIProvider',
    'OllamaProvider',
    'HuggingFaceRemoteProvider',
    'HuggingFaceLocalProvider',
    'Lm_studioProvider',
]
