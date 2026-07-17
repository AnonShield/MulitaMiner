"""
Base interface for all LLM providers.

All providers must implement this interface to ensure compatibility
with existing code that uses init_llm().

Providers self-register by name with :func:`register_provider`, the same
Open/Closed pattern the input readers use (readers/base.py): adding a provider
is a new ``providers/<name>_provider.py`` + one decorator, with no edit to the
factory. ``init_llm`` looks the name up here instead of a hand-maintained
if/elif chain.
"""

from abc import ABC, abstractmethod
from typing import Callable


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def invoke(self, prompt: str) -> str:
        """
        Send a prompt to the LLM and get a response.

        Args:
            prompt: Text prompt to send to LLM

        Returns:
            str: Model's response text (NOT a Message object)

        Raises:
            Exception: If LLM call fails
        """
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """
        Get the model identifier.

        Returns:
            str: Model name (e.g., "gpt-4o-mini-2024-07-18", "mistral")
        """
        pass


# name -> factory(config) -> provider instance. A factory is usually the
# provider class itself (it takes the config dict); huggingface registers a
# small dispatcher because it picks remote vs local from the config.
ProviderFactory = Callable[[dict], BaseLLMProvider]
_PROVIDER_FACTORIES: dict[str, ProviderFactory] = {}


def register_provider(*names: str) -> Callable[[ProviderFactory], ProviderFactory]:
    """Decorator: register a provider factory under one or more names/aliases."""
    def deco(factory: ProviderFactory) -> ProviderFactory:
        for name in names:
            _PROVIDER_FACTORIES[name.lower()] = factory
        return factory
    return deco


def get_provider_factory(name: str) -> ProviderFactory | None:
    """Return the registered factory for ``name`` (case-insensitive), or None."""
    return _PROVIDER_FACTORIES.get(name.lower())


def registered_providers() -> list[str]:
    """Names/aliases currently registered — for error messages and tests."""
    return sorted(_PROVIDER_FACTORIES)
