"""Base interface all LLM providers must implement (used via init_llm)."""

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def invoke(self, prompt: str) -> str:
        """Send a prompt and return the response text (not a Message object)."""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Return the model identifier (e.g. "gpt-4o-mini-2024-07-18")."""
        pass
