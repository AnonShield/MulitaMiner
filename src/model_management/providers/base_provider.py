"""
Base interface for all LLM providers.

All providers must implement this interface to ensure compatibility
with existing code that uses init_llm().
"""

from abc import ABC, abstractmethod


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
