"""LM Studio provider (local models behind an OpenAI-compatible API)."""

from langchain_openai import ChatOpenAI
from .base_provider import BaseLLMProvider


class Lm_studioProvider(BaseLLMProvider):
    """Provider for LLM Studio local models via OpenAI-compatible API."""
    
    def __init__(self, config: dict):
        self.config = config

        endpoint = config.get("endpoint", "http://localhost:1234")

        temperature = config.get("temperature", 0.0)
        if temperature is None:
            temperature = 0.0
        temperature = float(temperature)

        max_tokens = config.get("max_tokens", 4096)
        if max_tokens is None:
            max_tokens = 4096
        max_tokens = int(max_tokens)

        self.model_name = config["model"]
        self.endpoint = endpoint

        try:
            self.llm = ChatOpenAI(
                model=config["model"],
                base_url=endpoint,
                api_key="not-needed",  # LM Studio does not require auth
                temperature=temperature,
                timeout=config.get("timeout", 120),
                max_tokens=max_tokens,
            )

        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize LLM Studio provider. "
                f"Ensure LLM Studio is running at {endpoint}. "
                f"Error: {str(e)}"
            ) from e
    
    def invoke(self, prompt: str) -> str:
        """Send prompt to LLM Studio and return response text."""
        try:
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            raise RuntimeError(
                f"LLM Studio inference failed. Check endpoint: {self.endpoint}. "
                f"Error: {str(e)}"
            ) from e
    
    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name
