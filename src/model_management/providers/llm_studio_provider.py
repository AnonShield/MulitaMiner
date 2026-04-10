"""
LLM Studio provider for using local models via LLM Studio.

Connects to LLM Studio running on localhost:1234 (or custom endpoint).
Supports any model loaded in LLM Studio (Granite, Mistral, DeepSeek, etc).

LLM Studio provides OpenAI-compatible API endpoints.
"""

from langchain_openai import ChatOpenAI
from .base_provider import BaseLLMProvider


class Llm_studioProvider(BaseLLMProvider):
    """Provider for LLM Studio local models via OpenAI-compatible API."""
    
    def __init__(self, config: dict):
        """
        Initialize LLM Studio provider.
        
        Args:
            config: Configuration dict with:
                - model: Model name (as shown in LLM Studio)
                - endpoint: LLM Studio endpoint (default: http://localhost:1234)
                - temperature: Temperature setting
                - timeout: Request timeout
                - max_tokens: Max tokens in response
        """
        self.config = config
        
        # Get endpoint (defaults to LLM Studio default)
        endpoint = config.get("endpoint", "http://localhost:1234")
        
        # Parse temperature
        temperature = config.get("temperature", 0.0)
        if temperature is None:
            temperature = 0.0
        temperature = float(temperature)
        
        # Parse max_tokens
        max_tokens = config.get("max_tokens", 4096)
        if max_tokens is None:
            max_tokens = 4096
        max_tokens = int(max_tokens)
        
        self.model_name = config["model"]
        self.endpoint = endpoint
        
        try:
            # Create ChatOpenAI instance pointing to LLM Studio
            # LLM Studio provides OpenAI-compatible API
            self.llm = ChatOpenAI(
                model=config["model"],
                base_url=endpoint,
                api_key="not-needed",  # LLM Studio doesn't require auth
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
