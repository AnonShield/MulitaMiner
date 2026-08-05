"""OpenAI-compatible API provider (OpenAI, DeepSeek, Groq endpoints)."""

import os
from langchain_openai import ChatOpenAI
from .base_provider import BaseLLMProvider


class OpenAIProvider(BaseLLMProvider):
    """Provider for OpenAI API models (GPT-4, GPT-3.5, etc)."""
    
    def __init__(self, config: dict):
        self.config = config

        os.environ["OPENAI_API_KEY"] = config["api_key"]

        temperature = config.get("temperature", 1.0)
        if temperature is None:
            temperature = 1.0
        temperature = float(temperature)

        # max_completion_tokens takes precedence (newer OpenAI naming)
        max_tokens = None
        if "max_completion_tokens" in config:
            max_tokens = config["max_completion_tokens"]
        elif "max_tokens" in config:
            max_tokens = config["max_tokens"]
        else:
            max_tokens = 4096

        if max_tokens is None:
            max_tokens = 4096
        max_tokens = int(max_tokens)

        self.llm = ChatOpenAI(
            model=config["model"],
            temperature=temperature,
            base_url=config.get("endpoint", "https://api.openai.com/v1"),
            timeout=config.get("timeout", 120),
            max_tokens=max_tokens,
        )
        
        self.model_name = config["model"]
    
    def invoke(self, prompt: str) -> str:
        """Send prompt to OpenAI and return response text."""
        response = self.llm.invoke(prompt)
        return response.content
    
    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name
