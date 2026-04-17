"""
Ollama provider for using local LLM models.

Connects to Ollama running on localhost:11434 (or custom endpoint).
Supported models: Mistral, DeepSeek, Llama2, Neural Chat, etc.
"""

import requests
from langchain_ollama import ChatOllama
from .base_provider import BaseLLMProvider


class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama local LLM models."""
    
    def __init__(self, config: dict):
        """
        Initialize Ollama provider.
        
        Args:
            config: Configuration dict with:
                - model: Model name (must be imported in Ollama)
                - endpoint: Ollama endpoint (default: http://localhost:11434)
                - temperature: Temperature setting
                - timeout: Request timeout
                - max_tokens: Max tokens in response
        """
        self.config = config
        
        # Get endpoint (defaults to Ollama default)
        endpoint = config.get("endpoint", "http://localhost:11434")
        
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
        self.disable_thinking = bool(config.get("disable_thinking", False))
        
        try:
            ollama_kwargs = {
                "model": config["model"],
                "base_url": endpoint,
                "temperature": temperature,
                "timeout": config.get("timeout", 120),
                "num_predict": max_tokens,
            }
            # Forward runtime options (num_ctx, top_k, top_p, repeat_penalty, ...)to the Ollama server.
            for opt_key, opt_val in config.get("options", {}).items():
                ollama_kwargs[opt_key] = opt_val

            self.llm = ChatOllama(**ollama_kwargs)

            self._verify_num_ctx(config, endpoint)

        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Ollama provider. "
                f"Ensure Ollama is running at {endpoint}. "
                f"Error: {str(e)}"
            ) from e

    def _verify_num_ctx(self, config: dict, endpoint: str):
        """Query Ollama server to verify num_ctx is being applied."""
        requested_ctx = config.get("options", {}).get("num_ctx")
        if requested_ctx is None:
            return

        try:
            resp = requests.post(
                f"{endpoint}/api/show",
                json={"name": config["model"]},
                timeout=10,
            )
            if resp.status_code != 200:
                print(f"[OLLAMA] WARNING: Could not verify num_ctx (server returned {resp.status_code})")
                return

            data = resp.json()
            model_params = data.get("model_info", {})

            # Ollama reports context length under various keys depending on architecture
            server_ctx = None
            for key in model_params:
                if "context_length" in key:
                    server_ctx = model_params[key]
                    break

            if server_ctx is None:
                print(f"[OLLAMA] {config['model']} initialized (num_ctx: {requested_ctx} — could not read model default to compare)")
            elif requested_ctx <= server_ctx:
                print(f"[OLLAMA] {config['model']} initialized (num_ctx: {requested_ctx} \u2713, model supports up to {server_ctx})")
            else:
                print(f"[OLLAMA] WARNING: num_ctx={requested_ctx} exceeds model capacity ({server_ctx}) — Ollama will clamp it down")
        except Exception:
            print(f"[OLLAMA] {config['model']} initialized (num_ctx: {requested_ctx} — server unreachable for verification)")
    
    def invoke(self, prompt: str) -> str:
        """Send prompt to Ollama and return response text."""
        try:
            if self.disable_thinking:
                prompt = f"/no_think\n{prompt}"
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            raise RuntimeError(
                f"Ollama inference failed. Check endpoint: {self.endpoint}. "
                f"Error: {str(e)}"
            ) from e
    
    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name
