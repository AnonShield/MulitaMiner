"""
Ollama provider for using local LLM models.

Connects to Ollama running on localhost:11434 (or custom endpoint).
Calls the Ollama HTTP API directly (/api/chat) so that runtime options —
notably num_ctx — are sent on every request. langchain's ChatOllama did not
reliably forward num_ctx, which silently left models running at the default
context window.
"""

import requests
from .base_provider import BaseLLMProvider


class OllamaProvider(BaseLLMProvider):
    """Provider for Ollama local LLM models (direct HTTP API)."""

    def __init__(self, config: dict):
        """
        Initialize Ollama provider.

        Args:
            config: Configuration dict with:
                - model: Model name (must be pulled in Ollama)
                - endpoint: Ollama endpoint (default: http://localhost:11434)
                - temperature: Temperature setting
                - timeout: Request timeout
                - max_tokens: Max tokens in response (-> num_predict)
                - options: Runtime options forwarded to Ollama (num_ctx, top_k, ...)
        """
        self.config = config

        endpoint = config.get("endpoint", "http://localhost:11434")
        self.endpoint = endpoint.rstrip("/")
        self.model_name = config["model"]
        self.timeout = config.get("timeout", 120)
        self.disable_thinking = bool(config.get("disable_thinking", False))
        # Ollama 'think' control for reasoning models (e.g. gpt-oss). Sent at the
        # TOP LEVEL of the request (not inside options). None -> model default;
        # False -> disable reasoning; or "low"/"medium"/"high" for gpt-oss.
        self.think = config.get("think")

        # Parse temperature
        temperature = config.get("temperature", 0.0)
        if temperature is None:
            temperature = 0.0

        # Parse max_tokens (-> num_predict, the output token cap)
        max_tokens = config.get("max_tokens", 4096)
        if max_tokens is None:
            max_tokens = 4096

        # Options sent to Ollama on EVERY request. num_ctx and any other tuning
        # come from config["options"]; this is what makes num_ctx actually apply.
        self.options = {
            "temperature": float(temperature),
            "num_predict": int(max_tokens),
        }
        for opt_key, opt_val in config.get("options", {}).items():
            self.options[opt_key] = opt_val

        self._verify_num_ctx(config, self.endpoint)

    def _verify_num_ctx(self, config: dict, endpoint: str):
        """Query Ollama server to sanity-check the requested num_ctx vs model capacity."""
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
                print(f"[OLLAMA] {config['model']} initialized (num_ctx: {requested_ctx} ✓, model supports up to {server_ctx})")
            else:
                print(f"[OLLAMA] WARNING: num_ctx={requested_ctx} exceeds model capacity ({server_ctx}) — Ollama will clamp it down")
        except Exception:
            print(f"[OLLAMA] {config['model']} initialized (num_ctx: {requested_ctx} — server unreachable for verification)")

    def invoke(self, prompt: str) -> str:
        """Send prompt to Ollama via /api/chat and return the response text."""
        if self.disable_thinking:
            prompt = f"/no_think\n{prompt}"

        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": self.options,
        }
        if self.think is not None:
            payload["think"] = self.think

        try:
            resp = requests.post(
                f"{self.endpoint}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
        except Exception as e:
            raise RuntimeError(
                f"Ollama inference failed. Check endpoint: {self.endpoint}. "
                f"Error: {str(e)}"
            ) from e

    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name
