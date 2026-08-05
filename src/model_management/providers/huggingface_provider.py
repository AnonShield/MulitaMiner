"""HuggingFace providers: Inference API (remote) and local transformers."""

from .base_provider import BaseLLMProvider


class HuggingFaceRemoteProvider(BaseLLMProvider):
    """Provider for HuggingFace Inference API (remote)."""
    
    def __init__(self, config: dict):
        try:
            from langchain_huggingface import HuggingFaceHub
        except ImportError:
            raise ImportError(
                "langchain_huggingface package not installed. "
                "Install with: pip install langchain_huggingface"
            )
        
        self.config = config

        model_id = config.get("model") or config.get("repo_id")
        api_key = config.get("api_key")

        if not model_id:
            raise ValueError("HuggingFace provider requires 'model' or 'repo_id' in config")
        if not api_key:
            raise ValueError("HuggingFace remote provider requires 'api_key' in config")

        self.model_name = model_id

        temperature = config.get("temperature", 0.7)
        if temperature is None:
            temperature = 0.7
        temperature = float(temperature)

        max_length = config.get("max_length", 512)
        if max_length is None:
            max_length = 512
        max_length = int(max_length)

        self.llm = HuggingFaceHub(
            repo_id=model_id,
            model_kwargs={
                "temperature": temperature,
                "max_length": max_length,
            },
            huggingfacehub_api_token=api_key
        )
    
    def invoke(self, prompt: str) -> str:
        """Send prompt to HuggingFace API and return response text."""
        try:
            response = self.llm.invoke(prompt)
            return response
        except Exception as e:
            raise RuntimeError(
                f"HuggingFace Inference API failed. "
                f"Error: {str(e)}"
            ) from e
    
    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name


class HuggingFaceLocalProvider(BaseLLMProvider):
    """Provider for HuggingFace models using transformers locally."""
    
    def __init__(self, config: dict):
        try:
            from transformers import pipeline
        except ImportError:
            raise ImportError(
                "transformers package not installed. "
                "Install with: pip install transformers torch"
            )
        
        self.config = config

        model_id = config.get("model")
        if not model_id:
            raise ValueError("HuggingFace local provider requires 'model' in config")

        self.model_name = model_id

        temperature = config.get("temperature", 0.7)
        if temperature is None:
            temperature = 0.7
        temperature = float(temperature)

        max_length = config.get("max_length", 512)
        if max_length is None:
            max_length = 512
        max_length = int(max_length)

        self.llm = pipeline(
            "text-generation",
            model=model_id,
            temperature=temperature,
            max_length=max_length
        )
    
    def invoke(self, prompt: str) -> str:
        """Send prompt to local model and return response text."""
        try:
            max_tokens = self.config.get("max_completion_tokens") or self.config.get("max_tokens") or self.config.get("max_length", 512)
            result = self.llm(prompt, max_new_tokens=int(max_tokens))
            if isinstance(result, list) and len(result) > 0:
                return result[0].get("generated_text", "")
            return str(result)
        except Exception as e:
            raise RuntimeError(
                f"HuggingFace local inference failed. "
                f"Error: {str(e)}"
            ) from e
    
    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name


# Backward-compatible alias
HuggingFaceProvider = HuggingFaceRemoteProvider
