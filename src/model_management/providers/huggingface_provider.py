"""
HuggingFace provider for using LLM models from HuggingFace.

Supports both:
- Remote: HuggingFace Inference API (requires api_key)
- Local: transformers running on a local GPU with 4-bit quantization
  (no api_key needed)

Supported models: Mistral, DeepSeek, Llama, Qwen, etc.
"""

from .base_provider import BaseLLMProvider


class HuggingFaceRemoteProvider(BaseLLMProvider):
    """Provider for HuggingFace Inference API (remote)."""
    
    def __init__(self, config: dict):
        """
        Initialize HuggingFace remote provider.
        
        Args:
            config: Configuration dict with:
                - model: Model identifier (e.g., "mistralai/Mistral-7B-Instruct-v0.2")
                - repo_id: HuggingFace repo ID (can use this instead of model)
                - api_key: HuggingFace API token (required for remote)
                - temperature: Temperature setting
                - max_length: Max length of response
        """
        try:
            from langchain_huggingface import HuggingFaceHub
        except ImportError:
            raise ImportError(
                "langchain_huggingface package not installed. "
                "Install with: pip install langchain_huggingface"
            )
        
        self.config = config
        
        # Get model name and API key
        model_id = config.get("model") or config.get("repo_id")
        api_key = config.get("api_key")
        
        if not model_id:
            raise ValueError("HuggingFace provider requires 'model' or 'repo_id' in config")
        if not api_key:
            raise ValueError("HuggingFace remote provider requires 'api_key' in config")
        
        self.model_name = model_id
        
        # Parse temperature
        temperature = config.get("temperature", 0.7)
        if temperature is None:
            temperature = 0.7
        temperature = float(temperature)
        
        # Parse max_length
        max_length = config.get("max_length", 512)
        if max_length is None:
            max_length = 512
        max_length = int(max_length)
        
        # Create HuggingFaceHub instance
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
    """Run a HuggingFace model locally on GPU via transformers.

    Loads the model with 4-bit quantization by default so that 7B-14B
    models fit on a single 12GB GPU. No api_key required.
    """

    def __init__(self, config: dict):
        """
        Initialize a local transformers model.

        Args:
            config: Configuration dict with:
                - model: HF repo id (e.g., "Qwen/Qwen3-8B")
                - temperature: Sampling temperature (0.0 = greedy/deterministic)
                - max_tokens: Max new tokens to generate
                - quantization: "4bit" (default), "8bit", or "none"
                - device_map: transformers device map (default "auto")
                - disable_thinking: Skip the <think> block on models that support it
        """
        try:
            import torch
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
            )
        except ImportError as e:
            raise ImportError(
                "Local HuggingFace inference needs transformers, torch, "
                "accelerate and bitsandbytes. Install with: "
                "pip install transformers torch accelerate bitsandbytes"
            ) from e

        self.config = config

        model_id = config.get("model")
        if not model_id:
            raise ValueError("HuggingFace local provider requires 'model' in config")
        self.model_name = model_id

        temperature = config.get("temperature", 0.0)
        self.temperature = float(temperature) if temperature is not None else 0.0

        self.max_new_tokens = int(
            config.get("max_tokens")
            or config.get("max_completion_tokens")
            or config.get("max_length")
            or 4096
        )
        self.disable_thinking = bool(config.get("disable_thinking", False))

        # GPU: bf16 (Ampere+) or fp16. CPU: fp32 (fp16 ops are largely
        # unsupported on CPU, so generation would crash otherwise).
        cuda = torch.cuda.is_available()
        if cuda:
            compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        else:
            compute_dtype = torch.float32

        # 4-bit by default so 7B-14B fits on 12GB; opt out via config.
        quantization = str(config.get("quantization", "4bit")).lower()
        if quantization in ("4bit", "8bit") and not cuda:
            print(
                "[HF] No CUDA GPU detected — bitsandbytes requires CUDA. "
                "Loading in full precision on CPU (slow; smoke-test only)."
            )
            quantization = "none"
        quant_config = None
        if quantization == "4bit":
            quant_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=compute_dtype,
            )
        elif quantization == "8bit":
            quant_config = BitsAndBytesConfig(load_in_8bit=True)

        # device_map="auto" needs `accelerate` and only helps with a GPU.
        # On CPU, skip it so a smoke test doesn't require accelerate.
        device_map = config.get("device_map") or ("auto" if cuda else None)

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_id)
            model_kwargs = {
                "quantization_config": quant_config,
                "torch_dtype": compute_dtype,
            }
            if device_map is not None:
                model_kwargs["device_map"] = device_map
            self.model = AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)
            self.model.eval()
        except Exception as e:
            raise RuntimeError(
                f"Failed to load HuggingFace model '{model_id}' locally. "
                f"Error: {str(e)}"
            ) from e

        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self._torch = torch

    def invoke(self, prompt: str) -> str:
        """Send prompt to the local model and return the generated text."""
        torch = self._torch
        try:
            messages = [{"role": "user", "content": prompt}]
            template_kwargs = {"tokenize": False, "add_generation_prompt": True}
            if self.disable_thinking:
                template_kwargs["enable_thinking"] = False
            try:
                text = self.tokenizer.apply_chat_template(messages, **template_kwargs)
            except TypeError:
                # Tokenizer's chat template doesn't accept enable_thinking.
                template_kwargs.pop("enable_thinking", None)
                text = self.tokenizer.apply_chat_template(messages, **template_kwargs)

            inputs = self.tokenizer(text, return_tensors="pt").to(self.model.device)

            gen_kwargs = {
                "max_new_tokens": self.max_new_tokens,
                "pad_token_id": self.tokenizer.pad_token_id,
            }
            if self.temperature and self.temperature > 0:
                gen_kwargs["do_sample"] = True
                gen_kwargs["temperature"] = self.temperature
            else:
                gen_kwargs["do_sample"] = False

            with torch.no_grad():
                output_ids = self.model.generate(**inputs, **gen_kwargs)

            # Decode only the newly generated tokens (strip the prompt).
            new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
            return self.tokenizer.decode(new_tokens, skip_special_tokens=True)
        except Exception as e:
            raise RuntimeError(
                f"HuggingFace local inference failed. Error: {str(e)}"
            ) from e

    def get_model_name(self) -> str:
        """Return model identifier."""
        return self.model_name


# Alias for backward compatibility
HuggingFaceProvider = HuggingFaceRemoteProvider
