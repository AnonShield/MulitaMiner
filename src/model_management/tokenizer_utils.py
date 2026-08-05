"""Unified tokenizer loading and token counting (tiktoken, HuggingFace)."""

import tiktoken
import subprocess
import sys
import warnings


def get_tokenizer(llm_config: dict = None):
    """Load the tokenizer from llm_config; falls back to cl100k_base."""
    if llm_config:
        tokenizer_config = llm_config.get('tokenizer')
        if tokenizer_config and isinstance(tokenizer_config, dict):
            try:
                print(f"[DEBUG] Attempting to load tokenizer with config: {tokenizer_config}")
                tokenizer = _load_tokenizer(tokenizer_config)
                print(f"[DEBUG] Successfully loaded tokenizer object: {type(tokenizer)}")
                return tokenizer
            except Exception as e:
                print(f"[ERROR] Failed to load tokenizer from config. Error: {e}. Falling back.")

    return tiktoken.get_encoding("cl100k_base")


def _load_tokenizer(tokenizer_config: dict):
    """Load a tokenizer from a {'type', 'model'} config dict."""
    tokenizer_type = tokenizer_config.get('type', 'tiktoken')
    model_name = tokenizer_config.get('model')

    if not model_name:
        raise ValueError("Tokenizer 'model' not specified in config.")

    if tokenizer_type == 'huggingface':
        try:
            from transformers import AutoTokenizer
        except ImportError:
            print("[INFO] Installing 'transformers' library for Hugging Face tokenizer...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "transformers"])
                from transformers import AutoTokenizer
                print("[INFO] 'transformers' installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Failed to install 'transformers'. Please install it manually: pip install transformers. Error: {e}")
                raise ImportError("transformers library is required but installation failed.")
        
        print(f"[DEBUG] Loading Hugging Face tokenizer: {model_name}")
        return AutoTokenizer.from_pretrained(model_name)
    
    elif tokenizer_type == 'tiktoken':
        print(f"[DEBUG] Loading tiktoken with encoding: {model_name}")
        return tiktoken.get_encoding(model_name)
        
    else:
        raise ValueError(f"Unsupported tokenizer type: {tokenizer_type}")


def count_tokens(text: str, tokenizer=None) -> int:
    """Count tokens in text, agnostic to tokenizer type."""
    if not text:
        return 0

    if tokenizer is None:
        warnings.warn(
            "count_tokens was called without a tokenizer. Falling back to default 'cl100k_base'.",
            RuntimeWarning
        )
        tokenizer = tiktoken.get_encoding("cl100k_base")

    return len(tokenizer.encode(text))
