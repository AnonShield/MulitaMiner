"""Load LLM and scanner profile configs from JSON, resolving ${ENV_VAR} values."""

import os
import json
import re
from urllib.parse import urlparse
from dotenv import load_dotenv


def load_profile(profile_name):
    """Load a scanner profile by short name, or None if there is no such file."""
    profile_name = profile_name.lower()
    path = f"src/configs/scanners/{profile_name}.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Profile configuration file not found for '{profile_name}' at '{path}'.")
        return None


def load_llm(llm_name):
    """Load an LLM config by short name, resolving ${VAR} values and the provider."""
    load_dotenv()
    
    llm_name = llm_name.lower()
    path = f"src/configs/llms/{llm_name}.json"
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] LLM configuration file not found for '{llm_name}' at '{path}'.")
        return None

    for k, v in config.items():
        if isinstance(v, str):
            match = re.fullmatch(r"\$\{([A-Z0-9_]+)\}", v)
            if match:
                env_var = match.group(1)
                config[k] = os.getenv(env_var, "")
    
    # Normalize provider aliases so the rest of the code sees one canonical name
    if config.get("provider") == "hf":
        config["provider"] = "huggingface"

    if "provider" not in config:
        endpoint = config.get("endpoint", "").lower()
        
        if "localhost" in endpoint or "127.0.0.1" in endpoint or "11434" in endpoint:
            config["provider"] = "ollama"
        elif "openai" in endpoint or "api.openai.com" in endpoint:
            config["provider"] = "openai"
        else:
            # Default to openai for backward compatibility
            config["provider"] = "openai"
    
    return config


def get_provider_key(llm_name):
    """Return a grouping key for parallelism: endpoint domain, or 'local' for local providers."""
    config = load_llm(llm_name)
    if config is None:
        return "unknown"
    if config.get("provider") in ("ollama", "lm_studio", "huggingface"):
        return "local"
    endpoint = config.get("endpoint", "")
    netloc = urlparse(endpoint).netloc
    return netloc if netloc else "unknown"
