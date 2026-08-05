"""Loaders for LLM and scanner profile JSON configs, with env var substitution."""

import os
import json
import re
from urllib.parse import urlparse
from dotenv import load_dotenv


def load_profile(profile_name):
    """Load a scanner profile config by short name (e.g. 'openvas'); None if missing."""
    profile_name = profile_name.lower()
    path = f"src/configs/scanners/{profile_name}.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Profile configuration file not found for '{profile_name}' at '{path}'.")
        return None


def load_llm(llm_name):
    """Load an LLM config by short name, resolving ${VAR} from the environment."""
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
    
    # Auto-detect provider if not specified
    if "provider" not in config:
        endpoint = config.get("endpoint", "").lower()
        
        if "localhost" in endpoint or "127.0.0.1" in endpoint or "11434" in endpoint:
            config["provider"] = "ollama"
        elif "openai" in endpoint or "api.openai.com" in endpoint:
            config["provider"] = "openai"
        else:
            # openai is the backward-compatible default
            config["provider"] = "openai"
    
    return config


def get_provider_key(llm_name):
    """Return a grouping key for parallelism: endpoint domain, or 'local' for local providers."""
    config = load_llm(llm_name)
    if config is None:
        return "unknown"
    if config.get("provider") in ("ollama", "lm_studio"):
        return "local"
    endpoint = config.get("endpoint", "")
    netloc = urlparse(endpoint).netloc
    return netloc if netloc else "unknown"
