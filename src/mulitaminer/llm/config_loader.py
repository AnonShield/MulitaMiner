"""
Configuration loader for LLM and Scanner profiles.

Handles loading and parsing of model configurations from JSON files,
including environment variable substitution.
"""

import os
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
from pydantic import ValidationError

from mulitaminer.configs.schemas import LLMConfig, ScannerConfig

# Config files ship inside the package (src/mulitaminer/configs/), so locate
# them relative to this module — never relative to the process CWD.
_CONFIGS_DIR = Path(__file__).resolve().parent.parent / "configs"


def _config_path(subdir: str, name: str) -> Path:
    """Resolve ``<subdir>/<name>.json``, preferring an external override dir.

    ``MULITA_CONFIG_DIR`` (when set) is checked first: a file there shadows or
    adds to the packaged configs, so a Docker user can mount custom LLM/scanner
    JSONs (``-v ./myconfigs:/configs -e MULITA_CONFIG_DIR=/configs``) without
    knowing the package's internal path or rebuilding the image. Falls back to
    the packaged ``configs/`` when the override is unset or lacks the file.
    """
    override = os.getenv("MULITA_CONFIG_DIR")
    if override:
        candidate = Path(override) / subdir / f"{name}.json"
        if candidate.is_file():
            return candidate
    return _CONFIGS_DIR / subdir / f"{name}.json"


def _validate(model, config: dict, kind: str, name: str) -> None:
    """Fail fast with a clear message if a config is malformed, instead of
    letting a missing/mistyped field surface as a cryptic error several
    frames later."""
    try:
        model.model_validate(config)
    except ValidationError as exc:
        raise ValueError(f"Invalid {kind} config '{name}':\n{exc}") from exc


def load_profile(profile_name):
    """
    Load a scanner profile configuration by its short name.
    
    Args:
        profile_name: Name of the profile (e.g., 'openvas', 'tenable', 'cais_openvas')
    
    Returns:
        dict: Profile configuration or None if not found
    """
    profile_name = profile_name.lower()
    path = _config_path("scanners", profile_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Profile configuration file not found for '{profile_name}' at '{path}'.")
        return None
    _validate(ScannerConfig, config, "scanner profile", profile_name)
    return config


def load_llm(llm_name):
    """
    Load an LLM configuration by its short name.
    
    Supports environment variable substitution in format ${VAR_NAME}.
    Auto-detects LLM type if not specified in JSON.
    
    Args:
        llm_name: Name of the LLM (e.g., 'gpt4', 'deepseek', 'ollama-local')
    
    Returns:
        dict: LLM configuration with resolved environment variables and type field
    """
    load_dotenv()
    
    llm_name = llm_name.lower()
    path = _config_path("llms", llm_name)

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] LLM configuration file not found for '{llm_name}' at '{path}'.")
        return None

    # Replace environment variables in format ${NAME}
    for k, v in config.items():
        if isinstance(v, str):
            match = re.fullmatch(r"\$\{([A-Z0-9_]+)\}", v)
            if match:
                env_var = match.group(1)
                config[k] = os.getenv(env_var, "")
    
    # Normalize provider aliases so the rest of the code sees one canonical name
    if config.get("provider") == "hf":
        config["provider"] = "huggingface"

    # Auto-detect provider if not specified
    if "provider" not in config:
        endpoint = config.get("endpoint", "").lower()
        
        if "localhost" in endpoint or "127.0.0.1" in endpoint or "11434" in endpoint:
            config["provider"] = "ollama"
        elif "openai" in endpoint or "api.openai.com" in endpoint:
            config["provider"] = "openai"
        else:
            # Default to openai for backward compatibility
            config["provider"] = "openai"

    _validate(LLMConfig, config, "LLM", llm_name)
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
