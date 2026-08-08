"""Registry for profile validators, field handlers and consolidation strategies."""

from typing import Dict, Callable, Any, List, Optional
import json

PROFILE_VALIDATORS = {}
FIELD_HANDLERS = {}
CONSOLIDATION_STRATEGIES = {}


def register_validator(profile_name: str, validator_func: Callable) -> None:
    """Register a validator for a specific profile type."""
    PROFILE_VALIDATORS[profile_name.lower()] = validator_func


def register_field_handler(profile_name: str, field_name: str, handler_func: Callable) -> None:
    """Register a custom field handler for a profile."""
    key = f"{profile_name.lower()}:{field_name}"
    FIELD_HANDLERS[key] = handler_func


def register_consolidation_strategy(profile_name: str, strategy_func: Callable) -> None:
    """Register a consolidation strategy for a profile."""
    CONSOLIDATION_STRATEGIES[profile_name.lower()] = strategy_func


def get_validator(profile_name: str) -> Optional[Callable]:
    """Get validator for a profile. Returns default if not registered."""
    profile_key = profile_name.lower()
    if profile_key in PROFILE_VALIDATORS:
        return PROFILE_VALIDATORS[profile_key]
    return None


def get_field_handler(profile_name: str, field_name: str) -> Optional[Callable]:
    """Get custom field handler if registered."""
    key = f"{profile_name.lower()}:{field_name}"
    return FIELD_HANDLERS.get(key)


def get_consolidation_strategy(profile_name: str) -> Optional[Callable]:
    """Get consolidation strategy for a profile."""
    return CONSOLIDATION_STRATEGIES.get(profile_name.lower())


def detect_profile_type(profile_config: Dict[str, Any]) -> str:
    """Detect the profile type: prompt template, then output file, then
    the explicit `type` field, falling back to 'default'."""
    prompt_template = profile_config.get('prompt_template', '').lower()
    output_file = profile_config.get('output_file', '').lower()
    profile_type = profile_config.get('type', '').lower()

    if 'cais' in prompt_template:
        return 'cais'
    if 'tenable' in prompt_template:
        return 'tenable'
    if 'openvas' in prompt_template:
        return 'openvas'

    if 'cais' in output_file:
        return 'cais'
    if 'tenable' in output_file:
        return 'tenable'
    if 'openvas' in output_file:
        return 'openvas'

    if profile_type:
        return profile_type

    return 'default'


def is_cais_profile(profile_config: Dict[str, Any]) -> bool:
    """Check if profile is CAIS-based."""
    if not profile_config:
        return False
    prompt_template = profile_config.get('prompt_template', '').lower()
    return 'cais' in prompt_template


def get_profile_validator(profile_config: Dict[str, Any]) -> Callable:
    """Validator registered for this profile type, or the default one."""
    profile_type = detect_profile_type(profile_config)

    validator = get_validator(profile_type)
    if validator:
        return validator

    from src.model_management import validate_and_normalize_vulnerability
    return validate_and_normalize_vulnerability


def validate_vulnerability(vuln: Dict[str, Any], profile_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate vulnerability using appropriate profile validator."""
    validator = get_profile_validator(profile_config)
    return validator(vuln)


def register_default_validators():
    """Register validators for the built-in profile types."""
    from src.model_management import validate_and_normalize_vulnerability
    from .cais_validator import validate_cais_vulnerability

    register_validator('default', validate_and_normalize_vulnerability)
    register_validator('openvas', validate_and_normalize_vulnerability)
    register_validator('tenable', validate_and_normalize_vulnerability)

    # CAIS uses dotted field names, hence its own validator
    register_validator('cais', validate_cais_vulnerability)


register_default_validators()
