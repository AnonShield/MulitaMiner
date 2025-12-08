"""
Plugin registry system for profiles, validators, and handlers.
Allows dynamic registration of new profiles without code changes.
"""

from typing import Dict, Callable, Any, List, Optional
import json

# Registry for profile validators
PROFILE_VALIDATORS = {}

# Registry for field handlers
FIELD_HANDLERS = {}

# Registry for consolidation strategies
CONSOLIDATION_STRATEGIES = {}


def register_validator(profile_name: str, validator_func: Callable) -> None:
    """Register a validator for a specific profile type."""
    PROFILE_VALIDATORS[profile_name.lower()] = validator_func
    print(f"[REGISTRY] Validator registered for profile: {profile_name}")


def register_field_handler(profile_name: str, field_name: str, handler_func: Callable) -> None:
    """Register a custom field handler for a profile."""
    key = f"{profile_name.lower()}:{field_name}"
    FIELD_HANDLERS[key] = handler_func
    print(f"[REGISTRY] Field handler registered: {key}")


def register_consolidation_strategy(profile_name: str, strategy_func: Callable) -> None:
    """Register a consolidation strategy for a profile."""
    CONSOLIDATION_STRATEGIES[profile_name.lower()] = strategy_func
    print(f"[REGISTRY] Consolidation strategy registered for profile: {profile_name}")


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
    """
    Auto-detect profile type from configuration.
    
    Detection order:
    1. Check prompt template name (cais_prompt → cais, etc)
    2. Check output file name (vulnerabilities_cais.json → cais, etc)
    3. Check explicit type field
    4. Default to 'default'
    """
    prompt_template = profile_config.get('prompt_template', '').lower()
    output_file = profile_config.get('output_file', '').lower()
    profile_type = profile_config.get('type', '').lower()
    
    # Check prompt template
    if 'cais' in prompt_template:
        return 'cais'
    if 'tenable' in prompt_template:
        return 'tenable'
    if 'openvas' in prompt_template:
        return 'openvas'
    
    # Check output file
    if 'cais' in output_file:
        return 'cais'
    if 'tenable' in output_file:
        return 'tenable'
    if 'openvas' in output_file:
        return 'openvas'
    
    # Check explicit type
    if profile_type:
        return profile_type
    
    # Default
    return 'default'


def get_profile_validator(profile_config: Dict[str, Any]) -> Callable:
    """
    Get appropriate validator for a profile configuration.
    Auto-detects profile type and returns registered validator or default.
    """
    profile_type = detect_profile_type(profile_config)
    
    validator = get_validator(profile_type)
    if validator:
        return validator
    
    # Return default validator
    from utils.utils import validate_and_normalize_vulnerability
    return validate_and_normalize_vulnerability


def validate_vulnerability(vuln: Dict[str, Any], profile_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate vulnerability using appropriate profile validator."""
    validator = get_profile_validator(profile_config)
    return validator(vuln)


# Built-in validators registration

def register_default_validators():
    """Register validators for built-in profile types."""
    from utils.utils import validate_and_normalize_vulnerability
    from utils.cais_validator import validate_cais_vulnerability
    
    # Default validator (system fields: Name, description, etc)
    register_validator('default', validate_and_normalize_vulnerability)
    register_validator('openvas', validate_and_normalize_vulnerability)
    register_validator('tenable', validate_and_normalize_vulnerability)
    
    # CAIS validator (dotted fields: definition.name, etc)
    register_validator('cais', validate_cais_vulnerability)


# Auto-register on import
register_default_validators()
