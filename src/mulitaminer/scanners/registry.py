"""Scanner strategy registry.

Strategies self-register by family name via ``@register_strategy`` — the same
Open/Closed pattern the input readers use. Adding a scanner strategy is a new
``scanners/<name>.py`` + one decorator + an import in ``scanners/__init__.py``,
with no edit to this dispatch. ``get_strategy`` also resolves family aliases so
profile readers ('cais_openvas') and LLM-stamped record sources ('TENABLEWAS')
map onto the registered family.
"""

SCANNER_STRATEGIES = {}


def register_strategy(name: str):
    """Class decorator: register a scanner strategy under a family name."""
    def deco(cls):
        SCANNER_STRATEGIES[name.lower()] = cls()
        return cls
    return deco


# Importing the strategy modules runs their @register_strategy decorators.
from . import openvas, tenablewas  # noqa: E402,F401


def get_strategy(source: str):
    if not source:
        return None
    key = source.lower()
    if key in SCANNER_STRATEGIES:
        return SCANNER_STRATEGIES[key]
    # Family aliases: profile readers ('cais_openvas') and LLM-stamped record
    # sources ('TENABLEWAS') name the same families as the registry keys.
    for family, strategy in SCANNER_STRATEGIES.items():
        if family in key:
            return strategy
    return None
