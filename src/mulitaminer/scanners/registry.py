from .openvas import OpenVASStrategy
from .tenablewas import TenableWASStrategy

SCANNER_STRATEGIES = {
    'openvas': OpenVASStrategy(),
    'tenable': TenableWASStrategy(),
}

def get_strategy(source: str):
    if not source:
        return None
    return SCANNER_STRATEGIES.get(source.lower())
