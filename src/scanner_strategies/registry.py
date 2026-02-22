from .openvas import OpenVASStrategy
from .tenablewas import TenableWASStrategy

SCANNER_STRATEGIES = {
    'openvas': OpenVASStrategy(),
    'tenable': TenableWASStrategy(),
}

def get_strategy(source: str):
    return SCANNER_STRATEGIES.get(source.upper())
