from abc import ABC, abstractmethod
from typing import List, Dict

class ScannerStrategy(ABC):
    """
    Estratégia abstrata para cada tipo de scanner.
    Cada scanner implementa sua própria lógica.
    """
    @abstractmethod
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        pass
