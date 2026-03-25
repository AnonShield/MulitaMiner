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
    
    def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
        """
        Retorna um report estruturado sobre o processamento de consolidação.
        Pode ser overridden por strategies específicas para fornecer mais detalhes.
        
        Returns:
            Dict com chaves: strategy_name, description, input_count, output_count, removed, reason
        """
        return {
            'strategy_name': self.__class__.__name__,
            'description': 'Default consolidation strategy',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'deduplication'
        }
