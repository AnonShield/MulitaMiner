from abc import ABC, abstractmethod
from typing import List, Dict, Tuple

class ScannerStrategy(ABC):
    """
    Abstract strategy for each scanner type.
    Each scanner implements its own logic.
    """
    scanner_name: str = 'base'
    requires_visual_layout: bool = False
    
    @abstractmethod
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        pass
    
    def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
        """
        Extract initial context from visual layout (severity, port, protocol).
        Override if scanner needs visual layout extraction.
        
        Returns:
            Tuple: (initial_context_lines, severity, port, protocol)
            Default: Empty context
        """
        return [], None, None, None
    
    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple) -> List[Dict]:
        """
        Create blocks from report text. Override for custom logic.
        Default: Creates a single block with entire report.
        
        Args:
            report_text: Text extracted from report
            temp_dir: Directory to save block files
            initial_context: Tuple from extract_visual_context()
        
        Returns:
            List of block dictionaries with structure:
            {'file': path, 'port': port, 'protocol': protocol, 'severity': severity}
        """
        import os
        
        initial_context_lines, initial_severity, initial_port, initial_protocol = initial_context
        
        # Default: single block with all text
        block_path = os.path.join(temp_dir, f"block_{self.scanner_name}_1.txt")
        with open(block_path, 'w', encoding='utf-8') as f:
            if initial_context_lines:
                for ctx_line in initial_context_lines:
                    f.write(f"{ctx_line}\n")
                f.write("---\n")
            f.write(report_text)
        
        return [{
            'file': block_path,
            'port': initial_port,
            'protocol': initial_protocol,
            'severity': initial_severity
        }]
    
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
