from abc import ABC, abstractmethod
from typing import List, Dict, Tuple

class ScannerStrategy(ABC):
    """Abstract strategy with scanner-specific processing logic."""
    scanner_name: str = 'base'
    requires_visual_layout: bool = False

    def get_custom_activation_value(self) -> bool | set | list | tuple | None:
        """For which allow_duplicates value the custom logic activates.

        True/False: only that value; {True, False}: both; None: no custom
        logic, always use the default.
        """
        return None

    @abstractmethod
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """Scanner-specific processing (e.g. deduplication, severity normalization)."""
        pass

    def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
        """Initial context from the visual layout; default is empty.

        Returns (initial_context_lines, severity, port, protocol).
        """
        return [], None, None, None

    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple, output_ext: str = "txt") -> List[Dict]:
        """Split the report into block files; default is a single block.

        Returns a list of {'file', 'port', 'protocol', 'severity'} dicts.
        """
        import os

        initial_context_lines, initial_severity, initial_port, initial_protocol = initial_context

        block_path = os.path.join(temp_dir, f"block_{self.scanner_name}_1.{output_ext}")
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
        """Structured summary of the consolidation step."""
        return {
            'strategy_name': self.__class__.__name__,
            'description': 'Default consolidation strategy',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'deduplication'
        }
