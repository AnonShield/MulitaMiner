from abc import ABC, abstractmethod
from typing import List, Dict, NamedTuple, Optional, TypedDict


class Block(TypedDict, total=False):
    """One unit of report text handed to the LLM, plus the metadata the
    generic pipeline stamps onto every vulnerability extracted from it.

    ``file`` is always present; the rest are optional (a scanner that doesn't
    know a value omits it, and the pipeline reads it back with ``.get()``).
    Making the contract explicit is what kills the silent host bug: the generic
    loop can now stamp ``host`` unconditionally from ``block.get('host')``
    instead of only when some strategy happened to set the key.
    """
    file: str
    severity: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    host: Optional[str]


class VisualContext(NamedTuple):
    """The initial context a scanner recovers from the report's visual layout.

    Was an un-named 5-tuple whose annotation lied (declared 4 elements, returned
    5), so a new strategy trusting the signature broke on unpack. Named fields
    make the shape self-documenting and the annotation honest.
    """
    lines: List[str]
    severity: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    host: Optional[str]


class ScannerStrategy(ABC):
    """
    Abstract strategy for each scanner type.
    Each scanner implements its own logic.
    """
    scanner_name: str = 'base'
    requires_visual_layout: bool = False
    
    def get_custom_activation_value(self) -> bool | set | list | tuple | None:
        """
        Define em qual valor de allow_duplicates este custom deve ativar.
        
        Retorna:
            True: custom ativa quando allow_duplicates=True
            False: custom ativa quando allow_duplicates=False
            {True, False} ou [True, False]: custom ativa em AMBOS os casos
            None: sem custom (usa default sempre)
        
        Exemplos:
            return True                    # Custom só para True
            return False                   # Custom só para False
            return {True, False}           # Custom para ambos
            return None                    # Sem custom (default)
        """
        return None  # Default: sem custom
    
    @abstractmethod
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """Process extracted vulnerabilities with scanner-specific logic.
        Override for custom processing (e.g., deduplication, severity normalization).
        Default: default allow-duplicates behavior.
        """
        pass
    
    def extract_visual_context(self, visual_layout_path: str) -> VisualContext:
        """
        Extract initial context from visual layout (severity, port, protocol, host).
        Override if scanner needs visual layout extraction.

        Returns:
            VisualContext(lines, severity, port, protocol, host).
            Default: empty context.
        """
        return VisualContext([], None, None, None, None)

    def create_blocks(self, report_text: str, temp_dir: str, initial_context: VisualContext, output_ext: str = "txt") -> List[Block]:
        """
        Create blocks from report text. Override for custom logic.
        Default: Creates a single block with entire report.

        Args:
            report_text: Text extracted from report
            temp_dir: Directory to save block files
            initial_context: Tuple from extract_visual_context()
            output_ext: Extension to use for block files (e.g. "txt", "md")

        Returns:
            List of block dictionaries with structure:
            {'file': path, 'port': port, 'protocol': protocol, 'severity': severity}
        """
        import os

        initial_context_lines, initial_severity, initial_port, initial_protocol, initial_host = initial_context

        # Default: single block with all text
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
            'severity': initial_severity,
            'host': initial_host
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
