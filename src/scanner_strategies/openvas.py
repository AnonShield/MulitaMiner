import re
import os
from typing import List, Dict, Tuple
from .base import ScannerStrategy

class OpenVASStrategy(ScannerStrategy):
    scanner_name = 'openvas'
    requires_visual_layout = True
    has_merge_log = False
    
    def get_custom_activation_value(self) -> bool:
        """Custom consolidation activates when allow_duplicates=True"""
        return True
    
    # Constantes para headers
    HEADER_REGEX = re.compile(
        r"^(?:\d+\.\d+\.\d+\s+)?(Critical|High|Medium|Low|Log)\s+(\d+|general)/([a-zA-Z0-9_-]+)",
        re.IGNORECASE
    )
    HEADER_REGEX_ALT = re.compile(
        r"^(Critical|High|Medium|Low|Log)\s+(\d+|general)/([a-zA-Z0-9_-]+)",
        re.IGNORECASE
    )
    
    def extract_visual_context(self, visual_layout_path: str) -> Tuple[List, None, None, None]:
        """Extract severity/port/protocol from visual layout PDF."""
        if not visual_layout_path or 'openvas' not in visual_layout_path.lower():
            return [], None, None, None
        
        initial_context_lines = []
        initial_severity = None
        initial_port = None
        initial_protocol = None
        
        try:
            with open(visual_layout_path, encoding="utf-8") as f:
                layout_lines = [l.strip() for l in f.readlines() if l.strip()]
            
            # Search from bottom to top for first valid header
            found_idx = None
            for idx in range(len(layout_lines)-1, -1, -1):
                line = layout_lines[idx]
                m = self.HEADER_REGEX.match(line)
                if not m:
                    m = self.HEADER_REGEX_ALT.match(line)
                if m:
                    initial_severity = m.group(1)
                    initial_port = m.group(2)
                    initial_protocol = m.group(3)
                    found_idx = idx
                    break
            
            # Define initial_context_lines as last 5 lines above found header (or all if none)
            if found_idx is not None:
                initial_context_lines = layout_lines[max(0, found_idx-4):found_idx+1]
            else:
                initial_context_lines = layout_lines[-5:] if layout_lines else []
        
        except Exception:
            pass
        
        return initial_context_lines, initial_severity, initial_port, initial_protocol
    
    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple) -> List[Dict]:
        """Parse OpenVAS report and create blocks for each vulnerability."""
        initial_context_lines, initial_severity, initial_port, initial_protocol = initial_context
        
        lines = report_text.splitlines()
        blocks = []
        current_block = []
        current_port = initial_port
        current_protocol = initial_protocol
        current_severity = initial_severity
        block_idx = 0
        
        # Try to extract port/protocol from first NVT
        first_nvt_idx = next((i for i, l in enumerate(lines) if l.strip().startswith('NVT:')), None)
        if first_nvt_idx is not None and first_nvt_idx >= 2:
            port_line = lines[first_nvt_idx - 2].strip()
            port_match = self.HEADER_REGEX.match(port_line)
            if port_match:
                current_severity = port_match.group(1)
                current_port = port_match.group(2)
                current_protocol = port_match.group(3)
            else:
                alt_match = re.match(r"^(\d+|general)/([a-zA-Z0-9_-]+)", port_line, re.IGNORECASE)
                if alt_match:
                    current_port = alt_match.group(1)
                    current_protocol = alt_match.group(2)
        
        # Iterate through lines and create blocks by severity headers
        for line in lines:
            header_match = self.HEADER_REGEX.match(line.strip())
            if header_match:
                if current_block:
                    bloco_severity = current_severity
                    bloco_port = current_port
                    bloco_protocol = current_protocol
                    block_idx += 1
                    block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}.txt")
                    with open(block_path, 'w', encoding='utf-8') as f:
                        if len(blocks) == 0 and initial_context_lines:
                            for ctx_line in initial_context_lines:
                                f.write(f"{ctx_line}\n")
                            f.write("---\n")
                        f.write('\n'.join(current_block))
                    blocks.append({
                        'file': block_path,
                        'port': bloco_port,
                        'protocol': bloco_protocol,
                        'severity': bloco_severity
                    })
                    current_block = []
                current_severity = header_match.group(1)
                current_port = header_match.group(2)
                current_protocol = header_match.group(3)
            current_block.append(line)
        
        # Handle last block
        if current_block:
            block_idx += 1
            bloco_is_first = (len(blocks) == 0)
            bloco_port = current_port
            bloco_protocol = current_protocol
            bloco_severity = current_severity
            
            if bloco_is_first:
                if bloco_port is None and initial_port is not None:
                    bloco_port = initial_port
                if bloco_protocol is None and initial_protocol is not None:
                    bloco_protocol = initial_protocol
                if bloco_severity is None and initial_severity is not None:
                    bloco_severity = initial_severity
            
            block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}.txt")
            with open(block_path, 'w', encoding='utf-8') as f:
                if bloco_is_first and initial_context_lines:
                    for ctx_line in initial_context_lines:
                        f.write(f"{ctx_line}\n")
                    f.write("---\n")
                f.write('\n'.join(current_block))
            blocks.append({
                'file': block_path,
                'port': bloco_port,
                'protocol': bloco_protocol,
                'severity': bloco_severity
            })
        
        return blocks
    
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """
        Consolida todas as vulnerabilidades do OpenVAS agrupando por (Name, port, protocol),
        faz merge das duplicatas, mantendo a mais completa (com descrição válida).
        """
        if not vulns:
            return []
        from collections import defaultdict
        grouped = defaultdict(list)
        for v in vulns:
            name = v.get('Name', '').strip()
            port = v.get('port')
            protocol = v.get('protocol')
            if name == 'Services':
                # Garante que todos os valores sejam hashable
                def make_hashable(val):
                    if isinstance(val, list):
                        return tuple(val)
                    elif isinstance(val, dict):
                        return tuple(sorted(val.items()))
                    else:
                        return val
                key = tuple(sorted((k, make_hashable(vv)) for k, vv in v.items()))
            else:
                key = (name, port, protocol)
            grouped[key].append(v)
        merged = []
        def count_filled_fields(vuln):
            return sum(1 for k, val in vuln.items() if val not in [None, '', [], {}, 0])
        for group in grouped.values():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Merge: keep the most complete
                most_complete = max(group, key=count_filled_fields)
                merged.append(most_complete)
        return merged
    
    def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
        """
        Retorna report específico da estratégia OpenVAS.
        """
        return {
            'strategy_name': 'OpenVAS custom merge',
            'description': 'Groups vulnerabilities by (Name, port, protocol), keeps most complete',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'duplicate merge',
            'note': 'This is the custom OpenVAS consolidation strategy'
        }
