import re
import os
from typing import List, Dict
from .base import Block, ScannerStrategy, VisualContext
from .registry import register_strategy

@register_strategy('tenable')
class TenableWASStrategy(ScannerStrategy):
    scanner_name = 'tenable'
    requires_visual_layout = False
    has_merge_log = True
    
    def get_custom_activation_value(self) -> bool:
        """Custom consolidation activates when allow_duplicates=False"""
        return False
    
    # Header detection — accepts optional markdown heading prefix (`#+ `) and
    # section-number prefix (`2.1.1 `) so reports rendered via the markdown
    # extractor still match. Tenable's "VULNERABILITY ... PLUGIN ID" phrase
    # is distinctive enough that we don't need an alt-order regex like OpenVAS.
    HEADER_PATTERN = re.compile(
        r'(?:#+\s+)?(?:\d+(?:\.\d+)*\s+)?VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+PLUGIN\s+ID\s+\d+',
        re.IGNORECASE
    )
    SEVERITY_FIELD_PATTERN = re.compile(
        r'^\s*(?:#+\s+)?SEVERITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*$',
        re.IGNORECASE
    )
    
    def create_blocks(self, report_text: str, temp_dir: str, initial_context: VisualContext, output_ext: str = "txt") -> List[Block]:
        """
        Create blocks by severity for Tenable WAS.
        Strategy: Single pass through text, detecting each header
        "VULNERABILITY <SEVERITY> PLUGIN ID" and assigning content until next header.

        Args:
            output_ext: Extension to use for block files (e.g. "txt", "md")
        """
        file_ext = f".{output_ext}"
        
        severidades = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        blocks_por_severidade = {s: [] for s in severidades}
        
        lines = report_text.splitlines()
        current_severity = None
        current_block = []
        pre_header_lines = []
        first_header_found = False
        
        for line in lines:
            header_match = self.HEADER_PATTERN.search(line)
            
            if header_match:
                if not first_header_found:
                    # Determine severity of orphaned content (before first header)
                    orphan_severity = None
                    for orphan_line in pre_header_lines:
                        m = self.SEVERITY_FIELD_PATTERN.match(orphan_line)
                        if m:
                            orphan_severity = m.group(1).upper()
                            break
                    if orphan_severity and pre_header_lines:
                        blocks_por_severidade[orphan_severity].extend(pre_header_lines)
                    first_header_found = True
                
                if current_severity and current_block:
                    blocks_por_severidade[current_severity].extend(current_block)
                
                current_severity = header_match.group(1).upper()
                current_block = [line]
            elif not first_header_found:
                pre_header_lines.append(line)
            elif current_severity:
                current_block.append(line)
        
        if current_severity and current_block:
            blocks_por_severidade[current_severity].extend(current_block)
        
        # Create block files only for severities with content
        blocks = []
        for severidade in severidades:
            bloco = blocks_por_severidade[severidade]
            if bloco:
                block_path = os.path.join(temp_dir, f"block_tenable_{severidade}{file_ext}")
                with open(block_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(bloco))
                blocks.append({
                    'file': block_path,
                    'port': None,
                    'protocol': None,
                    'severity': severidade
                })
        
        return blocks
    
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """
        Consolidate Tenable WAS vulnerabilities already extracted into unified model.
        """
        if not vulns:
            return []
        # Defensive deduplication by Name + plugin
        seen = {}
        for v in vulns:
            key = (v.get('Name', '').strip(), v.get('plugin'))
            if key not in seen:
                seen[key] = v
            else:
                existing = seen[key]
                new_instances = v.get('instances', [])
                if new_instances:
                    existing.setdefault('instances', []).extend(new_instances)
                # Preenche campos vazios do existente com dados do novo
                for field in ['description', 'solution', 'cvss', 'references']:
                    if not existing.get(field) and v.get(field):
                        existing[field] = v[field]
        return list(seen.values())

    def get_consolidation_report(self, input_count: int, output_count: int, removed: int) -> Dict:
        """
        Return report specific to Tenable strategy.
        """
        return {
            'strategy_name': 'Tenable WAS custom merge',
            'description': 'Groups vulnerabilities by (Name, plugin), merges instances and metadata',
            'input_count': input_count,
            'output_count': output_count,
            'removed': removed,
            'reason': 'instance consolidation',
            'note': 'This is the custom Tenable WAS consolidation strategy'
        }
