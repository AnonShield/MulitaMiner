import re
from typing import List, Dict
from .base import ScannerStrategy

class OpenVASStrategy(ScannerStrategy):
    has_merge_log = False
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
                # Faz merge: mantém a mais completa
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
