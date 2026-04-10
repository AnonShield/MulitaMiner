import re
import os
from typing import List, Dict, Tuple
from .base import ScannerStrategy

class TenableWASStrategy(ScannerStrategy):
    scanner_name = 'tenable'
    requires_visual_layout = False
    has_merge_log = True
    
    # Constantes para Tenable
    HEADER_PATTERN = re.compile(
        r'VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+PLUGIN\s+ID\s+\d+',
        re.IGNORECASE
    )
    SEVERITY_FIELD_PATTERN = re.compile(
        r'^\s*SEVERITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*$',
        re.IGNORECASE
    )
    
    def create_blocks(self, report_text: str, temp_dir: str, initial_context: Tuple) -> List[Dict]:
        """
        Create blocks by severity for Tenable WAS.
        Strategy: Single pass through text, detecting each header 
        "VULNERABILITY <SEVERITY> PLUGIN ID" and assigning content until next header.
        """
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
                block_path = os.path.join(temp_dir, f"block_tenable_{severidade}.txt")
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
    
    def _merge_instances_group(self, instances: List[Dict], use_highest_count: bool = True, profile_config: Dict = None) -> Dict:
        if not instances:
            return None
        if len(instances) == 1:
            return instances[0]
        target_instance = instances[0]
        if use_highest_count:
            max_n = 0
            for instance in instances:
                name = instance.get('Name', '')
                match = re.search(r'Instances \((\d+)\)', name)
                if match:
                    n = int(match.group(1))
                    if n > max_n:
                        max_n = n
                        target_instance = instance
        consolidated = target_instance.copy()
        # Campos arrays reais do JSON atual
        merge_array_fields = profile_config.get('merge_array_fields', [
            'description', 'solution', 'references', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method', 'instances'
        ]) if profile_config else [
            'description', 'solution', 'references', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method', 'instances'
        ]
        merge_scalar_fields = profile_config.get('merge_scalar_fields', ['port', 'protocol', 'plugin', 'plugin_details']) if profile_config else ['port', 'protocol', 'plugin', 'plugin_details']
        preserve_highest_severity = profile_config.get('preserve_highest_severity', True) if profile_config else True
        # Merge arrays
        for field in merge_array_fields:
            all_values = []
            for instance in instances:
                val = instance.get(field, [])
                if isinstance(val, list):
                    all_values.extend(val)
                elif val is not None:
                    all_values.append(val)
            unique = []
            seen = set()
            for item in all_values:
                key = str(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            consolidated[field] = unique
        # Merge escalares
        for field in merge_scalar_fields:
            if consolidated.get(field) in [None, "", 0, {}]:
                for instance in sorted(instances, key=lambda x: self._extract_instance_number(x.get('Name', '')), reverse=True):
                    val = instance.get(field)
                    if val not in [None, "", 0, {}]:
                        consolidated[field] = val
                        break
        if preserve_highest_severity:
            severities = [v.get('severity', 'LOG') for v in instances]
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5, 'LOG': 0}
            consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        return consolidated
    
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
    
    def _merge_base_group(self, vulnerabilities, profile_config):
        if not vulnerabilities:
            return None
        if len(vulnerabilities) == 1:
            return vulnerabilities[0]
        consolidated = vulnerabilities[0].copy()
        merge_array_fields = profile_config.get('merge_array_fields', [
            'description', 'solution', 'references', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method', 'instances'
        ]) if profile_config else [
            'description', 'solution', 'references', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method', 'instances'
        ]
        merge_scalar_fields = profile_config.get('merge_scalar_fields', ['port', 'protocol', 'plugin', 'plugin_details']) if profile_config else ['port', 'protocol', 'plugin', 'plugin_details']
        preserve_highest_severity = profile_config.get('preserve_highest_severity', True) if profile_config else True
        # Merge arrays
        for field in merge_array_fields:
            all_values = []
            for vuln in vulnerabilities:
                val = vuln.get(field, [])
                if isinstance(val, list):
                    all_values.extend(val)
                elif val is not None:
                    all_values.append(val)
            unique = []
            seen = set()
            for item in all_values:
                key = str(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            consolidated[field] = unique
        # Merge escalares
        for field in merge_scalar_fields:
            if consolidated.get(field) in [None, "", 0, {}]:
                for vuln in vulnerabilities:
                    val = vuln.get(field)
                    if val not in [None, "", 0, {}]:
                        consolidated[field] = val
                        break
        if preserve_highest_severity:
            severities = [v.get('severity', 'LOG') for v in vulnerabilities]
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5, 'LOG': 0}
            consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        return consolidated
    
    def _extract_instance_number(self, name: str) -> int:
        match = re.search(r'Instances \((\d+)\)', name)
        return int(match.group(1)) if match else 0

def join_tenable_base_and_instances(vulns):
    """
    Junta vulnerabilidades base e suas instances pelo nome base e plugin_id.
    Retorna uma lista consolidada, onde cada base tem seu campo 'instances' preenchido corretamente.
    Se houver instances sem base correspondente, cria vulnerabilidade isolada para elas.
    """
    base_dict = {}
    instances_dict = {}
    for idx, v in enumerate(vulns):
        name = v.get('Name', '')
        plugin = v.get('plugin')
        print(f"[{idx}] Analyzing: Name={name} | Plugin={plugin}")
        if 'Instances (' in name:
            base_name = re.sub(r'\s+Instances\s*\(\d+\)$', '', name)
            key = (base_name, plugin)
            print(f"  -> Is instance. Key={key}")
            if v.get('instances'):
                print(f"    -> Adicionando {len(v.get('instances', []))} instances agrupadas ao grupo {key}")
                instances_dict.setdefault(key, []).extend(v.get('instances', []))
            else:
                print(f"    -> Adicionando instance isolada ao grupo {key}")
                instances_dict.setdefault(key, []).append(v)
        else:
            key = (name, plugin)
            print(f"  -> Is base. Key={key}")
            if key not in base_dict:
                base_dict[key] = v
                print(f"    -> Registrando base para {key}")
            else:
                print(f"    -> Base already registered for {key}, skipping.")

    print("\nResumo base_dict:")
    for k, v in base_dict.items():
        print(f"  Base {k}: Name={v.get('Name')} | Desc={' '.join(v.get('description', []))[:60]}")
    print("\nResumo instances_dict:")
    for k, lst in instances_dict.items():
        print(f"  Instances {k}: {len(lst)} instances")

    result = []
    # For each key, if base exists, associate instances; if not exists, create synthetic base
    all_keys = set(base_dict.keys()) | set(instances_dict.keys())
    for key in all_keys:
        if key in base_dict:
            base = base_dict[key]
            base['instances'] = instances_dict.get(key, [])
            result.append(base)
        else:
            # Create synthetic base from first instance
            inst_list = instances_dict.get(key, [])
            if inst_list:
                first = inst_list[0]
                base = {
                    'Name': key[0],
                    'description': first.get('description', []),
                    'detection_result': first.get('detection_result', []),
                    'detection_method': first.get('detection_method', []),
                    'product_detection_result': first.get('product_detection_result', []),
                    'impact': first.get('impact', []),
                    'solution': first.get('solution', []),
                    'insight': first.get('insight', []),
                    'log_method': first.get('log_method', []),
                    'cvss': first.get('cvss', []),
                    'port': first.get('port', None),
                    'protocol': first.get('protocol', None),
                    'severity': first.get('severity', 'LOG'),
                    'references': first.get('references', []),
                    'plugin': key[1],
                    'plugin_details': first.get('plugin_details', {}),
                    'instances': inst_list,
                    'source': first.get('source', 'TENABLEWAS'),
                }
                result.append(base)
    return result
