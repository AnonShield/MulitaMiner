import re
from typing import List, Dict
from .base import ScannerStrategy

class TenableWASStrategy(ScannerStrategy):
    has_merge_log = True
    def vulnerability_processing_logic(self, vulns: List[Dict], allow_duplicates: bool = True, profile_config: Dict = None) -> List[Dict]:
        """
        Consolida vulnerabilidades Tenable WAS já extraídas em modelo unificado.
        """
        if not vulns:
            return []
        # Deduplicação defensiva por Name + plugin
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
        Retorna report específico da estratégia Tenable.
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
        print(f"[{idx}] Analisando: Name={name} | Plugin={plugin}")
        if 'Instances (' in name:
            base_name = re.sub(r'\s+Instances\s*\(\d+\)$', '', name)
            key = (base_name, plugin)
            print(f"  -> É instance. Key={key}")
            if v.get('instances'):
                print(f"    -> Adicionando {len(v.get('instances', []))} instances agrupadas ao grupo {key}")
                instances_dict.setdefault(key, []).extend(v.get('instances', []))
            else:
                print(f"    -> Adicionando instance isolada ao grupo {key}")
                instances_dict.setdefault(key, []).append(v)
        else:
            key = (name, plugin)
            print(f"  -> É base. Key={key}")
            if key not in base_dict:
                base_dict[key] = v
                print(f"    -> Registrando base para {key}")
            else:
                print(f"    -> Base já registrada para {key}, ignorando.")

    print("\nResumo base_dict:")
    for k, v in base_dict.items():
        print(f"  Base {k}: Name={v.get('Name')} | Desc={' '.join(v.get('description', []))[:60]}")
    print("\nResumo instances_dict:")
    for k, lst in instances_dict.items():
        print(f"  Instances {k}: {len(lst)} instâncias")

    result = []
    # Para cada chave, se existe base, associa instâncias; se não existe base, cria base sintética
    all_keys = set(base_dict.keys()) | set(instances_dict.keys())
    for key in all_keys:
        if key in base_dict:
            base = base_dict[key]
            base['instances'] = instances_dict.get(key, [])
            result.append(base)
        else:
            # Cria base sintética a partir da primeira instância
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
