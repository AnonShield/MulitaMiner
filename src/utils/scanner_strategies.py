"""
Scanner-specific extraction rules and consolidation strategies.
Extensível para novos scanners: OpenVAS, Tenable WAS, Nessus, etc.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import re
import math
from difflib import SequenceMatcher


class ScannerStrategy(ABC):
    """
    Estratégia abstrata para cada tipo de scanner.
    Cada scanner implementa sua própria lógica.
    """
    
    @property
    @abstractmethod
    def source_name(self) -> str:
        """Retorna o nome da fonte (e.g., 'OPENVAS', 'TENABLEWAS')"""
        pass
    
    @abstractmethod
    def should_consolidate(self) -> bool:
        """Se deve consolidar duplicatas desta fonte"""
        pass
    
    @abstractmethod
    def get_base_name(self, name: str) -> str:
        """Extrai base name para agrupar duplicatas"""
        pass
    
    @abstractmethod
    def consolidate_group(self, vulns: List[Dict]) -> List[Dict]:
        """
        Consolida um grupo de vulnerabilidades iguais.
        
        Args:
            vulns: Lista de vulnerabilidades com mesmo base name
            
        Returns:
            Lista de vulnerabilidades consolidadas (1+ objetos)
        """
        pass


class OpenVASStrategy(ScannerStrategy):
    """OpenVAS consolida por nome + porta + protocolo."""
    
    @property
    def source_name(self) -> str:
        return 'OPENVAS'
    
    def should_consolidate(self) -> bool:
        return True
    
    def get_base_name(self, name: str) -> str:
        """Chave de consolidação: nome + porta + protocolo"""
        return name  # A chave será construída no consolidate_by_scanner
    
    def consolidate_group(self, vulns: List[Dict]) -> List[Dict]:
        """
        Consolida vulnerabilidades OpenVAS com mesmo nome, porta e protocolo.
        Mescla arrays de campos quando apropriado.
        """
        if len(vulns) <= 1:
            return vulns
        
        # Agrupar por (nome, porta, protocolo) para consolidar corretamente
        from collections import defaultdict
        by_key = defaultdict(list)
        
        for vuln in vulns:
            name = vuln.get('Name', '').strip()
            port = vuln.get('port')
            protocol = vuln.get('protocol')
            
            # Chave de consolidação
            key = (name, port, protocol)
            by_key[key].append(vuln)
        
        consolidated = []
        for key, group in by_key.items():
            if len(group) == 1:
                consolidated.extend(group)
            else:
                base_vuln = group[0].copy()
                array_fields = ['description', 'detection_result', 'detection_method', 
                               'product_detection_result', 'impact', 'solution', 
                               'insight', 'log_method', 'references', 'cvss']
                scalar_fields = ['port', 'protocol']
                # Mesclar arrays sem repetição
                for field in array_fields:
                    all_values = []
                    for vuln in group:
                        values = vuln.get(field, [])
                        if isinstance(values, list):
                            all_values.extend(values)
                        else:
                            all_values.append(values)
                    # Remover duplicatas mantendo ordem
                    seen = set()
                    unique_values = []
                    for v in all_values:
                        v_str = str(v) if not isinstance(v, (list, dict)) else str(sorted(v.items()) if isinstance(v, dict) else sorted(v))
                        if v_str not in seen:
                            unique_values.append(v)
                            seen.add(v_str)
                    base_vuln[field] = unique_values
                # Mesclar campos escalares: se todos iguais, manter um só; se diferentes, escolher o mais frequente (ou o primeiro não nulo)
                for field in scalar_fields:
                    values = [v.get(field) for v in group if v.get(field) not in [None, '', 0]]
                    if values:
                        # Se todos iguais, manter um só
                        if all(val == values[0] for val in values):
                            base_vuln[field] = values[0]
                        else:
                            # Escolher o mais frequente
                            from collections import Counter
                            most_common = Counter(values).most_common(1)[0][0]
                            base_vuln[field] = most_common
                consolidated.append(base_vuln)
        
        return consolidated


class TenableWASStrategy(ScannerStrategy):
    """
    Tenable WAS consolida por base name.
    Usa nome EXATO da última instance para nomear final.
    Consolida todas as URLs em um único array.
    """
    
    @property
    def source_name(self) -> str:
        return 'TENABLEWAS'
    
    def should_consolidate(self) -> bool:
        return False
    
    def get_base_name(self, name: str) -> str:
        """Remove ' Instances (N)' do final"""
        return re.sub(r'\s+Instances\s*\(\d+\)$', '', name)
    
    def consolidate_group(self, vulns: List[Dict], profile_config: Dict = None) -> List[Dict]:
        """
        Consolida grupo de Tenable WAS.
        MANTÉM AMBAS as versões: com Instances(N) e base name.
        
        Lógica:
        1. Se merge_instances_with_same_base=True: consolida todas as instances do mesmo tipo
        2. Separar em 2 grupos: com "Instances (N)" e sem
        3. Consolidar DENTRO de cada grupo
        4. Retornar ambos os grupos consolidados (máx 2 objetos)
        """
        if len(vulns) == 1:
            return vulns

        # Configurações do perfil
        merge_instances = profile_config.get('merge_instances_with_same_base', False) if profile_config else False
        use_highest_count = profile_config.get('use_highest_instance_count', True) if profile_config else True

        # Se merge_instances está habilitado, agrupar instances do mesmo tipo
        if merge_instances:
            # Agrupar instances por nome base (sem o número N)
            instance_groups = {}
            base_groups = {}
            
            for v in vulns:
                name = v.get('Name', '')
                if 'Instances (' in name:
                    # Extrair nome base sem o (N)
                    base_name = re.sub(r'\s+Instances\s*\(\d+\)$', '', name)
                    if base_name not in instance_groups:
                        instance_groups[base_name] = []
                    instance_groups[base_name].append(v)
                else:
                    # Agrupar bases por nome exato também
                    if name not in base_groups:
                        base_groups[name] = []
                    base_groups[name].append(v)
            
            # Consolidar cada grupo de instances
            consolidated_instances = []
            for base_name, instances in instance_groups.items():
                if len(instances) > 1:
                    # Múltiplas instances do mesmo tipo - consolidar
                    consolidated = self._merge_instances_group(instances, use_highest_count, profile_config)
                    if consolidated:
                        consolidated_instances.append(consolidated)
                else:
                    # Só uma instance, manter como está
                    consolidated_instances.extend(instances)
            
            # Consolidar cada grupo de bases também
            consolidated_bases = []
            for base_name, bases in base_groups.items():
                if len(bases) > 1:
                    # Múltiplas bases do mesmo nome - consolidar
                    consolidated = self._merge_base_group(bases, profile_config)
                    if consolidated:
                        consolidated_bases.append(consolidated)
                else:
                    # Só uma base, manter como está
                    consolidated_bases.extend(bases)
            
            # Retornar instances consolidadas + bases consolidadas
            return consolidated_instances + consolidated_bases
        
        # Lógica original - separar em grupos
        with_instances = []
        without_instances = []
        
        for v in vulns:
            if 'Instances (' in v.get('Name', ''):
                with_instances.append(v)
            else:
                without_instances.append(v)
        
        result = []
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5, 'LOG': 0}
        array_fields = ['description', 'solution', 'references', 'identification', 
                       'http_info', 'plugin', 'detection_result', 'detection_method',
                       'impact', 'insight', 'product_detection_result', 'log_method']
        
        def _consolidate_group_helper(group):
            """Helper para consolidar um grupo."""
            if not group:
                return None
            
            if len(group) == 1:
                return group[0]
            
            # Para Instances com (N), usar o que tem MAIOR N
            # Para outros, usar o último item do grupo  
            consolidated = group[0].copy()
            
            # Encontrar item com maior N se for Instances
            instances_items = [v for v in group if 'Instances (' in v.get('Name', '')]
            if instances_items:
                # Extrair números N e encontrar o maior
                max_n = 0
                best_item = instances_items[0]
                
                for item in instances_items:
                    name = item.get('Name', '')
                    import re
                    match = re.search(r'Instances \((\d+)\)', name)
                    if match:
                        n = int(match.group(1))
                        if n > max_n:
                            max_n = n
                            best_item = item
                
                consolidated['Name'] = best_item.get('Name')
            else:
                # Não é Instances, usar último item
                consolidated['Name'] = group[-1].get('Name')
            
            # Mesclar arrays
            for field in array_fields:
                all_values = []
                for v in group:
                    val = v.get(field, [])
                    if isinstance(val, list):
                        all_values.extend(val)
                    elif val is not None:
                        all_values.append(val)
                
                # Remover duplicatas mantendo ordem
                unique = []
                seen = set()
                for item in all_values:
                    key = item.lower() if isinstance(item, str) else str(item)
                    if key not in seen:
                        seen.add(key)
                        unique.append(item)
                
                consolidated[field] = unique
            
            # Severity: máxima
            severities = [v.get('severity', 'LOG') for v in group]
            consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
            
            return consolidated
        
        # Consolidar ambos os grupos
        if with_instances:
            result.append(_consolidate_group_helper(with_instances))
        
        if without_instances:
            result.append(_consolidate_group_helper(without_instances))
        
        return result

    def _merge_instances_group(self, instances: List[Dict], use_highest_count: bool = True, profile_config: Dict = None) -> Dict:
        """
        Mescla múltiplas instances do mesmo tipo base.
        
        Args:
            instances: Lista de instances com mesmo nome base
            use_highest_count: Se True, usa o nome com maior (N)
            profile_config: Configuração do perfil para merge settings
        
        Returns:
            Vulnerabilidade consolidada com todos os campos mesclados
        """
        if not instances:
            return None
        
        if len(instances) == 1:
            return instances[0]
        
        # Encontrar a instance com maior N se configurado
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
        
        # Criar vulnerabilidade consolidada baseada na instance com maior N
        consolidated = target_instance.copy()
        
        # Obter configurações de merge do profile_config se disponível
        merge_all_fields = profile_config.get('merge_all_fields', True) if profile_config else True
        preserve_highest_severity = profile_config.get('preserve_highest_severity', True) if profile_config else True
        merge_scalar_fields = profile_config.get('merge_scalar_fields', ['port', 'protocol']) if profile_config else ['port', 'protocol']
        merge_array_fields = profile_config.get('merge_array_fields', [
            'identification', 'http_info', 'description', 'solution', 
            'references', 'plugin', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method'
        ]) if profile_config else [
            'identification', 'http_info', 'description', 'solution', 
            'references', 'plugin', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method'
        ]
        
        # Mesclar arrays de todas as instances
        for field in merge_array_fields:
            all_values = []
            for instance in instances:
                val = instance.get(field, [])
                if isinstance(val, list):
                    all_values.extend(val)
                elif val is not None:
                    all_values.append(val)
            
            # Remover duplicatas mantendo ordem
            unique = []
            seen = set()
            for item in all_values:
                key = item.lower() if isinstance(item, str) else str(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            
            consolidated[field] = unique
        
        # Mesclar campos escalares (usar valores não-null da instance com maior N primeiro)
        for field in merge_scalar_fields:
            # Tentar usar valor da target_instance primeiro
            if consolidated.get(field) in [None, "", 0]:
                for instance in sorted(instances, key=lambda x: self._extract_instance_number(x.get('Name', '')), reverse=True):
                    val = instance.get(field)
                    if val not in [None, "", 0]:
                        consolidated[field] = val
                        break
        
        # Usar severity máxima se configurado
        if preserve_highest_severity:
            severities = [v.get('severity', 'LOG') for v in instances]
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5, 'LOG': 0}
            consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        
        # Garantir que campos críticos não fiquem vazios
        if not consolidated.get('identification'):
            # Se identification vazio, tentar coletar de qualquer instance
            for instance in instances:
                ident = instance.get('identification', [])
                if ident and len(ident) > 0:
                    consolidated['identification'] = ident
                    break
        
        if not consolidated.get('http_info'):
            # Se http_info vazio, tentar coletar de qualquer instance
            for instance in instances:
                http = instance.get('http_info', [])
                if http and len(http) > 0:
                    consolidated['http_info'] = http
                    break
        consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        
        print(f"[MERGE] Mescladas {len(instances)} instances do tipo '{self.get_base_name(target_instance.get('Name', ''))}' → Nome final: '{consolidated['Name']}'")
        
        return consolidated
    
    def _merge_base_group(self, vulnerabilities, profile_config):
        """
        Consolida múltiplas vulnerabilidades base com o mesmo nome.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades com o mesmo nome base
            profile_config: Configuração do profile para personalizações
            
        Returns:
            dict: Vulnerabilidade consolidada ou None
        """
        if not vulnerabilities:
            return None
            
        if len(vulnerabilities) == 1:
            return vulnerabilities[0]
        
        # Usar a primeira vulnerabilidade como base
        consolidated = vulnerabilities[0].copy()
        
        # Obter configurações de merge do profile_config se disponível
        merge_all_fields = profile_config.get('merge_all_fields', True) if profile_config else True
        preserve_highest_severity = profile_config.get('preserve_highest_severity', True) if profile_config else True
        merge_array_fields = profile_config.get('merge_array_fields', [
            'identification', 'http_info', 'description', 'solution', 
            'references', 'plugin', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method'
        ]) if profile_config else [
            'identification', 'http_info', 'description', 'solution', 
            'references', 'plugin', 'cvss', 'detection_result', 'detection_method',
            'impact', 'insight', 'product_detection_result', 'log_method'
        ]
        
        # Mesclar arrays de todas as vulnerabilidades
        for field in merge_array_fields:
            all_values = []
            for vuln in vulnerabilities:
                val = vuln.get(field, [])
                if isinstance(val, list):
                    all_values.extend(val)
                elif val is not None:
                    all_values.append(val)
            
            # Remover duplicatas mantendo ordem
            unique = []
            seen = set()
            for item in all_values:
                key = item.lower() if isinstance(item, str) else str(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            
            consolidated[field] = unique
        
        # Usar severidade mais alta
        if preserve_highest_severity:
            severities = [v.get('severity', 'LOG') for v in vulnerabilities]
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0.5, 'LOG': 0}
            consolidated['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        
        print(f"[MERGE] Mescladas {len(vulnerabilities)} bases com mesmo nome '{consolidated['Name']}'")
        
        return consolidated

    def _extract_instance_number(self, name: str) -> int:
        """Extrai o número N de 'Instances (N)' do nome."""
        import re
        match = re.search(r'Instances \((\d+)\)', name)
        return int(match.group(1)) if match else 0


# Registry de estratégias por scanner
SCANNER_STRATEGIES = {
    'OPENVAS': OpenVASStrategy(),
    'TENABLEWAS': TenableWASStrategy(),
}


def get_strategy(source: str) -> ScannerStrategy:
    """
    Retorna a estratégia para um scanner específico.
    
    Args:
        source: Nome da fonte (OPENVAS, TENABLEWAS, etc)
        
    Returns:
        Instância da estratégia ou None se não encontrada
    """
    return SCANNER_STRATEGIES.get(source.upper())


def consolidate_by_scanner(vulnerabilities: List[Dict], profile_config: Dict = None) -> List[Dict]:
    """
    Consolida vulnerabilidades usando estratégia específica de cada scanner.
    
    Lógica:
    1. Agrupa por source (OPENVAS, TENABLEWAS, etc)
    2. Para cada source, aplica sua estratégia
    3. Retorna lista consolidada
    
    Args:
        vulnerabilities: Lista de vulnerabilidades mistas
        profile_config: Configuração do perfil (para Tenable WAS merge options)
        
    Returns:
        Lista consolidada por estratégia de cada scanner
    """
    from collections import defaultdict
    
    # Agrupar por source
    by_source = defaultdict(list)
    for vuln in vulnerabilities:
        source = vuln.get('source', 'UNKNOWN')
        by_source[source].append(vuln)
    
    consolidated = []
    
    for source, vulns in by_source.items():
        strategy = get_strategy(source)
        
        if not strategy:
            # Fonte desconhecida - não consolidar
            consolidated.extend(vulns)
            continue
        
        if not strategy.should_consolidate():
            # Esta fonte não consolida
            consolidated.extend(vulns)
            continue
        
        # Agrupar por base name ou chave composta (para OpenVAS: nome + porta + protocolo)
        if source == 'OPENVAS':
            # Para OpenVAS, usar chave composta
            by_key = defaultdict(list)
            for vuln in vulns:
                name = vuln.get('Name', '').strip()
                port = vuln.get('port')
                protocol = vuln.get('protocol')
                if name:
                    key = (name, port, protocol)
                    by_key[key].append(vuln)
        else:
            # Para outros scanners, usar base name
            by_name = defaultdict(list)
            for vuln in vulns:
                name = vuln.get('Name', '').strip()
                if name:
                    base_name = strategy.get_base_name(name)
                    by_name[base_name].append(vuln)
        
        # Consolidar cada grupo
        if source == 'OPENVAS':
            for key, group in by_key.items():
                result = strategy.consolidate_group(group)
                consolidated.extend(result)
        else:
            for base_name, group in by_name.items():
                if source == 'TENABLEWAS':
                    result = strategy.consolidate_group(group, profile_config)
                else:
                    result = strategy.consolidate_group(group)
                consolidated.extend(result)
    
    return consolidated


def build_key(vuln):
    name = str(vuln.get('Name', '')).strip().lower()
    port = str(vuln.get('port', '')).strip()
    protocol = str(vuln.get('protocol', '')).strip().lower()
    host = str(vuln.get('host', '')).strip().lower()
    severity = str(vuln.get('severity', '')).strip().lower()
    description = str(vuln.get('description', '')).strip().lower()[:200]
    references = '|'.join(sorted([str(r) for r in vuln.get('references', [])]))
    if port and protocol:
        return (name, port, protocol, severity)
    else:
        return (name, host, description, severity, references)

def fuzzy_match(a, b, threshold=0.98):
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a, b).ratio() >= threshold

def get_scanner_type(vulnerabilities: list) -> str:
    """
    Detecta o tipo de scanner baseado no campo 'source' das vulnerabilidades.
    
    Returns:
        'openvas', 'tenable', ou 'unknown'
    """
    if not vulnerabilities:
        return 'unknown'
    
    for vuln in vulnerabilities:
        source = str(vuln.get('source', '')).upper()
        if source == 'OPENVAS':
            return 'openvas'
        elif source in ('TENABLEWAS', 'TENABLE'):
            return 'tenable'
    
    return 'unknown'

def remove_duplicates_by_key(vulnerabilities: list, log_path=None) -> list:
    """
    Deduplicação robusta (--allow-duplicates):
    - OpenVAS: chave = (Name, port, protocol) - SEM severity (mesma vuln/porta = mesma severidade)
    - Tenable: chave = (Name, severity)
    - EXCEÇÃO para "Services": só mescla se 100% idêntico (todos os campos)
    - Log detalhado se log_path for fornecido
    """
    import json
    seen = []
    result = []
    duplicates_log = []
    scanner_type = get_scanner_type(vulnerabilities)
    def has_valid_description(vuln):
        desc = vuln.get("description")
        if not desc:
            return False
        if isinstance(desc, list):
            return any(str(d).strip() for d in desc)
        return bool(str(desc).strip())

    key_to_vuln = {}
    key_to_all = {}
    for vuln in vulnerabilities:
        name = str(vuln.get('Name', '')).strip().lower()  # lowercase como no código original
        if scanner_type == 'openvas':
            if name == 'services':
                vuln_serialized = json.dumps(vuln, sort_keys=True, default=str)
                key = ('services_exact', hash(vuln_serialized))
            else:
                key = (name, str(vuln.get('port', '')).strip(), str(vuln.get('protocol', '')).strip().lower())
        elif scanner_type == 'tenable':
            severity = str(vuln.get('severity', '')).strip().lower()
            key = (name, severity)
        else:
            severity = str(vuln.get('severity', '')).strip().lower()
            key = (name, severity)
        if key not in key_to_all:
            key_to_all[key] = []
        key_to_all[key].append(vuln)

    def count_filled_fields(vuln):
        # Conta campos não nulos, não vazios, não lista vazia
        return sum(1 for k, v in vuln.items() if v not in [None, '', [], {}])

    for key, vulns in key_to_all.items():
        with_desc = [v for v in vulns if has_valid_description(v)]
        if with_desc:
            # Se múltiplas com descrição, prioriza a mais preenchida
            chosen = max(with_desc, key=count_filled_fields)
        else:
            chosen = max(vulns, key=count_filled_fields)
        result.append(chosen)
        for v in vulns:
            if v is not chosen:
                duplicates_log.append((key, v))
    if log_path and duplicates_log:
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(
                "# LOG DE DEDUPLICAÇÃO DE VULNERABILIDADES\n"
                "Este arquivo lista todas as vulnerabilidades consideradas duplicatas e agrupadas durante o processo.\n"
                "Cada grupo é identificado por uma chave composta (ex: nome, porta, protocolo).\n"
                "Apenas a vulnerabilidade mais completa e com descrição válida foi mantida em cada grupo.\n\n"
            )
            total_grupos = len(set([str(key) for key, _ in duplicates_log]))
            total_dups = len(duplicates_log)
            f.write(f"Total de grupos de duplicatas: {total_grupos}\n")
            f.write(f"Total de vulnerabilidades agrupadas (removidas): {total_dups}\n\n")
            from collections import defaultdict
            grupos = defaultdict(list)
            for key, vuln in duplicates_log:
                grupos[str(key)].append(vuln)
            for idx, (key, vulns) in enumerate(grupos.items(), 1):
                f.write(f"Grupo {idx}: Chave = {key}\n")
                f.write(f"  Total de duplicatas neste grupo: {len(vulns)}\n")
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"    {i}. Nome: {vuln.get('Name', '')}\n")
                    f.write(f"       Porta: {vuln.get('port', '')} | Protocolo: {vuln.get('protocol', '')} | Severidade: {vuln.get('severity', '')}\n")
                    desc = vuln.get('description', '')
                    if desc:
                        if isinstance(desc, list):
                            desc = ' '.join([str(d) for d in desc if d])
                        desc = str(desc).strip().replace('\n', ' ')
                        f.write(f"       Descrição: {desc[:200]}{'...' if len(desc)>200 else ''}\n")
                    f.write("\n")
                f.write("\n")
            f.write("Resumo final:\n")
            f.write(f"Total de grupos de duplicatas: {total_grupos}\n")
            f.write(f"Total de vulnerabilidades agrupadas (removidas): {total_dups}\n")
    return result
def merge_duplicates_by_name(vulnerabilities: list) -> list:
    """
    Mescla vulnerabilidades por nome (case-insensitive), consolidando campos/contexto.
    """
    merged = {}
    for vuln in vulnerabilities:
        name = str(vuln.get('Name', '')).strip().lower()
        if name not in merged:
            merged[name] = vuln.copy()
            # Mesclar campos de lista
            for field in ['identification', 'http_info', 'references', 'description', 'detection_result', 'detection_method', 'product_detection_result', 'impact', 'solution', 'insight', 'log_method', 'cvss']:
                if field in merged[name] and isinstance(merged[name][field], list):
                    merged[name][field] = list(merged[name][field])
        else:
            # Mesclar campos de lista
            for field in ['identification', 'http_info', 'references', 'description', 'detection_result', 'detection_method', 'product_detection_result', 'impact', 'solution', 'insight', 'log_method', 'cvss']:
                if field in vuln and isinstance(vuln[field], list):
                    for item in vuln[field]:
                        if item not in merged[name][field]:
                            merged[name][field].append(item)
    return list(merged.values())
