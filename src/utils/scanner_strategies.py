"""
Scanner-specific extraction rules and consolidation strategies.
Extensível para novos scanners: OpenVAS, Tenable WAS, Nessus, etc.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import re


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
    """OpenVAS não consolida, cada vulnerabilidade é independente."""
    
    @property
    def source_name(self) -> str:
        return 'OPENVAS'
    
    def should_consolidate(self) -> bool:
        return False
    
    def get_base_name(self, name: str) -> str:
        return name
    
    def consolidate_group(self, vulns: List[Dict]) -> List[Dict]:
        # OpenVAS não consolida - retornar como está
        return vulns


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
        return True
    
    def get_base_name(self, name: str) -> str:
        """Remove ' Instances (N)' do final"""
        return re.sub(r'\s+Instances\s*\(\d+\)$', '', name)
    
    def consolidate_group(self, vulns: List[Dict]) -> List[Dict]:
        """
        Consolida grupo de Tenable WAS.
        MANTÉM AMBAS as versões: com Instances(N) e base name.
        
        Lógica:
        1. Separar em 2 grupos: com "Instances (N)" e sem
        2. Consolidar DENTRO de cada grupo
        3. Retornar ambos os grupos consolidados (máx 2 objetos)
        """
        if len(vulns) == 1:
            return vulns
        
        # Separar em 2 grupos: com Instances e sem
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
            
            # Usar NOME EXATO da ÚLTIMA item do grupo
            consolidated = group[0].copy()
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


def consolidate_by_scanner(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Consolida vulnerabilidades usando estratégia específica de cada scanner.
    
    Lógica:
    1. Agrupa por source (OPENVAS, TENABLEWAS, etc)
    2. Para cada source, aplica sua estratégia
    3. Retorna lista consolidada
    
    Args:
        vulnerabilities: Lista de vulnerabilidades mistas
        
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
        
        # Agrupar por base name
        by_name = defaultdict(list)
        for vuln in vulns:
            name = vuln.get('Name', '').strip()
            if name:
                base_name = strategy.get_base_name(name)
                by_name[base_name].append(vuln)
        
        # Consolidar cada grupo
        for base_name, group in by_name.items():
            result = strategy.consolidate_group(group)
            consolidated.extend(result)
    
    return consolidated
