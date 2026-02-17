# --- Função para logs detalhados de removidos e merges ---
def consolidate_duplicates_with_logs(vulnerabilities: List[Dict], profile_config: Dict = None):
    """
    Consolida vulnerabilidades removendo duplicatas E mesclando URLs.
    Gera logs de removidos e merges.
    Retorna: (final_vulns, removed_vulns, merged_pairs)
    """
    if not vulnerabilities:
        return [], [], []

    removed = []
    merged = []
    # Remover vulnerabilidades sem descrição válida
    def has_valid_description(vuln):
        desc = vuln.get("description")
        if not desc:
            return False
        if isinstance(desc, list):
            return any(str(d).strip() for d in desc)
        return bool(str(desc).strip())

    valid_vulns = []
    for v in vulnerabilities:
        if has_valid_description(v):
            valid_vulns.append(v)
        else:
            removed.append(v)

    # Mesclar duplicatas por nome (case-insensitive)
    name_to_group = {}
    for v in valid_vulns:
        name = str(v.get('Name', '')).strip().lower()
        if name not in name_to_group:
            name_to_group[name] = [v]
        else:
            name_to_group[name].append(v)

    final_vulns = []
    for group in name_to_group.values():
        if len(group) == 1:
            final_vulns.append(group[0])
        else:
            # Mesclar campos de lista
            merged_vuln = group[0].copy()
            for field in ['identification', 'http_info', 'references', 'description', 'detection_result', 'detection_method', 'product_detection_result', 'impact', 'solution', 'insight', 'log_method', 'cvss']:
                if field in merged_vuln and isinstance(merged_vuln[field], list):
                    merged_vuln[field] = list(merged_vuln[field])
            for v2 in group[1:]:
                for field in ['identification', 'http_info', 'references', 'description', 'detection_result', 'detection_method', 'product_detection_result', 'impact', 'solution', 'insight', 'log_method', 'cvss']:
                    if field in v2 and isinstance(v2[field], list):
                        for item in v2[field]:
                            if item not in merged_vuln[field]:
                                merged_vuln[field].append(item)
            final_vulns.append(merged_vuln)
            merged.append(group)
    return final_vulns, removed, merged
"""
Processamento de chunks e vulnerabilidades.
Contém lógica de tokenização, splitting, retry e consolidação.
"""

import unicodedata
from typing import List, Dict, Any
from .chunking import validate_base_instances_pairs


def normalize_ligatures(text: str) -> str:
    """
    Normaliza ligaduras tipográficas em caracteres separados.
    
    PDFs frequentemente usam ligaduras (ﬁ, ﬂ, etc.) que são caracteres únicos.
    NFKC decompõe essas ligaduras em caracteres separados:
    - ﬁ (U+FB01) → fi
    - ﬂ (U+FB02) → fl
    - ﬀ (U+FB00) → ff
    - ﬃ (U+FB03) → ffi
    - ﬄ (U+FB04) → ffl
    """
    if not text:
        return text
    return unicodedata.normalize('NFKC', text)


def sanitize_unicode_text(text: str) -> str:
    """
    Remove/substitui caracteres Unicode problemáticos que não podem ser codificados no Windows.
    
    Mantém texto legível mas remove símbolos especiais que causam UnicodeEncodeError.
    """
    if not text:
        return text
    
    # PRIMEIRO: Normaliza ligaduras (ﬁ → fi, ﬂ → fl, etc.)
    result = normalize_ligatures(text)
    
    # Substituições comuns de caracteres problemáticos
    replacements = {
        '\u2717': '[X]',          # ✗ (checkmark)
        '\u2713': '[V]',          # ✓ (checkmark)
        '\u2022': '*',            # • (bullet)
        '\u00b7': '*',            # · (middle dot)
        '\u2023': '→',            # ‣ (triangular bullet)
        '\u2010': '-',            # ‐ (hyphen)
        '\u2011': '-',            # ‑ (non-breaking hyphen)
        '\u2012': '-',            # ‒ (figure dash)
        '\u2013': '-',            # – (en dash)
        '\u2014': '-',            # — (em dash)
        '\u2015': '-',            # ― (horizontal bar)
        '\u2018': "'",            # ' (left single quote)
        '\u2019': "'",            # ' (right single quote)
        '\u201c': '"',            # " (left double quote)
        '\u201d': '"',            # " (right double quote)
    }
    
    for problematic, replacement in replacements.items():
        result = result.replace(problematic, replacement)
    
    # Remove caracteres de controle e outros problemáticos
    # Mantém letras, números, pontuação básica e espaços
    clean_chars = []
    for char in result:
        try:
            # Tenta encodar em UTF-8 e depois em ASCII
            char.encode('ascii', 'strict')
            clean_chars.append(char)
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Se não consegue ASCII, tenta uma abordagem mais suave
            category = unicodedata.category(char)
            # Mantém letras (L*), números (N*), espaço (Zs)
            if category[0] in ['L', 'N'] or char.isspace() or char in ',.!?;:-':
                clean_chars.append(char)
            # Caso contrário, ignora
    
    return ''.join(clean_chars)




def get_consolidation_field(vulnerabilities: List[Dict], profile_config: Dict[str, Any] = None) -> str:
    """
    Detecta qual campo usar para consolidação.
    
    Prioridade:
    1. Campo configurado no profile (consolidation_field)
    2. Detecção automática baseada nos dados
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        profile_config: Configuração do perfil (opcional)
    
    Returns:
        Nome do campo a usar para consolidação
    """
    # Prioridade 1: Usar campo do profile se configurado
    if profile_config and 'consolidation_field' in profile_config:
        configured_field = profile_config.get('consolidation_field')
        # Verificar se o campo existe nos dados
        if vulnerabilities and any(
            configured_field in v for v in vulnerabilities if isinstance(v, dict)
        ):
            return configured_field
    
    if not vulnerabilities:
        return 'Name'
    
    # Prioridade 2: Detecção automática
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        
        # Prioridade: name_consolidated → definition.name → Name
        if 'name_consolidated' in vuln:
            return 'name_consolidated'
        if 'definition.name' in vuln:
            return 'definition.name'
        if 'Name' in vuln:
            return 'Name'
    
    # Fallback
    return 'Name'


def consolidate_duplicates(vulnerabilities: List[Dict], profile_config: Dict = None) -> List[Dict]:
    """
    Consolida vulnerabilidades removendo duplicatas E mesclando URLs.
    Remove entradas incompletas (BASE sem INSTANCES ou vice-versa).
    
    Para Tenable WAS:
    - Se mesma vulnerability (mesmo Name) aparece múltiplas vezes
    - Mescla os arrays de identification (combina URLs únicas)
    - Mantém apenas 1 entrada por vulnerability com TODAS as URLs
    - Remove pares incompletos
    - Se merge_instances_with_same_base=True: consolida instances com mesmo base name

    Para OpenVAS:
    - Consolida por (Name, port, protocol)
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        profile_config: Configuração do perfil
    
    Returns:
        Lista consolidada com URLs mescladas (apenas pares válidos)
    """
    if not vulnerabilities:
        return []

    # Usar nova estratégia de consolidação por scanner
    from .scanner_strategies import consolidate_by_scanner
    

    # PROPAGAÇÃO DE CONTEXTO PARA OPENVAS
    # Se for OpenVAS, propagar port/protocol do último cabeçalho válido para todas as vulnerabilidades até o próximo cabeçalho
    if profile_config and profile_config.get('reader', '').lower() == 'openvas':
        last_port = None
        last_protocol = None
        for vuln in vulnerabilities:
            port = vuln.get('port')
            protocol = vuln.get('protocol')
            # Se port/protocol presentes, atualiza contexto
            if port is not None:
                last_port = port
            if protocol is not None:
                last_protocol = protocol
            # Se ausente, propaga do último válido
            if port is None and last_port is not None:
                vuln['port'] = last_port
            if protocol is None and last_protocol is not None:
                vuln['protocol'] = last_protocol
            # Se encontrar um novo bloco/cabeçalho (ex: Name muda drasticamente), pode resetar contexto se necessário

    from .scanner_strategies import merge_duplicates_by_name
    try:
        # Mesclar por nome (100% igual) para qualquer scanner
        return merge_duplicates_by_name(vulnerabilities)
    except Exception as e:
        print(f"[CONSOLIDATE] Erro na consolidação por nome: {str(e)}")
        return _consolidate_duplicates_legacy(vulnerabilities)


def _consolidate_duplicates_legacy(vulnerabilities: List[Dict]) -> List[Dict]:
    """Método legado de consolidação para fallback."""
    if not vulnerabilities:
        return []
    
    # Primeiro, validar pares BASE+INSTANCES para Tenable WAS
    source = None
    for vuln in vulnerabilities:
        if isinstance(vuln, dict) and vuln.get('source'):
            source = vuln.get('source', 'UNKNOWN')
            break
    
    if source == 'TENABLEWAS':
        # Validar pares antes de consolidar
        vulnerabilities = validate_base_instances_pairs(vulnerabilities)
    
    # Detectar fonte
    if source == 'TENABLEWAS':
        # Para Tenable WAS: agrupar por Name e mesclar URLs
        consolidated = {}
        
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            
            name = vuln.get('Name', 'UNKNOWN')
            
            if name not in consolidated:
                # Primeira ocorrência - copiar tudo
                consolidated[name] = {
                    'Name': vuln.get('Name'),
                    'description': vuln.get('description', []),
                    'detection_result': vuln.get('detection_result', []),
                    'detection_method': vuln.get('detection_method', []),
                    'product_detection_result': vuln.get('product_detection_result', []),
                    'impact': vuln.get('impact', []),
                    'solution': vuln.get('solution', []),
                    'insight': vuln.get('insight', []),
                    'log_method': vuln.get('log_method', []),
                    'cvss': vuln.get('cvss', []),
                    'port': vuln.get('port'),
                    'protocol': vuln.get('protocol'),
                    'severity': vuln.get('severity'),
                    'references': vuln.get('references', []),
                    'plugin': vuln.get('plugin', []),
                    'identification': list(vuln.get('identification', [])),  # Cópia da lista
                    'http_info': vuln.get('http_info', []),
                    'source': vuln.get('source')
                }
            else:
                # Duplicata encontrada - MESCLAR URLs e HTTP Info
                new_urls = vuln.get('identification', [])
                existing_urls = consolidated[name].get('identification', [])
                
                # Mesclar URLs mantendo ordem e evitando duplicatas
                for url in new_urls:
                    if url and url not in existing_urls:
                        existing_urls.append(url)
                
                consolidated[name]['identification'] = existing_urls
                
                # Mesclar HTTP Info entries
                new_http_info = vuln.get('http_info', [])
                existing_http_info = consolidated[name].get('http_info', [])
                
                if new_http_info and isinstance(new_http_info, list):
                    for http_entry in new_http_info:
                        if http_entry and http_entry not in existing_http_info:
                            existing_http_info.append(http_entry)
                
                consolidated[name]['http_info'] = existing_http_info
        
        return list(consolidated.values())
    
    else:
        # OpenVAS: consolidar por (Name, port, protocol)
        consolidated = {}
        
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            
            name = vuln.get('Name', 'UNKNOWN')
            port = vuln.get('port', 'NO_PORT')
            protocol = vuln.get('protocol', '')
            key = (name, port, protocol)
            
            if key not in consolidated:
                consolidated[key] = vuln
        
        return list(consolidated.values())


