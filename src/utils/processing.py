"""
Processamento de chunks e vulnerabilidades.
Contém lógica de tokenização, splitting, retry e consolidação.
"""

import json
import re
import tiktoken
import unicodedata
from collections import defaultdict
from typing import List, Dict, Any, Optional

from utils.utils import parse_json_response, load_prompt


def sanitize_unicode_text(text: str) -> str:
    """
    Remove/substitui caracteres Unicode problemáticos que não podem ser codificados no Windows.
    
    Mantém texto legível mas remove símbolos especiais que causam UnicodeEncodeError.
    """
    if not text:
        return text
    
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
    
    result = text
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


def is_cais_profile(profile_config: Dict[str, Any]) -> bool:
    """Check if profile is CAIS-based."""
    if not profile_config:
        return False
    prompt_template = profile_config.get('prompt_template', '').lower()
    return 'cais' in prompt_template


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


class TokenChunk:
    """Wrapper simples para chunk de texto com conteúdo."""
    def __init__(self, page_content: str):
        self.page_content = page_content


def get_token_based_chunks(text: str, max_tokens: int, reserve_for_response: int = 1000, 
                          llm_config: dict = None, profile_config: dict = None) -> List[TokenChunk]:
    """
    Divide texto em chunks baseado em tokens com configurações customizáveis por scanner.
    
    Args:
        text: Texto a dividir
        max_tokens: Max tokens do modelo
        reserve_for_response: Tokens reservados para resposta (padrão: 1000)
        llm_config: Configuração do LLM com parâmetros específicos
        profile_config: Configuração do perfil/scanner com configurações de chunking
    
    Returns:
        Lista de TokenChunk com conteúdo dividido
    """
    # Garantir que max_tokens não é None
    if max_tokens is None:
        max_tokens = 4096
    
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    # CÁLCULO SIMPLIFICADO - Usar configuração do LLM se disponível
    if llm_config and 'max_chunk_size' in llm_config:
        available_for_content = llm_config['max_chunk_size']
        reserve_for_response = llm_config.get('reserve_for_response', reserve_for_response)
    else:
        # Fallback simples
        available_for_content = max(600, max_tokens - 1200 - reserve_for_response)
    
    print(f"[CHUNKING] Max tokens: {max_tokens}, Chunk size: {available_for_content}")
    
    # Detectar padrão do scanner com configurações customizáveis
    pattern_info = detect_scanner_pattern(text, profile_config)
    scanner_type = pattern_info.get('scanner_type', 'unknown').upper()
    using_custom = 'CUSTOM' if profile_config and 'chunking' in profile_config else 'AUTO'
    print(f"[SCANNER] {scanner_type} ({using_custom})")

    # Dividir por blocos de vulnerabilidades - VERSÃO CUSTOMIZÁVEL
    lines = text.split('\n')
    chunks = []
    current_chunk = []
    current_tokens = 0
    
    # CONFIGURAÇÕES PERSONALIZÁVEIS POR SCANNER
    min_chunk_tokens = pattern_info.get('min_chunk_tokens', 1000)
    force_break_at_markers = pattern_info.get('force_break_at_markers', True)
    max_vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)
    marker_pattern = pattern_info.get('marker_pattern')
    
    # Limite absoluto de tokens por chunk
    max_absolute_limit = available_for_content * 0.9  # 90% do limite para segurança
    
    print(f"[CONFIG] Min: {min_chunk_tokens}, Max vulns: {max_vulns_per_chunk}, Force break: {force_break_at_markers}")

    # Contador de vulnerabilidades no chunk atual
    current_vulns_count = 0
    
    for line in lines:
        line_tokens = len(tokenizer.encode(line))
        
        # DETECÇÃO DE MARCADORES CUSTOMIZÁVEL
        is_vuln_start = False
        if marker_pattern:
            is_vuln_start = bool(re.search(marker_pattern, line))
        
        # ESTRATÉGIA CUSTOMIZÁVEL: Usar configurações do scanner
        should_break = False
        
        if is_vuln_start and current_chunk:
            current_vulns_count += 1
            
            # Quebrar se:
            # 1. Force break está ativado E chunk tem conteúdo mínimo, OU
            # 2. Excedeu máximo de vulnerabilidades por chunk, OU  
            # 3. Vai exceder limite de tokens
            should_break = (
                (force_break_at_markers and current_tokens >= min_chunk_tokens) or
                (current_vulns_count > max_vulns_per_chunk) or
                (current_tokens + line_tokens > max_absolute_limit)
            )
        
        if should_break:
            # Finalizar chunk atual ANTES do marcador
            chunk_text = '\n'.join(current_chunk)
            chunks.append(TokenChunk(chunk_text))
            current_chunk = [line]  # Começar novo chunk COM o marcador
            current_tokens = line_tokens
            current_vulns_count = 1  # Reset contador
        else:
            current_chunk.append(line)
            current_tokens += line_tokens
            
            # PROTEÇÃO: Se exceder limite absoluto, forçar quebra
            if current_tokens > max_absolute_limit:
                # Remover última linha para ficar dentro do limite
                if len(current_chunk) > 1:
                    current_chunk.pop()
                    current_tokens -= line_tokens
                
                chunk_text = '\n'.join(current_chunk)
                chunks.append(TokenChunk(chunk_text))
                current_chunk = [line]
                current_tokens = line_tokens
                current_vulns_count = 1 if is_vuln_start else 0
    
    if current_chunk:
        chunk_text = '\n'.join(current_chunk)
        chunks.append(TokenChunk(chunk_text))
    
    print(f"[RESULTADO] {len(chunks)} chunks criados")
    
    # VALIDAÇÃO PÓS-CRIAÇÃO: Verificar chunks grandes
    oversized_count = sum(1 for chunk in chunks 
                         if len(tokenizer.encode(chunk.page_content)) > available_for_content)
    
    if oversized_count > 0:
        print(f"[AVISO] {oversized_count} chunks excedem limite - ajustar configurações se necessário")
    
    return chunks


def validate_base_instances_pairs(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Valida/processa vulnerabilidades em pares BASE+INSTANCES.
    Muito TOLERANTE para evitar perder dados.
    
    Estratégia:
    1. Procura por pares BASE + INSTANCES
    2. Se não encontra par, mantém a entrada mesmo assim
    3. Objetivo: minimizar perda de dados
    
    Args:
        vulnerabilities: Lista de vulnerabilidades extraídas
    
    Returns:
        Lista com entradas válidas (priorizando manter dados)
    """
    if not vulnerabilities:
        return []
    
    # Se < 2 entradas, retorna como está
    if len(vulnerabilities) < 2:
        return [v for v in vulnerabilities if isinstance(v, dict) and v.get('Name')]
    
    validated = []
    i = 0
    
    while i < len(vulnerabilities):
        curr = vulnerabilities[i]
        
        # Verificar se há próximo item
        if i + 1 < len(vulnerabilities):
            next_v = vulnerabilities[i + 1]
            curr_name = curr.get('Name', '')
            next_name = next_v.get('Name', '')
            
            # Procurar "Instance" (genérico)
            is_curr_base = 'Instance' not in curr_name.lower()
            is_next_instances = 'Instance' in next_name.lower()
            
            if is_curr_base and is_next_instances:
                # Extrair nomes base para comparação
                import re
                base_curr = re.split(r'\s+Instance', curr_name, flags=re.IGNORECASE)[0].strip()
                base_next = re.split(r'\s+Instance', next_name, flags=re.IGNORECASE)[0].strip()
                
                # Se nomes batem, é um par válido
                if base_curr.lower() == base_next.lower():
                    validated.append(curr)
                    validated.append(next_v)
                    i += 2
                    continue
        
        # Se não encontra par, mas tem dados úteis, mantém mesmo assim
        if isinstance(curr, dict) and curr.get('Name'):
            validated.append(curr)
        
        i += 1
    
    return validated


def build_prompt(doc_chunk: TokenChunk, profile_config: Dict[str, Any]) -> str:
    """
    Constrói o prompt para extração de vulnerabilidades.
    
    Args:
        doc_chunk: Chunk de documento
        profile_config: Configuração do perfil
    
    Returns:
        String com prompt completo
    """
    template_path = profile_config.get('prompt_template', '')
    prompt_template_content = load_prompt(template_path)
    
    # Sanitiza o conteúdo do chunk para evitar UnicodeEncodeError
    sanitized_content = sanitize_unicode_text(doc_chunk.page_content)
    
    prompt = (
        "Analyze this security report with preserved visual layout and extract vulnerabilities in JSON format:\n\n"
        f"REPORT CONTENT:\n{sanitized_content}\n\n"
        f"{prompt_template_content}"
    )
    
    return prompt


def detect_scanner_pattern(text: str, profile_config: dict = None) -> dict:
    """
    Detecta padrão de scanner baseado em markers no texto e configurações do perfil.
    
    Args:
        text: Texto para análise
        profile_config: Configuração do perfil/scanner (opcional)
    
    Returns:
        Dict com configurações de chunking específicas do scanner detectado
    """
    # Se perfil tem configurações de chunking, usar diretamente
    if profile_config and 'chunking' in profile_config:
        chunking_config = profile_config['chunking'].copy()
        
        # Validar se o padrão realmente existe no texto
        if chunking_config.get('marker_pattern'):
            matches = re.findall(chunking_config['marker_pattern'], text, re.MULTILINE)
            chunking_config['markers_found'] = len(matches)
            
            # Se encontrou marcadores, usar configuração do perfil
            if matches:
                return chunking_config
    
    # Fallback: Detectar automaticamente (comportamento anterior)
    # Detectar OpenVAS: começa com "NVT: "
    nvt_matches = re.findall(r'^\s*NVT:\s', text, re.MULTILINE)
    
    # Detectar Tenable WAS: padrão "VULNERABILITY CRITICAL/HIGH/MEDIUM/LOW PLUGIN ID XXXX"
    vuln_matches = re.findall(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+', text, re.MULTILINE)
    
    if nvt_matches:
        return {
            'scanner_type': 'openvas',
            'marker_pattern': r'^\s*NVT:\s',
            'has_pairs': False,
            'markers_found': len(nvt_matches),
            'min_chunk_tokens': 800,
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 5
        }
    elif vuln_matches:
        return {
            'scanner_type': 'tenable_was',
            'marker_pattern': r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+',
            'has_pairs': True,
            'markers_found': len(vuln_matches),
            'min_chunk_tokens': 1000,
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 3
        }
    else:
        return {
            'scanner_type': 'generic',
            'marker_pattern': None,
            'has_pairs': False,
            'markers_found': 0,
            'min_chunk_tokens': 1000,
            'force_break_at_markers': False,
            'max_vulnerabilities_per_chunk': 4
        }


def register_scanner_pattern(scanner_name: str, marker_pattern: str, has_pairs: bool = False):
    r"""
    Função helper para registrar novos padrões de scanner (extensível para futuros scanners).
    
    Uso:
        register_scanner_pattern('nessus', r'^\s*Nessus Plugin:\s', has_pairs=False)
        register_scanner_pattern('custom_tool', r'^\s*ISSUE:\s', has_pairs=False)
    
    Args:
        scanner_name: Nome do scanner (ex: 'nessus', 'qualys', etc)
        marker_pattern: Regex para detectar blocos
        has_pairs: Se True, mantém pares completos ao subdividir
    """
    # Nota: Esta função é um placeholder para futura extensibilidade
    # Atualmente, os padrões estão hardcoded em detect_scanner_pattern()
    # Para adicionar novo scanner:
    # 1. Adicionar detecção em detect_scanner_pattern()
    # 2. Exemplo:
    #    elif re.findall(marker_pattern, text):
    #        return {...}
    pass


def split_text_to_subchunks(text: str, target_size: int, profile_config: dict = None) -> List[str]:
    """
    Divide texto grande em subchunks menores - VERSÃO CUSTOMIZÁVEL.
    
    Args:
        text: Texto a dividir
        target_size: Tamanho alvo em caracteres
        profile_config: Configuração do perfil/scanner (opcional)
    
    Returns:
        Lista de subchunks otimizados baseados nas configurações do scanner
    """
    if len(text) <= target_size:
        return [text]
    
    lines = text.splitlines(keepends=True)
    if not lines:
        return [text]
    
    # OTIMIZAÇÃO: Usar configurações do scanner se disponível
    optimized_target = min(target_size, 8000)  # Máximo 8K chars por chunk
    
    # Detectar padrão com configurações customizáveis
    pattern_info = detect_scanner_pattern(text, profile_config)
    
    # Se não encontrou padrão, fazer divisão simples otimizada
    if pattern_info['marker_pattern'] is None:
        return _simple_split_by_size(text, optimized_target)
    
    # Encontrar índices de linhas com marcador detectado
    marker_lines = []
    for i, line in enumerate(lines):
        if re.search(pattern_info['marker_pattern'], line):
            marker_lines.append(i)
    
    # Se não encontrou marcadores mesmo após detecção, fallback
    if not marker_lines:
        return _simple_split_by_size(text, optimized_target)
    
    subchunks = []
    current_lines = []
    current_size = 0
    
    # NOVA ESTRATÉGIA CUSTOMIZÁVEL: Usar configurações do scanner
    vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)
    if pattern_info.get('has_pairs'):
        vulns_per_chunk = max(2, vulns_per_chunk // 2)  # Reduzir para pares
    
    i = 0
    while i < len(marker_lines):
        # Determinar quantas vulns incluir neste chunk
        vulns_in_chunk = 0
        chunk_lines = []
        chunk_size = 0
        
        while i < len(marker_lines) and vulns_in_chunk < vulns_per_chunk:
            # Determinar fim do bloco atual
            block_start = marker_lines[i]
            block_end = marker_lines[i + 1] if i + 1 < len(marker_lines) else len(lines)
            
            block_lines = lines[block_start:block_end]
            block_text = ''.join(block_lines)
            block_size = len(block_text)
            
            # Se adicionar este bloco excede target otimizado E já temos pelo menos 1 vuln
            if vulns_in_chunk > 0 and (chunk_size + block_size > optimized_target):
                break
            
            # Se bloco sozinho é maior que target, dividir internamente
            if block_size > optimized_target:
                # Salvar chunk atual se não vazio
                if chunk_lines:
                    subchunks.append(''.join(chunk_lines))
                
                # Dividir o bloco grande
                sub_blocks = _split_block_by_size(block_text, optimized_target)
                subchunks.extend(sub_blocks)
                
                # Resetar para próximo chunk
                chunk_lines = []
                chunk_size = 0
                vulns_in_chunk = 0
            else:
                # Adicionar bloco ao chunk atual
                chunk_lines.extend(block_lines)
                chunk_size += block_size
                vulns_in_chunk += 1
            
            i += 1
        
        # Salvar chunk se não vazio
        if chunk_lines:
            subchunks.append(''.join(chunk_lines))
    
    return subchunks if subchunks else [text]


def _split_block_by_size(text: str, target_size: int) -> List[str]:
    """
    Divide um bloco de texto em subchunks.
    Estratégia melhorada: Evita recursão infinita com limite de profundidade.
    
    Usado quando um bloco individual é maior que target_size.
    """
    if len(text) <= target_size:
        return [text]
    
    # Proteção contra recursão infinita
    if target_size < 1000:  # Mínimo absoluto
        # Se target_size muito pequeno, forçar divisão simples
        chunks = []
        for i in range(0, len(text), 1000):
            chunks.append(text[i:i+1000])
        return chunks
    
    subchunks = []
    lines = text.splitlines(keepends=True)
    current = []
    current_len = 0
    
    # Usar target_size direto ao invés de metade (evita recursão excessiva)
    for line in lines:
        line_len = len(line)
        
        # Se adicionando esta linha excede target_size, salvar chunk atual
        if current and (current_len + line_len > target_size):
            subchunks.append(''.join(current))
            current = []
            current_len = 0
        
        current.append(line)
        current_len += line_len
    
    if current:
        subchunks.append(''.join(current))
    
    # EVITAR RECURSÃO - se resultado ainda tem chunks grandes, aceitar como está
    # Melhor ter chunks grandes que loop infinito
    return subchunks if subchunks else [text]


def _simple_split_by_size(text: str, target_size: int) -> List[str]:
    """
    Divisão simples por tamanho quando não há VULNERABILITY markers.
    """
    if len(text) <= target_size:
        return [text]
    
    subchunks = []
    lines = text.splitlines(keepends=True)
    current = []
    current_len = 0
    
    for line in lines:
        line_len = len(line)
        
        if current and (current_len + line_len > target_size):
            subchunks.append(''.join(current))
            current = []
            current_len = 0
        
        current.append(line)
        current_len += line_len
    
    if current:
        subchunks.append(''.join(current))
    
    return subchunks if subchunks else [text]


def validate_json_and_tokens(response: str, chunk_content: str, max_tokens: int, prompt_template: str = "") -> Dict[str, Any]:
    """
    Valida resposta JSON e verifica limites de tokens.
    
    Args:
        response: Resposta da LLM
        chunk_content: Conteúdo do chunk
        max_tokens: Máximo de tokens permitido
        prompt_template: Template do prompt usado
    
    Returns:
        Dict com resultado da validação: {
            'json_valid': bool,
            'json_data': list/None,
            'token_valid': bool,
            'token_count': int,
            'errors': list,
            'needs_redivision': bool
        }
    """
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    result = {
        'json_valid': False,
        'json_data': None,
        'token_valid': True,
        'token_count': 0,
        'errors': [],
        'needs_redivision': False
    }
    
    # 1. VALIDAÇÃO DE JSON
    try:
        # Tentar extrair JSON da resposta
        json_data = parse_json_response(response)
        if json_data and isinstance(json_data, list):
            result['json_valid'] = True
            result['json_data'] = json_data
        else:
            result['errors'].append("JSON inválido ou não é uma lista")
    except Exception as e:
        result['errors'].append(f"Erro ao fazer parse do JSON: {str(e)}")
    
    # 2. VALIDAÇÃO DE TOKENS
    # Calcular tokens do prompt completo (template + chunk + overhead)
    prompt_tokens = len(tokenizer.encode(prompt_template)) if prompt_template else 800
    chunk_tokens = len(tokenizer.encode(chunk_content))
    response_tokens = len(tokenizer.encode(response))
    total_tokens = prompt_tokens + chunk_tokens + response_tokens
    
    result['token_count'] = total_tokens
    
    # Verificar se excede limite (deixar margem de 500 tokens)
    if total_tokens > (max_tokens - 500):
        result['token_valid'] = False
        result['errors'].append(f"Excede limite de tokens: {total_tokens}/{max_tokens}")
        result['needs_redivision'] = True
    
    # 3. DETECTAR NECESSIDADE DE REDIVISIÃO
    # Se JSON inválido OU excede tokens OU chunk muito grande
    if not result['json_valid'] or not result['token_valid'] or chunk_tokens > (max_tokens * 0.6):
        result['needs_redivision'] = True
    
    # 4. ANÁLISE ESPECÍFICA DE ERROS JSON
    if not result['json_valid']:
        if "..." in response or "truncated" in response.lower():
            result['errors'].append("Resposta truncada detectada")
        if response.count('[') != response.count(']'):
            result['errors'].append("JSON mal formado - colchetes desbalanceados")
        if response.count('{') != response.count('}'):
            result['errors'].append("JSON mal formado - chaves desbalanceadas")
    
    return result


def intelligent_chunk_redivision(chunk_content: str, max_tokens: int, error_context: Dict[str, Any]) -> List[str]:
    """
    Redivide chunk de forma inteligente baseado no tipo de erro detectado.
    
    Args:
        chunk_content: Conteúdo do chunk problemático
        max_tokens: Máximo de tokens permitido
        error_context: Contexto do erro da validação
    
    Returns:
        Lista de novos chunks menores
    """
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    # Calcular target size mais conservador baseado no erro
    base_target = max_tokens - 2000  # Margem maior para prompt + resposta
    chars_per_token = len(chunk_content) / len(tokenizer.encode(chunk_content))
    target_chars = int(base_target * chars_per_token * 0.7)  # 70% de segurança
    
    print(f"[REDIVISION] Erro detectado, redividindo chunk de {len(chunk_content)} chars")
    print(f"[REDIVISION] Target conservador: {target_chars} chars (~{base_target} tokens)")
    print(f"[REDIVISION] Erros: {error_context.get('errors', [])}")
    
    # ESTRATÉGIA 1: Se erro de tokens, dividir em partes menores
    if not error_context.get('token_valid', True):
        # Dividir em 3 partes para garantir que caiba
        target_chars = min(target_chars, len(chunk_content) // 3)
        print(f"[REDIVISION] Erro de tokens - usando target muito conservador: {target_chars} chars")
    
    # ESTRATÉGIA 2: Se JSON mal formado, tentar divisores diferentes
    if "JSON mal formado" in str(error_context.get('errors', [])):
        print(f"[REDIVISION] JSON mal formado - forçando divisão por vulnerabilidades")
        # Forçar divisão bem pequena para evitar JSON quebrado
        target_chars = min(target_chars, len(chunk_content) // 4)
    
    # ESTRATÉGIA 3: Se resposta truncada, dividir muito conservadoramente
    if "truncada" in str(error_context.get('errors', [])):
        print(f"[REDIVISION] Resposta truncada - divisão máxima")
        target_chars = min(target_chars, len(chunk_content) // 5)
    
    # Usar sistema de divisão otimizado
    new_chunks = split_text_to_subchunks(chunk_content, target_chars)
    
    print(f"[REDIVISION] Chunk original dividido em {len(new_chunks)} novos chunks")
    
    # VALIDAÇÃO DOS NOVOS CHUNKS
    validated_chunks = []
    for i, chunk in enumerate(new_chunks):
        chunk_tokens = len(tokenizer.encode(chunk))
        if chunk_tokens > base_target:
            print(f"[REDIVISION WARNING] Chunk {i+1} ainda grande ({chunk_tokens} tokens), forçando divisão")
            # Se ainda está grande, forçar divisão simples
            simple_chunks = _simple_split_by_size(chunk, target_chars // 2)
            validated_chunks.extend(simple_chunks)
        else:
            validated_chunks.append(chunk)
    
    print(f"[REDIVISION] Validação final: {len(validated_chunks)} chunks seguros")
    return validated_chunks


def robust_chunk_processing(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                           max_retries: int = 3) -> List[Dict]:
    """
    Processamento robusto de chunk com recuperação automática de erros.
    
    Fluxo:
    1. Tentar processar chunk normal
    2. Se erro JSON/tokens -> validar e diagnosticar
    3. Se necessário -> redividir inteligentemente
    4. Reprocessar chunks menores
    5. Consolidar resultados
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_retries: Máximo de tentativas
    
    Returns:
        Lista de vulnerabilidades extraídas com validação
    """
    max_tokens = getattr(llm, 'max_tokens', 4096) or 4096
    all_vulnerabilities = []
    
    try:
        # TENTATIVA 1: Processamento normal
        prompt = build_prompt(doc_chunk, profile_config)
        print(f"[ROBUST] Tentativa 1 - chunk normal ({len(doc_chunk.page_content)} chars)")
        
        response = llm.invoke(prompt).content
        
        # VALIDAÇÃO COMPLETA
        validation = validate_json_and_tokens(response, doc_chunk.page_content, max_tokens, prompt)
        
        if validation['json_valid'] and validation['token_valid']:
            print(f"[ROBUST] ✅ Sucesso normal - {len(validation['json_data'])} vulnerabilidades")
            return validation['json_data']
        
        # DIAGNÓSTICO DO PROBLEMA
        print(f"[ROBUST] ⚠️ Problemas detectados: {validation['errors']}")
        
        if not validation['needs_redivision']:
            # Se JSON inválido mas não precisa redividir, tentar retry simples
            print(f"[ROBUST] Tentando retry simples...")
            for retry in range(2):
                response = llm.invoke(prompt).content
                validation = validate_json_and_tokens(response, doc_chunk.page_content, max_tokens, prompt)
                if validation['json_valid']:
                    print(f"[ROBUST] ✅ Sucesso no retry {retry+1}")
                    return validation['json_data']
        
        # REDIVISIÃO INTELIGENTE
        print(f"[ROBUST] 🔄 Redividindo chunk inteligentemente...")
        new_chunks = intelligent_chunk_redivision(doc_chunk.page_content, max_tokens, validation)
        
        # PROCESSAMENTO DOS NOVOS CHUNKS
        for i, chunk_content in enumerate(new_chunks):
            sub_chunk = TokenChunk(chunk_content)
            sub_prompt = build_prompt(sub_chunk, profile_config)
            
            print(f"[ROBUST] Processando subchunk {i+1}/{len(new_chunks)} ({len(chunk_content)} chars)")
            
            try:
                sub_response = llm.invoke(sub_prompt).content
                sub_validation = validate_json_and_tokens(sub_response, chunk_content, max_tokens, sub_prompt)
                
                if sub_validation['json_valid']:
                    all_vulnerabilities.extend(sub_validation['json_data'])
                    print(f"[ROBUST] ✅ Subchunk {i+1} - {len(sub_validation['json_data'])} vulns")
                else:
                    print(f"[ROBUST] ❌ Subchunk {i+1} falhou: {sub_validation['errors']}")
                    
            except Exception as e:
                print(f"[ROBUST] ❌ Erro no subchunk {i+1}: {str(e)[:100]}")
                continue
        
        print(f"[ROBUST] 🏁 Processamento robusto finalizado: {len(all_vulnerabilities)} vulnerabilidades totais")
        return all_vulnerabilities
        
    except Exception as e:
        print(f"[ROBUST] 💥 Erro crítico no processamento robusto: {str(e)}")
        return []
    """
    Processa chunk grande dividindo em subchunks quando há erro.
    Valida que cada subchunk retorna pares BASE+INSTANCES completos.
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_subchunk_chars: Tamanho máximo de subchunk em caracteres
    
    Returns:
        Lista de vulnerabilidades extraídas (apenas pares completos)
    """
    sub_vulns = []
    sub_texts = split_text_to_subchunks(doc_chunk.page_content, max_subchunk_chars)
    print(f"[FALLBACK] Dividindo chunk em {len(sub_texts)} subchunks de ~{max_subchunk_chars} caracteres...")
    
    for idx, sub_text in enumerate(sub_texts, start=1):
        sub_chunk = TokenChunk(sub_text)
        prompt = build_prompt(sub_chunk, profile_config)
        print(f"[FALLBACK] Processando subchunk {idx}/{len(sub_texts)} (tamanho: {len(sub_text)} chars)...")
        
        try:
            print(f"[FALLBACK] → Enviando subchunk {idx} para LLM...")
            resposta = llm.invoke(prompt).content
            print(f"[FALLBACK] ← Resposta recebida do LLM para subchunk {idx}")
            
            parsed = parse_json_response(resposta, f" subchunk {idx}")
            
            if parsed and isinstance(parsed, list):
                # VALIDAR: apenas manter pares completos BASE+INSTANCES
                validated = validate_base_instances_pairs(parsed)
                sub_vulns.extend(validated)
                
                if len(validated) < len(parsed):
                    print(f"[FALLBACK] ✓ Subchunk {idx}: {len(parsed)} vulnerabilidades → {len(validated)} (pares válidos)")
                else:
                    print(f"[FALLBACK] ✓ Subchunk {idx}: {len(parsed)} vulnerabilidades extraídas (todos pares válidos)")
            else:
                print(f"[FALLBACK] ✗ Subchunk {idx} não retornou lista JSON válida.")
        except Exception as e:
            print(f"[FALLBACK] ✗ Erro ao processar subchunk {idx}: {e}")
    
    print(f"[FALLBACK] Processamento completo: {len(sub_vulns)} vulnerabilidades totais extraídas (validadas)")
    return sub_vulns


def retry_chunk_with_subdivision(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                                max_retries: int = 3) -> List[Dict]:
    """
    Processa chunk com retry automático e subdivisão progressiva JUSTA e EXTENSÍVEL.
    
    Estratégia:
    1. Detecta tipo de scanner (OpenVAS, Tenable WAS, etc) automaticamente
    2. Tentativa 1: Chunk completo
    3. Tentativa 2+: Subdivide progressivamente respeitando padrão detectado
    4. Para Tenable WAS: mantém pares BASE+INSTANCES completos
    5. Para OpenVAS: divide simplesmente por tamanho
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_retries: Máximo de tentativas (padrão: 3)
    
    Returns:
        Lista de vulnerabilidades extraídas (validadas conforme padrão)
    """
    retry_count = 0
    subchunk_size = 4000  # Tamanho inicial para subdivisões
    
    # Detectar scanner no início
    pattern_info = detect_scanner_pattern(doc_chunk.page_content)
    print(f"[SCANNER] Detectado: {pattern_info['scanner_type'].upper()} ({pattern_info['markers_found']} blocos)")
    
    while retry_count <= max_retries:
        try:
            if retry_count == 0:
                # TENTATIVA 1: Processar chunk completo
                print(f"[ATTEMPT {retry_count+1}/{max_retries+1}] Processando chunk completo ({len(doc_chunk.page_content)} chars)...")
                prompt = build_prompt(doc_chunk, profile_config)
                resposta = llm.invoke(prompt).content
                
                try:
                    vulnerabilities = json.loads(resposta)
                    if isinstance(vulnerabilities, list) and vulnerabilities:
                        # Validar conforme tipo de scanner
                        if pattern_info['has_pairs']:
                            # Tenable WAS: validar pares
                            validated = validate_base_instances_pairs(vulnerabilities)
                        else:
                            # OpenVAS/Generic: não validar pares, apenas manter
                            validated = vulnerabilities
                        
                        if validated:
                            print(f"[ATTEMPT {retry_count+1}] ✓ Sucesso: {len(validated)} vulnerabilidades extraídas")
                            return validated
                        else:
                            print(f"[ATTEMPT {retry_count+1}] ⚠ JSON válido mas 0 entradas válidas")
                except json.JSONDecodeError:
                    pass
                
                # Tentar parser alternativo
                vulnerabilities = parse_json_response(resposta, f" attempt {retry_count+1}")
                if vulnerabilities:
                    if pattern_info['has_pairs']:
                        validated = validate_base_instances_pairs(vulnerabilities)
                    else:
                        validated = vulnerabilities
                    
                    if validated:
                        print(f"[ATTEMPT {retry_count+1}] ✓ Sucesso (parser alt): {len(validated)} vulnerabilidades")
                        return validated
                
                print(f"[ATTEMPT {retry_count+1}] ✗ Falha no chunk completo - iniciando subdivisão")
            else:
                # TENTATIVA 2+: Subdividir pela METADE do chunk que entrou
                print(f"[ATTEMPT {retry_count+1}/{max_retries+1}] Erro lógico detectado - subdividindo chunk pela metade...")
                
                # Dividir pela metade do texto atual (não pelo subchunk_size dinâmico)
                text_half = len(doc_chunk.page_content) // 2
                
                # Usar a função de divisão para encontrar ponto de corte próximo à metade
                lines = doc_chunk.page_content.splitlines(keepends=True)
                current = []
                current_len = 0
                
                for line in lines:
                    line_len = len(line)
                    if current and current_len >= text_half:
                        break
                    current.append(line)
                    current_len += line_len
                
                first_half = ''.join(current)
                second_half = doc_chunk.page_content[current_len:]
                subchunks = [first_half, second_half] if second_half else [first_half]
                
                if len(subchunks) == 1:
                    # Não conseguiu dividir (texto é pequeno) - erro no LLM
                    print(f"[ATTEMPT {retry_count+1}] ✗ Impossível subdividir mais (texto muito pequeno)")
                    retry_count += 1
                    continue
                
                print(f"[ATTEMPT {retry_count+1}] Chunk dividido em 2 partes pela metade")
                all_vulnerabilities = []
                
                for idx, sub_text in enumerate(subchunks, start=1):
                    try:
                        print(f"  [Subchunk {idx}/2] Tamanho: {len(sub_text)} chars...")
                        sub_chunk = TokenChunk(sub_text)
                        prompt = build_prompt(sub_chunk, profile_config)
                        resposta = llm.invoke(prompt).content
                        
                        # Tentar parsing
                        try:
                            parsed = json.loads(resposta)
                        except json.JSONDecodeError:
                            parsed = parse_json_response(resposta, f" subchunk {idx}")
                        
                        if parsed and isinstance(parsed, list):
                            # Validar conforme tipo de scanner
                            if pattern_info['has_pairs']:
                                validated = validate_base_instances_pairs(parsed)
                            else:
                                validated = parsed
                            
                            if validated:
                                all_vulnerabilities.extend(validated)
                                print(f"  [Subchunk {idx}] ✓ {len(validated)} vulnerabilidades extraídas")
                            else:
                                print(f"  [Subchunk {idx}] ⚠ {len(parsed)} entradas mas 0 válidas")
                        else:
                            print(f"  [Subchunk {idx}] ✗ JSON inválido")
                    except Exception as e:
                        print(f"  [Subchunk {idx}] ✗ Erro: {str(e)[:100]}")
                        continue
                
                if all_vulnerabilities:
                    print(f"[ATTEMPT {retry_count+1}] ✓ Sucesso na subdivisão: {len(all_vulnerabilities)} vulnerabilidades")
                    return all_vulnerabilities
                else:
                    print(f"[ATTEMPT {retry_count+1}] ✗ Nenhuma vulnerabilidade válida em qualquer subchunk")
            
            # Preparar para próxima tentativa
            retry_count += 1
            if retry_count > max_retries:
                print(f"[ERRO] Máximo de {max_retries} tentativas excedidas - retornando lista vazia")
                return []
            
            # Reduzir tamanho para próxima subdivisão
            subchunk_size = max(1000, subchunk_size // 2)
            print(f"[INFO] Próxima tentativa com subchunks de {subchunk_size} chars\n")
            
        except Exception as e:
            error_msg = str(e).lower()
            
            # Erros críticos que não devem fazer retry
            if any(kw in error_msg for kw in ['quota', '429', 'rate limit', 'timeout', 'authentication']):
                print(f"[ERRO CRITICO] {type(e).__name__}: {str(e)[:100]}")
                raise e
            
            # Outros erros - fazer retry
            retry_count += 1
            if retry_count > max_retries:
                print(f"[ERRO] Máximo de tentativas excedidas após erro: {str(e)[:100]}")
                return []
            
            subchunk_size = max(1000, subchunk_size // 2)
            print(f"[RETRY] Erro {type(e).__name__} - tentando novamente com subchunks menores...\n")
    
    return []


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
    from utils.scanner_strategies import consolidate_by_scanner
    
    try:
        return consolidate_by_scanner(vulnerabilities, profile_config)
    except Exception as e:
        print(f"[CONSOLIDATE] Erro na nova consolidação, usando método fallback: {str(e)}")
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


# ============================================================================
# SISTEMA ROBUSTO DE RECUPERAÇÃO DE ERROS JSON E VALIDAÇÃO DE TOKENS
# ============================================================================

def validate_json_and_tokens(response: str, chunk_content: str, max_tokens: int, prompt_template: str = "") -> Dict[str, Any]:
    """
    Valida resposta JSON e verifica limites de tokens.
    
    Args:
        response: Resposta da LLM
        chunk_content: Conteúdo do chunk
        max_tokens: Máximo de tokens permitido
        prompt_template: Template do prompt usado
    
    Returns:
        Dict com resultado da validação: {
            'json_valid': bool,
            'json_data': list/None,
            'token_valid': bool,
            'token_count': int,
            'errors': list,
            'needs_redivision': bool
        }
    """
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    result = {
        'json_valid': False,
        'json_data': None,
        'token_valid': True,
        'token_count': 0,
        'errors': [],
        'needs_redivision': False
    }
    
    # 1. VALIDAÇÃO DE JSON
    try:
        # Tentar extrair JSON da resposta
        json_data = parse_json_response(response)
        if json_data and isinstance(json_data, list):
            result['json_valid'] = True
            result['json_data'] = json_data
        else:
            result['errors'].append("JSON inválido ou não é uma lista")
    except Exception as e:
        result['errors'].append(f"Erro ao fazer parse do JSON: {str(e)}")
    
    # 2. VALIDAÇÃO DE TOKENS
    # Calcular tokens do prompt completo (template + chunk + overhead)
    prompt_tokens = len(tokenizer.encode(prompt_template)) if prompt_template else 800
    chunk_tokens = len(tokenizer.encode(chunk_content))
    response_tokens = len(tokenizer.encode(response))
    total_tokens = prompt_tokens + chunk_tokens + response_tokens
    
    result['token_count'] = total_tokens
    
    # Verificar se excede limite (deixar margem de 500 tokens)
    if total_tokens > (max_tokens - 500):
        result['token_valid'] = False
        result['errors'].append(f"Excede limite de tokens: {total_tokens}/{max_tokens}")
        result['needs_redivision'] = True
    
    # 3. DETECTAR NECESSIDADE DE REDIVISÃO
    # Se JSON inválido OU excede tokens OU chunk muito grande
    if not result['json_valid'] or not result['token_valid'] or chunk_tokens > (max_tokens * 0.6):
        result['needs_redivision'] = True
    
    # 4. ANÁLISE ESPECÍFICA DE ERROS JSON
    if not result['json_valid']:
        if "..." in response or "truncated" in response.lower():
            result['errors'].append("Resposta truncada detectada")
        if response.count('[') != response.count(']'):
            result['errors'].append("JSON mal formado - colchetes desbalanceados")
        if response.count('{') != response.count('}'):
            result['errors'].append("JSON mal formado - chaves desbalanceadas")
    
    return result


def intelligent_chunk_redivision(chunk_content: str, max_tokens: int, error_context: Dict[str, Any]) -> List[str]:
    """
    Redivide chunk de forma inteligente baseado no tipo de erro detectado.
    
    Args:
        chunk_content: Conteúdo do chunk problemático
        max_tokens: Máximo de tokens permitido
        error_context: Contexto do erro da validação
    
    Returns:
        Lista de novos chunks menores
    """
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    # Calcular target size mais conservador baseado no erro
    base_target = max_tokens - 2000  # Margem maior para prompt + resposta
    chars_per_token = len(chunk_content) / len(tokenizer.encode(chunk_content))
    target_chars = int(base_target * chars_per_token * 0.7)  # 70% de segurança
    
    print(f"[REDIVISION] Erro detectado, redividindo chunk de {len(chunk_content)} chars")
    print(f"[REDIVISION] Target conservador: {target_chars} chars (~{base_target} tokens)")
    print(f"[REDIVISION] Erros: {error_context.get('errors', [])}")
    
    # ESTRATÉGIA 1: Se erro de tokens, dividir em partes menores
    if not error_context.get('token_valid', True):
        # Dividir em 3 partes para garantir que caiba
        target_chars = min(target_chars, len(chunk_content) // 3)
        print(f"[REDIVISION] Erro de tokens - usando target muito conservador: {target_chars} chars")
    
    # ESTRATÉGIA 2: Se JSON mal formado, tentar divisores diferentes
    if "JSON mal formado" in str(error_context.get('errors', [])):
        print(f"[REDIVISION] JSON mal formado - forçando divisão por vulnerabilidades")
        # Forçar divisão bem pequena para evitar JSON quebrado
        target_chars = min(target_chars, len(chunk_content) // 4)
    
    # ESTRATÉGIA 3: Se resposta truncada, dividir muito conservadoramente
    if "truncada" in str(error_context.get('errors', [])):
        print(f"[REDIVISION] Resposta truncada - divisão máxima")
        target_chars = min(target_chars, len(chunk_content) // 5)
    
    # Usar sistema de divisão otimizado
    new_chunks = split_text_to_subchunks(chunk_content, target_chars)
    
    print(f"[REDIVISION] Chunk original dividido em {len(new_chunks)} novos chunks")
    
    # VALIDAÇÃO DOS NOVOS CHUNKS
    validated_chunks = []
    for i, chunk in enumerate(new_chunks):
        chunk_tokens = len(tokenizer.encode(chunk))
        if chunk_tokens > base_target:
            print(f"[REDIVISION WARNING] Chunk {i+1} ainda grande ({chunk_tokens} tokens), forçando divisão")
            # Se ainda está grande, forçar divisão simples
            simple_chunks = _simple_split_by_size(chunk, target_chars // 2)
            validated_chunks.extend(simple_chunks)
        else:
            validated_chunks.append(chunk)
    
    print(f"[REDIVISION] Validação final: {len(validated_chunks)} chunks seguros")
    return validated_chunks


def robust_chunk_processing(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                           max_retries: int = 3) -> List[Dict]:
    """
    Processamento robusto de chunk com recuperação automática de erros.
    
    Fluxo:
    1. Tentar processar chunk normal
    2. Se erro JSON/tokens -> validar e diagnosticar
    3. Se necessário -> redividir inteligentemente
    4. Reprocessar chunks menores
    5. Consolidar resultados
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_retries: Máximo de tentativas
    
    Returns:
        Lista de vulnerabilidades extraídas com validação
    """
    max_tokens = getattr(llm, 'max_tokens', 4096) or 4096
    all_vulnerabilities = []
    
    try:
        # TENTATIVA 1: Processamento normal
        prompt = build_prompt(doc_chunk, profile_config)
        print(f"[ROBUST] Tentativa 1 - chunk normal ({len(doc_chunk.page_content)} chars)")
        
        response = llm.invoke(prompt).content
        
        # VALIDAÇÃO COMPLETA
        validation = validate_json_and_tokens(response, doc_chunk.page_content, max_tokens, prompt)
        
        if validation['json_valid'] and validation['token_valid']:
            print(f"[ROBUST] ✅ Sucesso normal - {len(validation['json_data'])} vulnerabilidades")
            return validation['json_data']
        
        # DIAGNÓSTICO DO PROBLEMA
        print(f"[ROBUST] ⚠️ Problemas detectados: {validation['errors']}")
        
        if not validation['needs_redivision']:
            # Se JSON inválido mas não precisa redividir, tentar retry simples
            print(f"[ROBUST] Tentando retry simples...")
            for retry in range(2):
                response = llm.invoke(prompt).content
                validation = validate_json_and_tokens(response, doc_chunk.page_content, max_tokens, prompt)
                if validation['json_valid']:
                    print(f"[ROBUST] ✅ Sucesso no retry {retry+1}")
                    return validation['json_data']
        
        # REDIVISÃO INTELIGENTE
        print(f"[ROBUST] 🔄 Redividindo chunk inteligentemente...")
        new_chunks = intelligent_chunk_redivision(doc_chunk.page_content, max_tokens, validation)
        
        # PROCESSAMENTO DOS NOVOS CHUNKS
        for i, chunk_content in enumerate(new_chunks):
            sub_chunk = TokenChunk(chunk_content)
            sub_prompt = build_prompt(sub_chunk, profile_config)
            
            print(f"[ROBUST] Processando subchunk {i+1}/{len(new_chunks)} ({len(chunk_content)} chars)")
            
            try:
                sub_response = llm.invoke(sub_prompt).content
                sub_validation = validate_json_and_tokens(sub_response, chunk_content, max_tokens, sub_prompt)
                
                if sub_validation['json_valid']:
                    all_vulnerabilities.extend(sub_validation['json_data'])
                    print(f"[ROBUST] ✅ Subchunk {i+1} - {len(sub_validation['json_data'])} vulns")
                else:
                    print(f"[ROBUST] ❌ Subchunk {i+1} falhou: {sub_validation['errors']}")
                    
            except Exception as e:
                print(f"[ROBUST] ❌ Erro no subchunk {i+1}: {str(e)[:100]}")
                continue
        
        print(f"[ROBUST] 🏁 Processamento robusto finalizado: {len(all_vulnerabilities)} vulnerabilidades totais")
        return all_vulnerabilities
        
    except Exception as e:
        print(f"[ROBUST] 💥 Erro crítico no processamento robusto: {str(e)}")
        return []


def retry_chunk_with_subdivision_robust(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                                       max_retries: int = 3) -> List[Dict]:
    """
    Processa chunk com retry automático e subdivisão inteligente.
    
    NOVA VERSÃO: Usa sistema robusto de validação e recuperação de erros.
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_retries: Máximo de tentativas (mantido por compatibilidade)
    
    Returns:
        Lista de vulnerabilidades extraídas com validação completa
    """
    # Detectar scanner no início para log
    pattern_info = detect_scanner_pattern(doc_chunk.page_content)
    print(f"[SCANNER] Detectado: {pattern_info['scanner_type'].upper()} ({pattern_info['markers_found']} blocos)")
    
    # Usar sistema robusto que inclui validação e recuperação
    vulnerabilities = robust_chunk_processing(doc_chunk, llm, profile_config, max_retries)
    
    # Validação final conforme tipo de scanner
    if vulnerabilities:
        if pattern_info['has_pairs']:
            # Tenable WAS: validar pares
            validated = validate_base_instances_pairs(vulnerabilities)
            if len(validated) != len(vulnerabilities):
                print(f"[VALIDATION] Pares validados: {len(vulnerabilities)} → {len(validated)}")
            return validated
        else:
            # OpenVAS: validação simples
            return vulnerabilities
    
    return []


# Alias para compatibilidade - usar sistema robusto como padrão
# retry_chunk_with_subdivision = retry_chunk_with_subdivision_robust

