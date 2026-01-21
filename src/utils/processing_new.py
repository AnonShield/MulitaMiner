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
            char.encode('ascii', 'strict')
            clean_chars.append(char)
        except (UnicodeEncodeError, UnicodeDecodeError):
            category = unicodedata.category(char)
            if category[0] in ['L', 'N'] or char.isspace() or char in ',.!?;:-':
                clean_chars.append(char)
    
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
    if profile_config and 'consolidation_field' in profile_config:
        configured_field = profile_config.get('consolidation_field')
        if vulnerabilities and any(
            configured_field in v for v in vulnerabilities if isinstance(v, dict)
        ):
            return configured_field
    
    if not vulnerabilities:
        return 'Name'
    
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        
        if 'name_consolidated' in vuln:
            return 'name_consolidated'
        if 'definition.name' in vuln:
            return 'definition.name'
        if 'Name' in vuln:
            return 'Name'
    
    return 'Name'


class TokenChunk:
    """Wrapper simples para chunk de texto com conteúdo."""
    def __init__(self, page_content: str):
        self.page_content = page_content

def get_token_based_chunks(text: str, max_tokens: int, llm_config: dict = None, profile_config: dict = None) -> List[TokenChunk]:
    """
    Divide texto em chunks baseado em tokens com configurações customizáveis por scanner.
    
    Args:
        text: Texto a dividir
        max_tokens: Max tokens do modelo
        llm_config: Configuração do LLM com parâmetros específicos
        profile_config: Configuração do perfil/scanner com configurações de chunking
    
    Returns:
        Lista de TokenChunk com conteúdo dividido
    """
    if max_tokens is None:
        max_tokens = 4096
    
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    if llm_config and 'max_chunk_size' in llm_config:
        available_for_content = llm_config['max_chunk_size']
    else:
        reserve_for_response = llm_config.get('reserve_for_response', 1000) if llm_config else 1000
        available_for_content = max(600, max_tokens - 1200 - reserve_for_response)
    
    print(f"[CHUNKING] Max tokens: {max_tokens}, Chunk size: {available_for_content}")
    
    max_absolute_limit = int(available_for_content * 0.9)
    print(f"[CONFIG] Max absolute limit for chunk content: {max_absolute_limit} tokens")
    
    pattern_info = detect_scanner_pattern(text, profile_config)
    scanner_type = pattern_info.get('scanner_type', 'unknown').upper()
    using_custom = 'CUSTOM' if profile_config and 'chunking' in profile_config else 'AUTO'
    print(f"[SCANNER] {scanner_type} ({using_custom})")

    chunks = _create_semantic_chunks(text, pattern_info, max_absolute_limit, tokenizer)
    
    print(f"[RESULTADO] {len(chunks)} chunks criados")
    
    oversized_count = sum(1 for chunk in chunks 
                         if len(tokenizer.encode(chunk.page_content)) > available_for_content)
    
    if oversized_count > 0:
        print(f"[AVISO] {oversized_count} chunks excedem limite - ajustar configurações se necessário")
    
    return chunks

def _create_semantic_chunks(text: str, pattern_info: dict, max_chunk_size: int, tokenizer) -> List[TokenChunk]:
    """
    Cria chunks semanticamente, dividindo o texto em blocos de vulnerabilidade completos
    e depois agrupando esses blocos em chunks que caibam no limite de tokens.

    Args:
        text (str): O texto completo do relatório.
        pattern_info (dict): A configuração do scanner, contendo o 'marker_pattern'.
        max_chunk_size (int): O tamanho máximo em tokens para cada chunk.
        tokenizer: O tokenizador a ser usado.

    Returns:
        List[TokenChunk]: Uma lista de chunks semanticamente divididos.
    """
    marker_pattern = pattern_info.get('marker_pattern')
    if not marker_pattern:
        return [TokenChunk(text)]

    blocks = re.split(f'({marker_pattern})', text, flags=re.MULTILINE)
    
    vulnerability_blocks_content = []
    current_block_part = ""

    for i, part in enumerate(blocks):
        if i == 0 and not part.strip():
            continue
        
        if re.match(marker_pattern, part, re.MULTILINE):
            if current_block_part.strip():
                vulnerability_blocks_content.append(current_block_part)
            current_block_part = part
        else:
            current_block_part += part

    if current_block_part.strip():
        vulnerability_blocks_content.append(current_block_part)

    if not vulnerability_blocks_content:
        return [TokenChunk(text)]

    processed_blocks = []
    for block_content in vulnerability_blocks_content:
        block_tokens = len(tokenizer.encode(block_content))
        
        if block_tokens > max_chunk_size:
            print(f"[AVISO CRÍTICO] Bloco de vulnerabilidade ({block_tokens} tokens) excede o limite de {max_chunk_size} tokens.")
            print(f"[AVISO CRÍTICO] Este bloco não pode ser processado pelo LLM sem modificação de conteúdo. Será enviado como está e provavelmente causará uma falha na API do LLM para este chunk.")
            # Pass the oversized block as is, as per "no modification" constraint.
            processed_blocks.append(block_content)
        else:
            processed_blocks.append(block_content)
            
    chunks = []
    current_chunk_content = ""
    current_chunk_tokens = 0

    for block_content in processed_blocks:
        block_tokens = len(tokenizer.encode(block_content))

        if current_chunk_tokens + block_tokens > max_chunk_size:
            chunks.append(TokenChunk(current_chunk_content))
            current_chunk_content = block_content
            current_chunk_tokens = block_tokens
        else:
            current_chunk_content += block_content
            current_chunk_tokens += block_tokens

    if current_chunk_content:
        chunks.append(TokenChunk(current_chunk_content))

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
    
    if len(vulnerabilities) < 2:
        return [v for v in vulnerabilities if isinstance(v, dict) and v.get('Name')]
    
    validated = []
    i = 0
    
    while i < len(vulnerabilities):
        curr = vulnerabilities[i]
        
        if i + 1 < len(vulnerabilities):
            next_v = vulnerabilities[i + 1]
            curr_name = curr.get('Name', '')
            next_name = next_v.get('Name', '')
            
            is_curr_base = 'Instance' not in curr_name.lower()
            is_next_instances = 'Instance' in next_name.lower()
            
            if is_curr_base and is_next_instances:
                import re
                base_curr = re.split(r'\s+Instance', curr_name, flags=re.IGNORECASE)[0].strip()
                base_next = re.split(r'\s+Instance', next_name, flags=re.IGNORECASE)[0].strip()
                
                if base_curr.lower() == base_next.lower():
                    validated.append(curr)
                    validated.append(next_v)
                    i += 2
                    continue
        
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
    if profile_config and 'chunking' in profile_config:
        chunking_config = profile_config['chunking'].copy()
        
        if chunking_config.get('marker_pattern'):
            matches = re.findall(chunking_config['marker_pattern'], text, re.MULTILINE)
            chunking_config['markers_found'] = len(matches)
            
            if matches:
                return chunking_config
    
    nvt_matches = re.findall(r'^\s*NVT:\s', text, re.MULTILINE)
    
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
    
    optimized_target = min(target_size, 8000)
    
    pattern_info = detect_scanner_pattern(text, profile_config)
    
    if pattern_info['marker_pattern'] is None:
        return _simple_split_by_size(text, optimized_target)
    
    marker_lines = []
    for i, line in enumerate(lines):
        if re.search(pattern_info['marker_pattern'], line):
            marker_lines.append(i)
    
    if not marker_lines:
        return _simple_split_by_size(text, optimized_target)
    
    subchunks = []
    current_lines = []
    current_size = 0
    
    vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)
    if pattern_info.get('has_pairs'):
        vulns_per_chunk = max(2, vulns_per_chunk // 2)
    
    i = 0
    while i < len(marker_lines):
        vulns_in_chunk = 0
        chunk_lines = []
        chunk_size = 0
        
        while i < len(marker_lines) and vulns_in_chunk < vulns_per_chunk:
            block_start = marker_lines[i]
            block_end = marker_lines[i + 1] if i + 1 < len(marker_lines) else len(lines)
            
            block_lines = lines[block_start:block_end]
            block_text = ''.join(block_lines)
            block_size = len(block_text)
            
            if vulns_in_chunk > 0 and (chunk_size + block_size > optimized_target):
                break
            
            if block_size > optimized_target:
                if chunk_lines:
                    subchunks.append(''.join(chunk_lines))
                
                sub_blocks = _split_block_by_size(block_text, optimized_target)
                subchunks.extend(sub_blocks)
                
                chunk_lines = []
                chunk_size = 0
                vulns_in_chunk = 0
            else:
                chunk_lines.extend(block_lines)
                chunk_size += block_size
                vulns_in_chunk += 1
            
            i += 1
        
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
    
    if target_size < 1000:
        chunks = []
        for i in range(0, len(text), 1000):
            chunks.append(text[i:i+1000])
        return chunks
    
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