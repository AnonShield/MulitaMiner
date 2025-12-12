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


def get_token_based_chunks(text: str, max_tokens: int, reserve_for_response: int = 1000) -> List[TokenChunk]:
    """
    Divide texto em chunks baseado em tokens.
    
    Args:
        text: Texto a dividir
        max_tokens: Max tokens do modelo
        reserve_for_response: Tokens reservados para resposta (padrão: 1000)
    
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
    
    prompt_overhead = 500  # Estimativa do prompt template
    available_for_content = max(1000, max_tokens - prompt_overhead - reserve_for_response)
    
    print(f"[TOKEN CALC] Max tokens do modelo: {max_tokens}")
    print(f"[TOKEN CALC] Overhead do prompt: ~{prompt_overhead} tokens")
    print(f"[TOKEN CALC] Reserve para resposta: ~{reserve_for_response} tokens")
    print(f"[TOKEN CALC] Tokens disponíveis para conteúdo: ~{available_for_content} tokens")
    
    # Dividir por blocos de vulnerabilidades (NVT:, VULNERABILITY, ou Vulnerability:)
    # Isso preserva integridade em vez de quebrar no meio de uma vuln
    lines = text.split('\n')
    chunks = []
    current_chunk = []
    current_tokens = 0
    
    for line in lines:
        line_tokens = len(tokenizer.encode(line))
        # Match: "NVT:", "VULNERABILITY", "Vulnerability:" com espaço opcional antes
        is_vuln_start = re.search(r'^\s*(?:NVT:|VULNERABILITY|Vulnerability:)', line.strip())
        
        # Se é início de vuln E chunk não vazio E excederia limite
        if is_vuln_start and current_chunk and (current_tokens + line_tokens > available_for_content):
            chunk_text = '\n'.join(current_chunk)
            chunks.append(TokenChunk(chunk_text))
            current_chunk = [line]
            current_tokens = line_tokens
        else:
            current_chunk.append(line)
            current_tokens += line_tokens
    
    if current_chunk:
        chunk_text = '\n'.join(current_chunk)
        chunks.append(TokenChunk(chunk_text))
    
    print(f"[TOKEN CALC] Total de chunks criados (respeitando blocos): {len(chunks)}")
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


def detect_scanner_pattern(text: str) -> dict:
    """
    Detecta padrão de scanner (OpenVAS, Tenable WAS, etc) baseado em markers no texto.
    
    Estratégia extensível:
    1. Tenta detectar padrões conhecidos (OpenVAS, Tenable WAS)
    2. Se encontra, retorna configuração específica
    3. Se não encontra, retorna 'generic' para fallback simples
    
    Returns:
        Dict com:
        {
            'scanner_type': 'openvas' | 'tenable_was' | 'generic',
            'marker_pattern': regex pattern para encontrar blocos (None se generic),
            'has_pairs': bool (True se vulnerabilidades vêm em pares BASE+INSTANCES),
            'markers_found': int (número de blocos detectados)
        }
    """
    # Detectar OpenVAS: começa com "NVT: "
    nvt_matches = re.findall(r'^\s*NVT:\s', text, re.MULTILINE)
    
    # Detectar Tenable WAS: começa com "VULNERABILITY"
    vuln_matches = re.findall(r'^\s*VULNERABILITY\s', text, re.MULTILINE)
    
    if nvt_matches:
        return {
            'scanner_type': 'openvas',
            'marker_pattern': r'^\s*NVT:\s',
            'has_pairs': False,
            'markers_found': len(nvt_matches)
        }
    elif vuln_matches:
        return {
            'scanner_type': 'tenable_was',
            'marker_pattern': r'^\s*VULNERABILITY\s',
            'has_pairs': True,  # Tenable WAS usa pares
            'markers_found': len(vuln_matches)
        }
    else:
        return {
            'scanner_type': 'generic',
            'marker_pattern': None,
            'has_pairs': False,
            'markers_found': 0
        }


def register_scanner_pattern(scanner_name: str, marker_pattern: str, has_pairs: bool = False):
    """
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


def split_text_to_subchunks(text: str, target_size: int) -> List[str]:
    """
    Divide texto grande em subchunks menores com divisão JUSTA e extensível.
    
    Estratégia:
    1. Detecta tipo de scanner (OpenVAS, Tenable WAS, etc)
    2. Encontra blocos baseado no padrão detectado
    3. Processa blocos respeitando tamanho alvo
    4. Se há pares (Tenable WAS), mantém pares completos
    5. Se não há pares (OpenVAS), quebra simplesmente por tamanho
    
    Args:
        text: Texto a dividir
        target_size: Tamanho alvo em caracteres
    
    Returns:
        Lista de subchunks (respeitando limites de padrão detectado)
    """
    if len(text) <= target_size:
        return [text]
    
    lines = text.splitlines(keepends=True)
    if not lines:
        return [text]
    
    # Detectar padrão
    pattern_info = detect_scanner_pattern(text)
    
    # Se não encontrou padrão, fazer fallback simples
    if pattern_info['marker_pattern'] is None:
        return [text] if len(text) <= target_size else _simple_split_by_size(text, target_size)
    
    # Encontrar índices de linhas com marcador detectado
    marker_lines = []
    for i, line in enumerate(lines):
        if re.search(pattern_info['marker_pattern'], line):
            marker_lines.append(i)
    
    # Se não encontrou marcadores mesmo após detecção, fallback
    if not marker_lines:
        return [text] if len(text) <= target_size else _simple_split_by_size(text, target_size)
    
    subchunks = []
    current_lines = []
    current_size = 0
    
    # Processar marcadores (blocos)
    i = 0
    while i < len(marker_lines):
        # Determinar fim do bloco atual (próximo marcador ou fim do arquivo)
        block_start = marker_lines[i]
        block_end = marker_lines[i + 1] if i + 1 < len(marker_lines) else len(lines)
        
        block_lines = lines[block_start:block_end]
        block_text = ''.join(block_lines)
        block_size = len(block_text)
        
        # Se bloco sozinho é maior que target_size, dividir o bloco
        if block_size > target_size:
            # Salvar current se não vazio
            if current_lines:
                subchunks.append(''.join(current_lines))
                current_lines = []
                current_size = 0
            
            # Subdividir o bloco internamente
            sub_blocks = _split_block_by_size(block_text, target_size)
            subchunks.extend(sub_blocks)
            i += 1
            continue
        
        # Se adicionar bloco ultrapassa target_size, salvar current antes
        if current_lines and (current_size + block_size > target_size):
            subchunks.append(''.join(current_lines))
            current_lines = []
            current_size = 0
        
        # Adicionar bloco ao current
        current_lines.extend(block_lines)
        current_size += block_size
        i += 1
    
    # Adicionar restante
    if current_lines:
        subchunks.append(''.join(current_lines))
    
    return subchunks if subchunks else [text]


def _split_block_by_size(text: str, target_size: int) -> List[str]:
    """
    Divide um bloco de texto em subchunks.
    Estratégia: Divide pela METADE do texto (não pelo target_size).
    Isso evita subdivisões excessivas até 2000 caracteres.
    
    Usado quando um bloco individual é maior que target_size.
    """
    if len(text) <= target_size:
        return [text]
    
    # NOVA ESTRATÉGIA: Dividir pela metade do texto
    # Ao invés de ir diminuindo até target_size (que causa muitas subdivisões)
    # Dividir só pela metade reduz o número de chunks drasticamente
    half_size = len(text) // 2
    
    subchunks = []
    lines = text.splitlines(keepends=True)
    current = []
    current_len = 0
    
    # Procurar ponto de divisão próximo à metade
    for line in lines:
        line_len = len(line)
        
        # Se atingiu a metade, salvar
        if current and current_len >= half_size:
            subchunks.append(''.join(current))
            current = []
            current_len = 0
        
        current.append(line)
        current_len += line_len
    
    if current:
        subchunks.append(''.join(current))
    
    # Se resultado ainda é grande, fazer recursão (divide novamente pela metade)
    result = []
    for subchunk in subchunks:
        if len(subchunk) > target_size:
            # Recursivamente divide este subchunk também pela metade
            result.extend(_split_block_by_size(subchunk, target_size))
        else:
            result.append(subchunk)
    
    return result if result else [text]


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


def fallback_process_large_chunk(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                                max_subchunk_chars: int = 4000) -> List[Dict]:
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


def consolidate_duplicates(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Consolida vulnerabilidades removendo duplicatas E mesclando URLs.
    Remove entradas incompletas (BASE sem INSTANCES ou vice-versa).
    
    Para Tenable WAS:
    - Se mesma vulnerability (mesmo Name) aparece múltiplas vezes
    - Mescla os arrays de identification (combina URLs únicas)
    - Mantém apenas 1 entrada por vulnerability com TODAS as URLs
    - Remove pares incompletos

    Para OpenVAS:
    - Consolida por (Name, port, protocol)
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
    
    Returns:
        Lista consolidada com URLs mescladas (apenas pares válidos)
    """
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

