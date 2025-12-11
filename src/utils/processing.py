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


def split_text_to_subchunks(text: str, target_size: int) -> List[str]:
    """
    Divide texto grande em subchunks menores preservando quebras de linha.
    
    Args:
        text: Texto a dividir
        target_size: Tamanho alvo em caracteres
    
    Returns:
        Lista de strings com subchunks
    """
    if len(text) <= target_size:
        return [text]
    
    lines = text.splitlines(keepends=True)
    subchunks = []
    current = []
    current_len = 0
    
    for line in lines:
        line_len = len(line)
        # Match: "NVT:", "VULNERABILITY", "Vulnerability:" com espaço opcional
        is_vuln_start = re.search(r'^\s*(?:NVT:|VULNERABILITY|Vulnerability:)', line.lstrip())
        
        if is_vuln_start and current and (current_len + line_len > target_size):
            subchunks.append(''.join(current))
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len
    
    if current:
        subchunks.append(''.join(current))
    
    return subchunks


def fallback_process_large_chunk(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                                max_subchunk_chars: int = 4000) -> List[Dict]:
    """
    Processa chunk grande dividindo em subchunks quando há erro.
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_subchunk_chars: Tamanho máximo de subchunk em caracteres
    
    Returns:
        Lista de vulnerabilidades extraídas
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
                sub_vulns.extend(parsed)
                print(f"[FALLBACK] ✓ Subchunk {idx}: {len(parsed)} vulnerabilidades extraídas")
            else:
                print(f"[FALLBACK] ✗ Subchunk {idx} não retornou lista JSON válida.")
        except Exception as e:
            print(f"[FALLBACK] ✗ Erro ao processar subchunk {idx}: {e}")
    
    print(f"[FALLBACK] Processamento completo: {len(sub_vulns)} vulnerabilidades totais extraídas")
    return sub_vulns


def retry_chunk_with_subdivision(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any], 
                                max_retries: int = 3) -> List[Dict]:
    """
    Processa chunk com retry automático e subdivisão progressiva.
    
    Args:
        doc_chunk: Chunk de documento
        llm: Instância do LLM
        profile_config: Configuração do perfil
        max_retries: Máximo de tentativas
    
    Returns:
        Lista de vulnerabilidades extraídas
    """
    retry_count = 0
    current_size = 4000
    
    while retry_count <= max_retries:
        try:
            if retry_count == 0:
                print(f"[ATTEMPT {retry_count+1}/{max_retries+1}] Chunk completo...")
                prompt = build_prompt(doc_chunk, profile_config)
                resposta = llm.invoke(prompt).content
            else:
                print(f"[ATTEMPT {retry_count+1}/{max_retries+1}] Subdividindo ({current_size} chars)...")
                sub_vulns = fallback_process_large_chunk(doc_chunk, llm, profile_config, current_size)
                return sub_vulns
            
            try:
                vulnerabilities = json.loads(resposta)
                if isinstance(vulnerabilities, list):
                    return vulnerabilities
                else:
                    raise json.JSONDecodeError("Resposta não é lista", resposta, 0)
            except json.JSONDecodeError:
                vulnerabilities = parse_json_response(resposta, f" attempt {retry_count+1}")
                if vulnerabilities:
                    return vulnerabilities
                raise json.JSONDecodeError("JSON inválido", resposta, 0)
                    
        except Exception as e:
            error_msg = str(e).lower()
            if any(kw in error_msg for kw in ['quota', '429', 'rate limit', 'timeout']):
                print(f"[ERRO CRÍTICO] {type(e).__name__}: Interrompendo")
                raise e
            
            retry_count += 1
            if retry_count > max_retries:
                print(f"[ERRO] {max_retries} tentativas excedidas")
                return []
            
            current_size = max(1000, current_size // 2)
            print(f"[RETRY] Tentativa {retry_count}/{max_retries}")
    
    return []


def consolidate_duplicates(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Consolida vulnerabilidades (dedup) para AMBOS OpenVAS e Tenable WAS.
    Mesma vuln pode aparecer em múltiplos chunks - manter apenas uma.
    
    IMPORTANTE para OpenVAS:
    - Vulnerabilidades com o MESMO NAME mas PORTAS DIFERENTES são entidades DIFERENTES
    - Só consolidar se Name AND Port (ou ambas as chaves relevantes) forem iguais
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
    
    Returns:
        Lista consolidada sem duplicatas
    """
    if not vulnerabilities:
        return []
    
    consolidated = {}
    
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        
        source = vuln.get('source', 'UNKNOWN')
        
        if source == 'TENABLEWAS':
            if 'name_consolidated' in vuln:
                key = vuln.get('name_consolidated', 'UNKNOWN')
            elif 'definition.name' in vuln:
                name = vuln.get('definition.name', 'UNKNOWN')
                key = re.sub(r'\s+Instances\s*\(\d+\)\s*$', '', name)
            else:
                name = vuln.get('Name', 'UNKNOWN')
                key = re.sub(r'\s+Instances\s*\(\d+\)\s*$', '', name)
        else:
            # OpenVAS: consolidar apenas se Name AND Port forem iguais
            # (vulnerabilidades com mesmo nome mas portas diferentes são entidades diferentes!)
            name = vuln.get('Name', 'UNKNOWN')
            port = vuln.get('port', 'NO_PORT')
            protocol = vuln.get('protocol', '')
            # Chave composta: (Name, port, protocol)
            key = (re.sub(r'\s+Instances\s*\(\d+\)\s*$', '', name), port, protocol)
        
        if key not in consolidated:
            consolidated[key] = vuln
    
    return list(consolidated.values())
