"""
Processamento de chunks e vulnerabilidades.
Contém lógica de tokenização, splitting, retry e consolidação.
"""

import json
import re
import tiktoken
from collections import defaultdict
from typing import List, Dict, Any, Optional

from utils.utils import parse_json_response, load_prompt


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
    
    tokens = tokenizer.encode(text)
    n_tokens = len(tokens)
    print(f"[TOKEN CALC] Total de tokens no texto: {n_tokens}")
    
    chunks = []
    for i in range(0, n_tokens, available_for_content):
        chunk_tokens = tokens[i:i + available_for_content]
        chunk_text = tokenizer.decode(chunk_tokens)
        chunks.append(TokenChunk(chunk_text))
    
    print(f"[TOKEN CALC] Total de chunks criados: {len(chunks)}")
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
    
    prompt = (
        "Analyze this security report with preserved visual layout and extract vulnerabilities in JSON format:\n\n"
        f"REPORT CONTENT:\n{doc_chunk.page_content}\n\n"
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
        if current_len + line_len > target_size and current:
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
    
    while retry_count < max_retries:
        try:
            if retry_count == 0:
                prompt = build_prompt(doc_chunk, profile_config)
                resposta = llm.invoke(prompt).content
            else:
                print(f"[RETRY {retry_count}] Subdividindo chunk com tamanho {current_size}...")
                sub_vulns = fallback_process_large_chunk(doc_chunk, llm, profile_config, current_size)
                return sub_vulns
            
            try:
                vulnerabilities = json.loads(resposta)
                if isinstance(vulnerabilities, list):
                    return vulnerabilities
                else:
                    print(f"[AVISO] Resposta não é uma lista, tentando extrair JSON...")
                    raise json.JSONDecodeError("Resposta não é uma lista", resposta, 0)
            except json.JSONDecodeError as json_err:
                vulnerabilities = parse_json_response(resposta, f" chunk")
                if vulnerabilities:
                    return vulnerabilities
                
                print(f"[AVISO] Não foi possível encontrar array JSON válido na resposta")
                raise json_err
                    
        except Exception as e:
            retry_count += 1
            error_msg = str(e)
            error_type = type(e).__name__
            print(f"[RETRY {retry_count}/{max_retries}] {error_type}: {error_msg[:150]}...")
            
            if any(keyword in error_msg.lower() for keyword in ['quota', '429', 'rate limit', 'timeout', 'timed out']):
                print(f"[ERRO CRÍTICO] Detectado erro de quota/timeout/rate limit. Interrompendo.")
                raise e
            
            current_size = max(1000, current_size // 2)
            
            if retry_count >= max_retries:
                print(f"[ERRO] Máximo de tentativas ({max_retries}) excedido. Último erro: {error_type}")
                return []
    
    print(f"[ERRO] Saiu do loop de retry sem retornar vulnerabilidades")
    return []


def consolidate_duplicates(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Consolida vulnerabilidades (sem duplicação de Tenable WAS).
    
    - Se tem Tenable WAS (source='TENABLEWAS'): consolida por name_consolidated
    - Se é OpenVAS: retorna como está
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
    
    Returns:
        Lista consolidada
    """
    # Verificar se tem Tenable WAS
    has_tenable = any(
        v.get('source') == 'TENABLEWAS' 
        for v in vulnerabilities 
        if isinstance(v, dict)
    )
    
    if not has_tenable:
        # OpenVAS: sem consolidação
        return vulnerabilities
    
    # Tenable WAS: consolidar por name_consolidated
    consolidated = {}
    
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        
        # Usar name_consolidated se disponível, senão usar definição original
        if 'name_consolidated' in vuln:
            # Formato CAIS com name_consolidated
            key = vuln.get('name_consolidated', 'UNKNOWN')
        elif 'definition.name' in vuln:
            # Formato CAIS sem name_consolidated (fallback)
            name = vuln.get('definition.name', 'UNKNOWN')
            key = re.sub(r'\s+Instances\s*\(\d+\)\s*$', '', name)
        else:
            # Formato Sistema
            name = vuln.get('Name', 'UNKNOWN')
            key = re.sub(r'\s+Instances\s*\(\d+\)\s*$', '', name)
        
        if key not in consolidated:
            consolidated[key] = vuln
        else:
            # Manter a última instância extraída
            consolidated[key] = vuln
    
    return list(consolidated.values())
