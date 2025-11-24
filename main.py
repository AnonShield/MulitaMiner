import os
import sys
import argparse
import json
import tiktoken

# third-party
from tqdm import tqdm

# ensure local package imports resolve (adds project src to sys.path)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# local imports (from src/)
from utils.utils import (
    load_profile, load_llm, init_llm, load_prompt, save_visual_layout,
    execute_conversions
)
from utils.pdf_loader import load_pdf_with_pypdf2

class _TokenChunk:
    """Objeto simples compatível com doc_chunk esperado (atributo page_content)."""
    def __init__(self, page_content):
        self.page_content = page_content

def get_token_based_chunks(text, max_tokens):
    """Divide texto em chunks baseado em tokens seguindo a lógica especificada."""
    # Usar tokenizer do GPT por padrão (compatível com a maioria dos modelos)
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    tokens = tokenizer.encode(text)
    n_tokens = len(tokens)
    chunks = []
    
    # Seguir a lógica: for i in range(0, n_tokens, MAX_TOKENS)
    for i in range(0, n_tokens, max_tokens):
        chunk_tokens = tokens[i:i + max_tokens]
        chunk_text = tokenizer.decode(chunk_tokens)
        chunks.append(_TokenChunk(chunk_text))
    
    return chunks




def parse_arguments():
    """Parse argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description='Extrai vulnerabilidades de relatórios PDF usando um LLM e salva em JSON/CSV/XLSX.'
    )
    parser.add_argument('--profile', default='default', help='Perfil de configuração (padrão: default)')
    
    parser.add_argument('pdf_path', help='Caminho para o arquivo PDF')
    
    
    # Opções de conversão
    parser.add_argument('--convert',
                        choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                        default='none',
                        help='Converter saída JSON para formato específico (padrão: none)')
    parser.add_argument('--output',
                        help='Caminho do arquivo de saída para a conversão (opcional)')
    parser.add_argument('--output-dir',
                        dest='output_dir',
                        help='Diretório de saída para arquivos convertidos (opcional)')
    parser.add_argument('--csv-delimiter',
                        dest='csv_delimiter',
                        default=',',
                        help='Delimitador para CSV (padrão: ,)')
    parser.add_argument('--csv-encoding',
                        dest='csv_encoding',
                        default='utf-8-sig',
                        help='Codificação para CSV (padrão: utf-8-sig)')
    
    # Argumentos essenciais
    parser.add_argument('--LLM', default='gpt4', help='Nome do LLM a usar (padrão: gpt4)')
    return parser.parse_args()
def validate_pdf_path(pdf_path):
    if not os.path.isfile(pdf_path):
        print(f"Erro: Arquivo PDF não encontrado: {pdf_path}")
        return False
    return True

def get_configs(args):
    profile_config = load_profile(args.profile)
    if profile_config is None:
        print(f"Erro ao carregar configuração do perfil: {args.profile}")
        return None, None
    llm_config = load_llm(args.LLM)
    if llm_config is None:
        print(f"Erro ao carregar configuração do LLM: {args.LLM}")
        return None, None
    return profile_config, llm_config

def build_prompt(doc_chunk, profile_config):
    template_path = profile_config.get('prompt_template', '')
    prompt_template_content = load_prompt(template_path)
    
    prompt = (
        "Analyze this security report with preserved visual layout and extract vulnerabilities in JSON format:\n\n"
        f"REPORT CONTENT:\n{doc_chunk.page_content}\n\n"
        f"{prompt_template_content}"
    )
    
    return prompt

def _split_text_to_subchunks(text, target_size):
    """Divide um texto grande em subchunks menores aproximando target_size em caracteres.
    Mantém quebras de linha para preservar contexto lógico.
    """
    if len(text) <= target_size:
        return [text]
    lines = text.splitlines(keepends=True)
    subchunks = []
    current = []
    current_len = 0
    for line in lines:
        line_len = len(line)
        # Se adicionar esta linha extrapola o target, fecha chunk atual
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

class _AdHocChunk:
    """Objeto simples compatível com doc_chunk esperado (atributo page_content)."""
    def __init__(self, page_content):
        self.page_content = page_content

def _fallback_process_large_chunk(doc_chunk, llm, profile_config, max_subchunk_chars=4000):
    """Processa um chunk grande dividindo-o em subchunks quando há erro de contexto ou tamanho.
    Retorna lista de vulnerabilidades extraídas dos subchunks.
    """
    sub_vulns = []
    sub_texts = _split_text_to_subchunks(doc_chunk.page_content, max_subchunk_chars)
    print(f"[FALLBACK] Dividindo chunk em {len(sub_texts)} subchunks de ~{max_subchunk_chars} caracteres...")
    
    for idx, sub_text in enumerate(sub_texts, start=1):
        sub_chunk = _AdHocChunk(sub_text)
        prompt = build_prompt(sub_chunk, profile_config)
        print(f"[FALLBACK] Processando subchunk {idx}/{len(sub_texts)} (tamanho: {len(sub_text)} chars)...")
        try:
            print(f"[FALLBACK] → Enviando subchunk {idx} para LLM...")
            resposta = llm.invoke(prompt).content
            print(f"[FALLBACK] ← Resposta recebida do LLM para subchunk {idx}")
            try:
                parsed = json.loads(resposta)
            except json.JSONDecodeError:
                start = resposta.find('[')
                end = resposta.rfind(']') + 1
                parsed = []
                if start != -1 and end > start:
                    try:
                        parsed = json.loads(resposta[start:end])
                        print(f"[FALLBACK] ✓ JSON extraído com sucesso do subchunk {idx}")
                    except Exception:
                        print(f"[FALLBACK] ✗ Falha ao extrair JSON do subchunk {idx}")
                        pass
            if isinstance(parsed, list):
                sub_vulns.extend(parsed)
                print(f"[FALLBACK] ✓ Subchunk {idx}: {len(parsed)} vulnerabilidades extraídas")
            else:
                print(f"[FALLBACK] ✗ Subchunk {idx} não retornou lista JSON válida.")
        except Exception as e:
            print(f"[FALLBACK] ✗ Erro ao processar subchunk {idx}: {e}")
    
    print(f"[FALLBACK] Processamento completo: {len(sub_vulns)} vulnerabilidades totais extraídas")
    return sub_vulns

def _retry_chunk_with_subdivision(doc_chunk, llm, profile_config, max_retries=3):
    """Processa um chunk com retry automático e subdivisão progressiva em caso de erro."""
    retry_count = 0
    current_size = 4000  # Tamanho inicial para subdivisão
    last_error = None
    
    while retry_count < max_retries:
        try:
            if retry_count == 0:
                # Primeira tentativa: chunk original
                prompt = build_prompt(doc_chunk, profile_config)
                resposta = llm.invoke(prompt).content
            else:
                # Tentativas subsequentes: dividir em subchunks
                print(f"[RETRY {retry_count}] Subdividindo chunk com tamanho {current_size}...")
                sub_vulns = _fallback_process_large_chunk(doc_chunk, llm, profile_config, current_size)
                return sub_vulns
            
            # Tentar parsear JSON
            try:
                vulnerabilities = json.loads(resposta)
                if isinstance(vulnerabilities, list):
                    return vulnerabilities
                else:
                    print(f"[AVISO] Resposta não é uma lista, tentando extrair JSON...")
                    raise json.JSONDecodeError("Resposta não é uma lista", resposta, 0)
            except json.JSONDecodeError as json_err:
                # Fallback: buscar JSON entre colchetes
                start = resposta.find('[')
                end = resposta.rfind(']') + 1
                if start != -1 and end > start:
                    json_str = resposta[start:end]
                    try:
                        vulnerabilities = json.loads(json_str)
                        if isinstance(vulnerabilities, list):
                            return vulnerabilities
                        else:
                            print(f"[AVISO] JSON extraído não é uma lista")
                            raise json_err
                    except json.JSONDecodeError as parse_err:
                        print(f"[AVISO] Falha ao parsear JSON extraído: {str(parse_err)[:100]}")
                        raise parse_err
                else:
                    print(f"[AVISO] Não foi possível encontrar array JSON válido na resposta")
                    raise json_err
                    
        except Exception as e:
            retry_count += 1
            error_msg = str(e)
            error_type = type(e).__name__
            last_error = e
            print(f"[RETRY {retry_count}/{max_retries}] {error_type}: {error_msg[:150]}...")
            
            # Se é erro de quota/rate limit/timeout, não retry
            if any(keyword in error_msg.lower() for keyword in ['quota', '429', 'rate limit', 'timeout', 'timed out']):
                print(f"[ERRO CRÍTICO] Detectado erro de quota/timeout/rate limit. Interrompendo.")
                raise e
                
            # Reduzir tamanho para próxima tentativa
            current_size = max(1000, current_size // 2)
            
            if retry_count >= max_retries:
                print(f"[ERRO] Máximo de tentativas ({max_retries}) excedido. Último erro: {error_type}")
                return []
    
    print(f"[ERRO] Saiu do loop de retry sem retornar vulnerabilidades")
    return []

def process_vulnerabilities(doc_texts, llm, profile_config):
    all_vulnerabilities = []
    total_chunks = len(doc_texts)
    max_retries = profile_config.get('retry_attempts', 3)
    
    for i, doc_chunk in enumerate(tqdm(doc_texts, desc="Processando chunks", unit="chunk")):
        print(f"\n{'='*60}")
        print(f"Processando chunk {i+1}/{total_chunks}")
        print(f"{'='*60}")
        try:
            vulnerabilities_chunk = _retry_chunk_with_subdivision(doc_chunk, llm, profile_config, max_retries)
            
            if vulnerabilities_chunk:
                all_vulnerabilities.extend(vulnerabilities_chunk)
                nomes_vulns = [v.get('Name') for v in vulnerabilities_chunk if isinstance(v, dict) and v.get('Name')]
                print(f"[LOG] Chunk {i+1}/{total_chunks}: {len(vulnerabilities_chunk)} vulnerabilidades extraídas: {nomes_vulns}")
            else:
                print(f"[LOG] Chunk {i+1}/{total_chunks}: 0 vulnerabilidades extraídas: []")
                
        except Exception as e:
            error_text = str(e).lower()
            error_type = type(e).__name__
            
            # Verificar erros críticos que devem parar o processamento
            if any(keyword in error_text for keyword in ['quota', '429', 'rate limit', 'timeout', 'timed out', 'connection', 'ssl']):
                print(f"\n[ERRO CRÍTICO] {error_type}: {str(e)[:200]}")
                print(f"Chunk {i+1}/{total_chunks} - Parando processamento.")
                break
            else:
                print(f"\n[ERRO] {error_type} no chunk {i+1}: {str(e)[:200]}")
                print(f"[LOG] Chunk {i+1}/{total_chunks}: 0 vulnerabilidades extraídas: []")
                print(f"Continuando com próximo chunk...\n")
                
    return all_vulnerabilities

def consolidate_duplicates(vulnerabilities):
    """
    Consolida vulnerabilidades com mesmo Name em um único objeto.
    Mescla arrays (description, solution, references, identification, http_info, plugin)
    mantendo valores únicos. Mantém highest severity.
    """
    from collections import defaultdict
    
    # Agrupar por Name
    by_name = defaultdict(list)
    for vuln in vulnerabilities:
        name = (vuln.get('Name') or '').strip()
        if name:
            by_name[name].append(vuln)
    
    consolidated = []
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'LOG': 0}
    
    for name, vulns in by_name.items():
        if len(vulns) == 1:
            consolidated.append(vulns[0])
            continue
        
        # Mesclar múltiplas instâncias
        base = vulns[0].copy()
        
        # Arrays para mesclar (unique values)
        array_fields = ['description', 'solution', 'references', 'identification', 
                       'http_info', 'plugin', 'detection_result', 'detection_method',
                       'impact', 'insight', 'product_detection_result', 'log_method']
        
        for field in array_fields:
            all_values = []
            for v in vulns:
                val = v.get(field, [])
                if isinstance(val, list):
                    all_values.extend(val)
                elif val is not None:
                    all_values.append(val)
            # Remove duplicatas mantendo ordem
            unique = []
            seen = set()
            for item in all_values:
                # Para strings, usar lowercase para dedup case-insensitive
                key = item.lower() if isinstance(item, str) else str(item)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            base[field] = unique
        
        # Severity: pegar o maior
        severities = [v.get('severity', 'LOG') for v in vulns]
        base['severity'] = max(severities, key=lambda s: severity_order.get(s, 0))
        
        # CVSS: pegar primeiro não-null
        cvss_vals = [v.get('cvss') for v in vulns if v.get('cvss') and any(v.get('cvss'))]
        if cvss_vals:
            base['cvss'] = cvss_vals[0]
        
        # Port/protocol: pegar primeiro não-null
        ports = [v.get('port') for v in vulns if v.get('port')]
        if ports:
            base['port'] = ports[0]
        
        protocols = [v.get('protocol') for v in vulns if v.get('protocol')]
        if protocols:
            base['protocol'] = protocols[0]
        
        consolidated.append(base)
    
    return consolidated

def save_results(all_vulnerabilities, output_file):
    try:
        # Verificar se há vulnerabilidades de Tenable WAS
        has_tenable = any(v.get('source') == 'TENABLEWAS' for v in all_vulnerabilities if isinstance(v, dict))
        
        if has_tenable:
            # Consolidar duplicatas apenas para Tenable WAS
            print(f"\nConsolidando vulnerabilidades duplicadas (Tenable WAS)...")
            unique_vulns = consolidate_duplicates(all_vulnerabilities)
            print(f"Total antes: {len(all_vulnerabilities)} | Após consolidação: {len(unique_vulns)}")
        else:
            # OpenVAS: não consolidar
            print(f"\nSem consolidação (OpenVAS) - {len(all_vulnerabilities)} vulnerabilidades")
            unique_vulns = all_vulnerabilities
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(unique_vulns, f, indent=2, ensure_ascii=False)
        print(f"Processamento concluído. Vulnerabilidades salvas em: {output_file}")
        return True
    except Exception as e:
        print(f"Erro ao salvar arquivo JSON: {e}")
        return False

def handle_conversions(output_file, args, visual_file):
    print(f"Layout visual salvo em: {visual_file if visual_file else 'Erro ao salvar'}")
    # Executa conversões conforme argumentos (csv/xlsx/tsv/all)
    try:
        converted = execute_conversions(output_file, args)
        if converted:
            print("Conversões geradas:")
            for c in converted:
                print(f" - {c}")
        else:
            print("Nenhuma conversão realizada.")
    except Exception as e:
        print(f"Erro ao executar conversões: {e}")

def main():
    args = parse_arguments()
    if not validate_pdf_path(args.pdf_path):
        return
    profile_config, llm_config = get_configs(args)
    if not profile_config or not llm_config:
        return
    llm = init_llm(llm_config)
    output_file = profile_config['output_file']
    
    # Usar max_tokens diretamente da configuração do LLM
    max_tokens = llm_config.get('max_tokens', 4000)  # Fallback padrão
    
    # Carregamento do documento PDF
    documents = load_pdf_with_pypdf2(args.pdf_path)
    if documents is None:
        print("Falha ao carregar o PDF. Verifique se o arquivo não está corrompido.")
        return
    visual_file = save_visual_layout(documents[0].page_content, args.pdf_path)
    
    # Divisão baseada em tokens do LLM
    doc_texts = get_token_based_chunks(documents[0].page_content, max_tokens)
    # Divisão baseada em tokens do LLM
    doc_texts = get_token_based_chunks(documents[0].page_content, max_tokens)
    print(f"Total de chunks a processar: {len(doc_texts)}")
    all_vulnerabilities = process_vulnerabilities(doc_texts, llm, profile_config)
    if save_results(all_vulnerabilities, output_file):
        handle_conversions(output_file, args, visual_file)

if __name__ == "__main__":
    main()