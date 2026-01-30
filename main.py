"""
PDF Vulnerability Extractor - Main Entry Point

Extrai vulnerabilidades de relatórios PDF (OpenVAS/Tenable WAS) usando LLM
e converte para formatos estruturados (JSON/CSV/XLSX).

Usage:
    python main.py <pdf_path> [--LLM <model>] [--convert <format>] [--scanner <name>]
"""
import os
import sys

# Garante que o diretório 'src' esteja no sys.path para imports absolutos
project_root = os.path.abspath(os.path.dirname(__file__))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

import argparse
import json
import subprocess
from tqdm import tqdm
from utils.cli_args import parse_arguments
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from utils.cli_args import parse_arguments

# Force UTF-8 encoding on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')



from utils.utils import (
    load_profile, load_llm, init_llm, save_visual_layout,
    execute_conversions, validate_and_normalize_vulnerability,
    validate_cais_vulnerability
)
from utils.pdf_loader import load_pdf_with_pypdf2
from utils.processing import (
    get_token_based_chunks, retry_chunk_with_subdivision,
    consolidate_duplicates, is_cais_profile, get_consolidation_field
)


def get_validator(profile_config: dict):
    """Obter validador apropriado baseado no perfil."""
    if is_cais_profile(profile_config):
        return validate_cais_vulnerability
    return validate_and_normalize_vulnerability




def validate_inputs(args: argparse.Namespace) -> bool:
    """Valida inputs do usuário."""
    if not os.path.isfile(args.pdf_path):
        print(f"Erro: Arquivo PDF não encontrado: {args.pdf_path}")
        return False
    
    # Validação para o modo de avaliação
    if args.evaluate:
        if not args.baseline:
            print("Erro: O argumento --baseline é obrigatório quando --evaluate é usado.")
            return False
        if not os.path.isfile(args.baseline):
            print(f"Erro: Arquivo de baseline não encontrado: {args.baseline}")
            return False
        if args.convert not in ['xlsx', 'all']:
            print("Aviso: Para avaliação, a conversão para '.xlsx' é necessária. Ativando a conversão para 'all'.")
            args.convert = 'all'

    return True


def load_configs(args: argparse.Namespace) -> tuple:
    """Carrega configurações de perfil e LLM."""
    profile_config = load_profile(args.scanner)
    if not profile_config:
        print(f"Erro ao carregar perfil: {args.scanner}")
        return None, None
    
    llm_config = load_llm(args.LLM)
    if not llm_config:
        print(f"Erro ao carregar LLM: {args.LLM}")
        return None, None
    
    return profile_config, llm_config


def process_vulnerabilities(doc_texts: list, llm, profile_config: dict) -> list:
    """
    Processa todos os chunks e extrai vulnerabilidades.
    
    Args:
        doc_texts: Lista de chunks de documento
        llm: Instância do LLM inicializada
        profile_config: Configuração do perfil
    
    Returns:
        Lista de todas as vulnerabilidades extraídas
    """
    all_vulnerabilities = []
    max_retries = profile_config.get('retry_attempts', 3)
    
    for i, doc_chunk in enumerate(tqdm(doc_texts, desc="Processando chunks", unit="chunk")):
        print(f"\n{'='*60}")
        print(f"Processando chunk {i+1}/{len(doc_texts)}")
        print(f"{'='*60}")
        
        try:
            vulns_chunk = retry_chunk_with_subdivision(doc_chunk, llm, profile_config, max_retries)
            
            if vulns_chunk:
                # Validar vulnerabilidades (CHAMADA ÚNICA per vuln)
                validator = get_validator(profile_config)
                validated_vulns = []
                for v in vulns_chunk:
                    validated = validator(v)
                    if validated:
                        validated_vulns.append(validated)
                
                # Determinar campo de nome
                name_field = get_consolidation_field(validated_vulns, profile_config)
                
                all_vulnerabilities.extend(validated_vulns)
                names = [v.get(name_field) for v in validated_vulns if isinstance(v, dict) and v.get(name_field)]
                
                print(f"[LOG] Chunk {i+1}/{len(doc_texts)}: {len(validated_vulns)}/{len(vulns_chunk)} válidas")
                if names:
                    print(f"[NOMES] {len(names)}:")
                    for idx, name in enumerate(names, 1):
                        print(f"  {idx:2d}. {name}")
            else:
                print(f"[LOG] Chunk {i+1}/{len(doc_texts)}: 0 extraídas")
                
        except Exception as e:
            error_msg = str(e).lower()
            
            # Erros críticos que interrompem processamento
            if any(kw in error_msg for kw in ['quota', '429', 'rate limit', 'timeout', 'connection']):
                print(f"\n[ERRO CRÍTICO] {type(e).__name__}: {str(e)[:200]}")
                print(f"Parando processamento no chunk {i+1}/{len(doc_texts)}")
                break
            else:
                print(f"\n[ERRO] {type(e).__name__}: {str(e)[:200]}")
                print(f"Continuando com próximo chunk...")
    
    return all_vulnerabilities


def load_previous_vulnerabilities(output_file: str) -> dict:
    """
    Carrega vulnerabilidades previamente salvas para comparação.
    
    Args:
        output_file: Caminho do arquivo de saída
    
    Returns:
        Dicionário com vulnerabilidades anteriores por nome
    """
    previous = {}
    if os.path.isfile(output_file):
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for v in data:
                        if isinstance(v, dict) and v.get('Name'):
                            name = v.get('Name')
                            if name not in previous:
                                previous[name] = []
                            previous[name].append(v)
        except Exception as e:
            print(f"[AVISO] Não foi possível carregar arquivo anterior: {e}")
    return previous


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None) -> bool:
    """
    Salva vulnerabilidades em JSON.
    Consolida duplicatas para Tenable WAS.
    Mostra apenas as vulnerabilidades NOVAS encontradas.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        output_file: Caminho do arquivo de saída
        profile_config: Configuração do perfil (opcional)
    
    Returns:
        True se sucesso, False caso contrário
    """
    try:
        # Carregar vulnerabilidades anteriores para comparação
        previous_vulns = load_previous_vulnerabilities(output_file)
        
        # Verificar se o merge está habilitado na configuração
        merge_instances_with_same_base = profile_config.get('merge_instances_with_same_base', False)
        
        if merge_instances_with_same_base:
            print(f"\nConsolidando vulnerabilidades duplicadas...")
            final_vulns = consolidate_duplicates(vulnerabilities, profile_config)
            print(f"Total: {len(vulnerabilities)} → {len(final_vulns)} após consolidação")
        else:
            print(f"\nSem consolidação - {len(vulnerabilities)} vulnerabilidades")
            final_vulns = vulnerabilities
        
        # Detectar campo de consolidação do profile ou auto-detectar
        name_field = get_consolidation_field(final_vulns, profile_config)
        
        # Identificar vulnerabilidades NOVAS vs ANTIGAS
        new_vulns = []
        updated_vulns = []
        repeated_vulns = []
        
        for v in final_vulns:
            if isinstance(v, dict):
                name = v.get(name_field, 'SEM NOME')
                if name in previous_vulns:
                    # Verificar se é igual à versão anterior
                    is_duplicate = any(
                        v == prev_v 
                        for prev_v in previous_vulns[name]
                    )
                    if is_duplicate:
                        repeated_vulns.append(v)
                    else:
                        updated_vulns.append(v)
                else:
                    new_vulns.append(v)
        
        # Com merge: mostrar vulnerabilidades únicas
        # Sem merge: mostrar todas (permitir duplicatas)
        if merge_instances_with_same_base:
            unique_names = sorted(set(v.get(name_field, 'SEM NOME') for v in final_vulns if isinstance(v, dict)))
            print(f"\nTotal de vulnerabilidades únicas: {len(unique_names)}")
            print(f"\nResumo de vulnerabilidades encontradas:")
            for idx, name in enumerate(unique_names, 1):
                count = sum(1 for v in final_vulns if isinstance(v, dict) and v.get(name_field) == name)
                print(f"  {idx:3d}. [{count:2d}x] {name}")
        else:
            # Sem merge: listar separando NOVAS de REPETIDAS
            print(f"\nTotal de vulnerabilidades: {len(final_vulns)}")
            print(f"  - NOVAS: {len(new_vulns)}")
            print(f"  - ATUALIZADAS: {len(updated_vulns)}")
            print(f"  - REPETIDAS (sem mudança): {len(repeated_vulns)}")
            
            if new_vulns:
                print(f"\nVulnerabilidades NOVAS encontradas:")
                for idx, v in enumerate(new_vulns, 1):
                    if isinstance(v, dict):
                        name = v.get(name_field, 'SEM NOME')
                        severity = v.get('severity', 'UNKNOWN')
                        print(f"  {idx:3d}. [NOVO     ] [{severity:8s}] {name}")
            
            if updated_vulns:
                print(f"\nVulnerabilidades ATUALIZADAS:")
                for idx, v in enumerate(updated_vulns, 1):
                    if isinstance(v, dict):
                        name = v.get(name_field, 'SEM NOME')
                        severity = v.get('severity', 'UNKNOWN')
                        print(f"  {idx:3d}. [ATUALIZADO] [{severity:8s}] {name}")
            
            if repeated_vulns:
                print(f"\nVulnerabilidades REPETIDAS (sem mudança): {len(repeated_vulns)}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)
        
        print(f"\nVulnerabilidades salvas em: {output_file}")
        return True
        
    except Exception as e:
        print(f"Erro ao salvar JSON: {e}")
        return False


def run_evaluation(args: argparse.Namespace, extraction_output_path: str):
    """
    Executa o script de avaliação de métricas como um processo separado.
    
    Args:
        args: Argumentos da linha de comando, contendo --baseline e --evaluation-method.
        extraction_output_path: Caminho para o arquivo .xlsx gerado pela extração.
    """
    print(f"\n{'='*60}")
    print(f"Iniciando avaliação de métricas com o método: '{args.evaluation_method}'")
    print(f"{'='*60}")

    method = args.evaluation_method
    script_path = os.path.join('metrics', method, f'compare_extractions_{method}.py')
    
    if not os.path.isfile(script_path):
        print(f"Erro: Script de avaliação não encontrado em '{script_path}'")
        return

    # O diretório de saída será relativo ao script de métricas
    output_dir = os.path.join('metrics', method, 'results')

    command = [
        sys.executable,  # Usa o mesmo interpretador Python que está executando o main
        script_path,
        '--baseline_file', args.baseline,
        '--extraction_file', extraction_output_path,
        '--output_dir', output_dir
    ]
    # Passa o nome do modelo explicitamente se disponível
    if hasattr(args, 'LLM') and args.LLM:
        command += ['--model', args.LLM]
    
    # Passa configuração de duplicatas se especificada
    if hasattr(args, 'allow_duplicates') and args.allow_duplicates:
        command += ['--allow_duplicates']
    
    try:
        print(f"Executando comando: {' '.join(command)}")
        subprocess.run(command, check=True)
        print(f"\n[SUCESSO] Avaliação de métricas concluída.")
        print(f"Resultados salvos no diretório: '{output_dir}'")
        
    except FileNotFoundError:
        print(f"Erro: Python ou o script '{script_path}' não foi encontrado.")
        print("Verifique se o ambiente virtual de 'metrics' está configurado corretamente.")
    except subprocess.CalledProcessError as e:
        print("\n[ERRO] A avaliação de métricas falhou.")
        print(f"  Comando: {' '.join(e.cmd)}")
        print(f"  Código de Saída: {e.returncode}")
        print("-------------------------------------------------")


def main():
    """Fluxo principal de extração."""
    # Parse e validação
    args = parse_arguments()
    if not validate_inputs(args):
        return
    
    # Carregar configs
    profile_config, llm_config = load_configs(args)
    if not profile_config or not llm_config:
        return
    
    # Inicializar LLM
    llm = init_llm(llm_config)
    
    # Obter max_tokens (suportar tanto max_tokens quanto max_completion_tokens)
    if 'max_completion_tokens' in llm_config:
        max_tokens = llm_config.get('max_completion_tokens', 4096)
    else:
        max_tokens = llm_config.get('max_tokens', 4096)
    
    # Garantir que max_tokens é um inteiro
    if max_tokens is None:
        max_tokens = 4096
    max_tokens = int(max_tokens)
    
    reserve_response = llm_config.get('reserve_for_response', 1000)
    if reserve_response is None:
        reserve_response = 1000
    reserve_response = int(reserve_response)
    
    print(f"\n{'='*60}")
    print(f"[CONFIG] LLM: {llm_config.get('model')}")
    print(f"[CONFIG] Max tokens: {max_tokens}")
    print(f"[CONFIG] Reserve para resposta: {reserve_response}")
    print(f"{'='*60}\n")
    
    # Carregamento do PDF em blocos (um Document por página)
    documents = load_pdf_with_pypdf2(args.pdf_path)
    if not documents:
        print("Erro: Falha ao carregar PDF")
        return

    # Salvar layout visual da primeira página como referência
    visual_file = save_visual_layout(documents[0].page_content, args.pdf_path)
    print(f"Layout visual salvo em: {visual_file}\n")

    all_vulnerabilities = []
    total_chunks = 0
    for doc in documents:
        # Dividir cada bloco (página) em chunks
        doc_texts = get_token_based_chunks(
            doc.page_content,
            max_tokens,
            reserve_response,
            llm_config,
            profile_config
        )
        print(f"Páginas {doc.metadata.get('pages', doc.metadata.get('page', '?'))}: {len(doc_texts)} chunks")
        total_chunks += len(doc_texts)
        # Processar cada chunk normalmente
        try:
            vulns = process_vulnerabilities(doc_texts, llm, profile_config)
            all_vulnerabilities.extend(vulns)
        except Exception as e:
            print(f"[ERRO] Falha ao processar página {doc.metadata.get('page', '?')}: {e}")

    print(f"\n[SUMMARY] Total de chunks: {total_chunks}")
    print(f"[SUMMARY] Total de vulnerabilidades extraídas: {len(all_vulnerabilities)}")

    # Definir nome do arquivo como output ou baseado no PDF 
    if args.output:
        output_file = args.output
    else:
        pdf_base = os.path.splitext(os.path.basename(args.pdf_path))[0]
        output_file = f"{pdf_base}.json"

    if save_results(all_vulnerabilities, output_file, profile_config):
        xlsx_output_path = None
        try:
            converted_files = execute_conversions(output_file, args)
            if converted_files:
                print(f"\nConversões geradas: {len(converted_files)}")
                for c in converted_files:
                    print(f"  - {c}")
                    if c.endswith('.xlsx'):
                        xlsx_output_path = c
        except Exception as e:
            print(f"Erro ao executar conversões: {e}")

        # Etapa de avaliação de métricas
        if args.evaluate:
            if xlsx_output_path and os.path.isfile(xlsx_output_path):
                run_evaluation(args, xlsx_output_path)
            else:
                print("\n[AVISO] Avaliação de métricas pulada.")
                print("Motivo: A conversão para .xlsx não foi solicitada ou falhou.")
    else:
        print(f"\n[ERRO] Falha ao salvar resultados em {output_file}")


if __name__ == "__main__":
    main()