"""
PDF Vulnerability Extractor - Main Entry Point

Extrai vulnerabilidades de relatórios PDF (OpenVAS/Tenable WAS) usando LLM
e converte para formatos estruturados (JSON/CSV/XLSX).

Usage:
    python main.py <pdf_path> [--LLM <model>] [--convert <format>]
"""

import os
import sys
import argparse
import json
from tqdm import tqdm

# Adicionar src ao path para imports locais
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

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


def parse_arguments() -> argparse.Namespace:
    """Parse argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Extrai vulnerabilidades de relatórios PDF usando LLM'
    )
    parser.add_argument('pdf_path', help='Caminho para o arquivo PDF')
    parser.add_argument('--profile', default='default', 
                       help='Perfil de configuração (padrão: default)')
    parser.add_argument('--LLM', default='gpt4', 
                       help='Nome do LLM a usar (padrão: gpt4)')
    
    # Opções de conversão
    parser.add_argument('--convert', choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                       default='none',
                       help='Converter saída JSON para formato específico (padrão: none)')
    parser.add_argument('--output', help='Caminho do arquivo de saída para conversão')
    parser.add_argument('--output-dir', dest='output_dir',
                       help='Diretório de saída para arquivos convertidos')
    parser.add_argument('--csv-delimiter', dest='csv_delimiter', default=',',
                       help='Delimitador para CSV (padrão: ,)')
    parser.add_argument('--csv-encoding', dest='csv_encoding', default='utf-8-sig',
                       help='Codificação para CSV (padrão: utf-8-sig)')
    
    return parser.parse_args()


def validate_inputs(args: argparse.Namespace) -> bool:
    """Valida inputs do usuário."""
    if not os.path.isfile(args.pdf_path):
        print(f"Erro: Arquivo PDF não encontrado: {args.pdf_path}")
        return False
    return True


def load_configs(args: argparse.Namespace) -> tuple:
    """Carrega configurações de perfil e LLM."""
    profile_config = load_profile(args.profile)
    if not profile_config:
        print(f"Erro ao carregar perfil: {args.profile}")
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
                # Validate vulnerabilities based on profile type
                validator = get_validator(profile_config)
                validated_vulns = [
                    validator(v)
                    for v in vulns_chunk
                    if validator(v)
                ]
                
                # Determine name field from profile or auto-detect
                name_field = get_consolidation_field(validated_vulns, profile_config)
                
                all_vulnerabilities.extend(validated_vulns)
                names = [v.get(name_field) for v in validated_vulns if isinstance(v, dict) and v.get(name_field)]
                
                print(f"[LOG] Chunk {i+1}/{len(doc_texts)}: {len(validated_vulns)}/{len(vulns_chunk)} vulnerabilidades extraídas")
                if names:
                    print(f"[NOMES]")
                    for idx, name in enumerate(names, 1):
                        print(f"  {idx:2d}. {name}")
            else:
                print(f"[LOG] Chunk {i+1}/{len(doc_texts)}: 0 vulnerabilidades")
                
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


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None) -> bool:
    """
    Salva vulnerabilidades em JSON.
    Consolida duplicatas para Tenable WAS.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        output_file: Caminho do arquivo de saída
        profile_config: Configuração do perfil (opcional)
    
    Returns:
        True se sucesso, False caso contrário
    """
    try:
        has_tenable = any(
            v.get('source') == 'TENABLEWAS' 
            for v in vulnerabilities 
            if isinstance(v, dict)
        )
        
        if has_tenable:
            print(f"\nConsolidando vulnerabilidades duplicadas (Tenable WAS)...")
            final_vulns = consolidate_duplicates(vulnerabilities)
            print(f"Total: {len(vulnerabilities)} → {len(final_vulns)} após consolidação")
        else:
            print(f"\nSem consolidação (OpenVAS) - {len(vulnerabilities)} vulnerabilidades")
            final_vulns = vulnerabilities
        
        # Detectar campo de consolidação do profile ou auto-detectar
        name_field = get_consolidation_field(final_vulns, profile_config)
        
        unique_names = sorted(set(v.get(name_field, 'SEM NOME') for v in final_vulns if isinstance(v, dict)))
        print(f"\nTotal de vulnerabilidades únicas: {len(unique_names)}")
        print(f"\nResumo de vulnerabilidades encontradas:")
        for idx, name in enumerate(unique_names, 1):
            count = sum(1 for v in final_vulns if isinstance(v, dict) and v.get(name_field) == name)
            print(f"  {idx:3d}. [{count:2d}x] {name}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)
        
        print(f"Vulnerabilidades salvas em: {output_file}")
        return True
        
    except Exception as e:
        print(f"Erro ao salvar JSON: {e}")
        return False


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
    max_tokens = llm_config.get('max_tokens', 4096)
    reserve_response = llm_config.get('reserve_for_response', 1000)
    
    print(f"\n{'='*60}")
    print(f"[CONFIG] LLM: {llm_config.get('model')}")
    print(f"[CONFIG] Max tokens: {max_tokens}")
    print(f"[CONFIG] Reserve para resposta: {reserve_response}")
    print(f"{'='*60}\n")
    
    # Carregamento do PDF
    documents = load_pdf_with_pypdf2(args.pdf_path)
    if not documents:
        print("Erro: Falha ao carregar PDF")
        return
    
    visual_file = save_visual_layout(documents[0].page_content, args.pdf_path)
    print(f"Layout visual salvo em: {visual_file}\n")
    
    # Divisão em chunks e processamento
    doc_texts = get_token_based_chunks(
        documents[0].page_content,
        max_tokens,
        reserve_response
    )
    print(f"Total de chunks: {len(doc_texts)}\n")
    
    all_vulnerabilities = process_vulnerabilities(doc_texts, llm, profile_config)
    
    # Salvar resultados e conversões
    output_file = profile_config['output_file']
    if save_results(all_vulnerabilities, output_file, profile_config):
        try:
            converted = execute_conversions(output_file, args)
            if converted:
                print(f"\nConversões geradas: {len(converted)}")
                for c in converted:
                    print(f"  - {c}")
        except Exception as e:
            print(f"Erro ao executar conversões: {e}")


if __name__ == "__main__":
    main()