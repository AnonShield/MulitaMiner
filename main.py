"""
PDF Vulnerability Extractor - Main Entry Point

Extrai vulnerabilidades de relatórios PDF (OpenVAS/Tenable WAS) usando LLM
e converte para formatos estruturados (JSON/CSV/XLSX).

Usage:
    python main.py <pdf_path> [--LLM <model>] [--convert <format>] [--scanner <name>]
"""
import os
from src.utils.block_creation import create_session_blocks_from_text, extract_vulns_from_blocks, cleanup_temp_blocks

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
import datetime
from tqdm import tqdm
from src.utils.cli_args import parse_arguments
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from src.utils.cli_args import parse_arguments

# Force UTF-8 encoding on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')



from src.utils.llm_utils import (
    load_profile, load_llm, init_llm, validate_and_normalize_vulnerability
)
from src.utils.convertions import execute_conversions
from src.utils.cais_validator import validate_cais_vulnerability
from src.utils.pdf_loader import load_pdf_with_pypdf2, save_visual_layout
from src.utils.chunking import get_token_based_chunks, retry_chunk_with_subdivision
from src.scanner_strategies.consolidation import central_custom_allow_duplicates
from src.utils.profile_registry import is_cais_profile


def get_validator(profile_config: dict):
    """Obter validador apropriado baseado no perfil."""
    if is_cais_profile(profile_config):
        return validate_cais_vulnerability
    return validate_and_normalize_vulnerability


def validate_inputs(args: argparse.Namespace) -> bool:
    """Valida inputs do usuário."""
    if not os.path.isfile(args.pdf_path):
        print(f"❌ Erro: Arquivo PDF não encontrado: {args.pdf_path}")
        return False
    # Validação para o modo de avaliação
    if args.evaluate:
        if not args.baseline:
            print("❌ Erro: O argumento --baseline é obrigatório quando --evaluate é usado.")
            return False
        if not os.path.isfile(args.baseline):
            print(f"❌ Erro: Arquivo de baseline não encontrado: {args.baseline}")
            return False
        if args.convert not in ['xlsx', 'all']:
            print("⚠️ Aviso: Para avaliação, a conversão para '.xlsx' é necessária. Ativando a conversão para 'all'.")
            args.convert = 'all'
    return True


def load_configs(args: argparse.Namespace) -> tuple:
    """Carrega configurações de perfil e LLM."""
    profile_config = load_profile(args.scanner)
    if not profile_config:
        print(f"❌ Erro ao carregar perfil: {args.scanner}")
        return None, None
    llm_config = load_llm(args.LLM)
    if not llm_config:
        print(f"❌ Erro ao carregar LLM: {args.LLM}")
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
    total_chunks = len(doc_texts)
    
    with tqdm(total=total_chunks, desc="Processando chunks", unit="chunk", ncols=80) as pbar:
      for i, doc_chunk in enumerate(doc_texts):
        tqdm.write(f"\n{'='*60}")
        tqdm.write(f"🔹 Processando chunk {i+1}/{total_chunks}")
        tqdm.write(f"{'='*60}")
        try:
            vulns_chunk = retry_chunk_with_subdivision(doc_chunk, llm, profile_config, max_retries)
            if vulns_chunk:
                validator = get_validator(profile_config)
                validated_vulns = []
                for v in vulns_chunk:
                    validated = validator(v)
                    if validated:
                        validated_vulns.append(validated)
                name_field = get_consolidation_field(validated_vulns, profile_config)
                all_vulnerabilities.extend(validated_vulns)
                names = [v.get(name_field) for v in validated_vulns if isinstance(v, dict) and v.get(name_field)]
                tqdm.write(f"✅ [CHUNK {i+1}] {len(validated_vulns)}/{len(vulns_chunk)} vulnerabilidades válidas extraídas.")
                if names:
                    tqdm.write(f"   📋 Nomes extraídos:")
                    for idx, name in enumerate(names, 1):
                        tqdm.write(f"     {idx:2d}. {name}")
            else:
                tqdm.write(f"⚠️ [CHUNK {i+1}] Nenhuma vulnerabilidade extraída.")
        except Exception as e:
            error_msg = str(e).lower()
            if any(kw in error_msg for kw in ['quota', '429', 'rate limit', 'timeout', 'connection']):
                tqdm.write(f"\n🛑 [ERRO CRÍTICO] {type(e).__name__}: {str(e)[:200]}")
                tqdm.write(f"⏹️ Parando processamento no chunk {i+1}/{total_chunks}")
                break
            else:
                tqdm.write(f"\n❌ [ERRO] {type(e).__name__}: {str(e)[:200]}")
                tqdm.write(f"➡️  Continuando com próximo chunk...")
        pbar.update(1)
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


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None, allow_duplicates: bool = False) -> bool:
    """
    Salva vulnerabilidades em JSON.
    
    Args:
        vulnerabilities: Lista de vulnerabilidades
        output_file: Caminho do arquivo de saída
        profile_config: Configuração do perfil (opcional)
    
    Returns:
        True se sucesso, False caso contrário
    """
    try:
        previous_vulns = load_previous_vulnerabilities(output_file)
        removed_log_path = os.path.join(os.path.dirname(output_file), os.path.splitext(os.path.basename(output_file))[0] + '_removed_log.txt')
        merge_log_path = os.path.join(os.path.dirname(output_file), os.path.splitext(os.path.basename(output_file))[0] + '_merge_log.txt')
        duplicates_removed_log_path = os.path.join(
            os.path.dirname(output_file),
            os.path.splitext(os.path.basename(output_file))[0] + '_duplicates_removed_log.txt'
        )
        print(f"\n🔄 Processando deduplicação/consolidação (allow_duplicates={allow_duplicates})...")
        final_vulns = central_custom_allow_duplicates(vulnerabilities, profile_config, allow_duplicates, output_file=output_file)
        print(f"📊 Total: {len(vulnerabilities)} → {len(final_vulns)} após deduplicação/consolidação")
        # O campo de consolidação agora é definido internamente pelas estratégias/scanners
        name_field = 'Name'  # Fallback para exibição
        if final_vulns and isinstance(final_vulns[0], dict):
            for k in ['name_consolidated', 'definition.name', 'Name']:
                if k in final_vulns[0]:
                    name_field = k
                    break
        new_vulns = []
        updated_vulns = []
        repeated_vulns = []
        for v in final_vulns:
            if isinstance(v, dict):
                name = v.get(name_field, 'SEM NOME')
                if name in previous_vulns:
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
        if not allow_duplicates:
            unique_names = sorted(set(str(v.get(name_field, 'SEM NOME') or 'SEM NOME') for v in final_vulns if isinstance(v, dict)))
            print(f"\n📋 Total de vulnerabilidades únicas: {len(unique_names)}")
            print(f"\n📋 Resumo de vulnerabilidades encontradas:")
            for idx, name in enumerate(unique_names, 1):
                count = sum(1 for v in final_vulns if isinstance(v, dict) and (str(v.get(name_field, 'SEM NOME') or 'SEM NOME') == name))
                print(f"  {idx:3d}. [{count:2d}x] {name}")
        else:
            print(f"\n📋 Total de vulnerabilidades: {len(final_vulns)}")
            print(f"  - 🆕 NOVAS: {len(new_vulns)}")
            print(f"  - 🔄 ATUALIZADAS: {len(updated_vulns)}")
            print(f"  - ♻️ REPETIDAS (sem mudança): {len(repeated_vulns)}")
            if new_vulns:
                print(f"\n🆕 Vulnerabilidades NOVAS encontradas:")
                for idx, v in enumerate(new_vulns, 1):
                    if isinstance(v, dict):
                        name = str(v.get(name_field, 'SEM NOME') or 'SEM NOME')
                        severity = str(v.get('severity', 'UNKNOWN') or 'UNKNOWN')
                        print(f"  {idx:3d}. [NOVO     ] [{severity:8s}] {name}")
            if updated_vulns:
                print(f"\n🔄 Vulnerabilidades ATUALIZADAS:")
                for idx, v in enumerate(updated_vulns, 1):
                    if isinstance(v, dict):
                        name = str(v.get(name_field, 'SEM NOME') or 'SEM NOME')
                        severity = str(v.get('severity', 'UNKNOWN') or 'UNKNOWN')
                        print(f"  {idx:3d}. [ATUALIZADO] [{severity:8s}] {name}")
            if repeated_vulns:
                print(f"\n♻️ Vulnerabilidades REPETIDAS (sem mudança): {len(repeated_vulns)}")
        # Filtra vulnerabilidades sem descrição válida antes de salvar
        def has_valid_description(vuln):
            desc = vuln.get("description")
            if not desc:
                return False
            if isinstance(desc, list):
                return any(str(d).strip() for d in desc)
            return bool(str(desc).strip())

        removed_vulns = [v for v in final_vulns if not has_valid_description(v)]
        final_vulns = [v for v in final_vulns if has_valid_description(v)]
        # Salva log das vulnerabilidades removidas
        if removed_vulns:
            log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'
            with open(log_path, 'w', encoding='utf-8') as logf:
                logf.write(
                    "# LOG DE REMOÇÃO DE VULNERABILIDADES\n"
                    "Este arquivo lista todas as vulnerabilidades removidas por falta de descrição válida.\n"
                    "Cada item apresenta detalhes relevantes para rastreabilidade.\n\n"
                )
                logf.write(f"Total de vulnerabilidades removidas: {len(removed_vulns)}\n\n")
                for idx, v in enumerate(removed_vulns, 1):
                    name = str(v.get('Name', 'SEM NOME'))
                    port = str(v.get('port', ''))
                    protocol = str(v.get('protocol', ''))
                    severity = str(v.get('severity', ''))
                    logf.write(f"{idx}. Nome: {name}\n")
                    logf.write(f"   Porta: {port} | Protocolo: {protocol} | Severidade: {severity}\n")
                    desc = v.get('description', '')
                    if desc:
                        if isinstance(desc, list):
                            desc = ' '.join([str(d) for d in desc if d])
                        desc = str(desc).strip().replace('\n', ' ')
                        logf.write(f"   Descrição original (inválida): {desc[:200]}{'...' if len(desc)>200 else ''}\n")
                    logf.write("\n")
                logf.write(f"Resumo final: {len(removed_vulns)} vulnerabilidades removidas por falta de descrição válida.\n")
            print(f"\n🗑 Log de vulnerabilidades removidas salvo em: {log_path}")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Vulnerabilidades salvas em: {output_file}")
        return True
    except Exception as e:
        print(f"❌ Erro ao salvar JSON: {e}")
        return False


def run_evaluation(args: argparse.Namespace, extraction_output_path: str):
    """
    Executa o script de avaliação de métricas como um processo separado.
    
    Args:
        args: Argumentos da linha de comando, contendo --baseline e --evaluation-method.
        extraction_output_path: Caminho para o arquivo .xlsx gerado pela extração.
    """
    print(f"\n{'='*60}")
    print(f"📊 Iniciando avaliação de métricas com o método: '{args.evaluation_method}'")
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
        '--baseline-file', args.baseline,
        '--extraction-file', extraction_output_path,
        '--output-dir', output_dir
    ]
    # Passa o nome do modelo explicitamente se disponível
    if hasattr(args, 'LLM') and args.LLM:
        command += ['--model', args.LLM]

    # Passa configuração de duplicatas se especificada
    if hasattr(args, 'allow_duplicates') and args.allow_duplicates:
        command += ['--allow-duplicates']
    
    try:
        print(f"⚙️ Executando comando: {' '.join(command)}")
        subprocess.run(command, check=True)
        print(f"\n✅ [SUCESSO] Avaliação de métricas concluída.")
        print(f"📁 Resultados salvos no diretório: '{output_dir}'")
    except FileNotFoundError:
        print(f"❌ Erro: Python ou o script '{script_path}' não foi encontrado.")
        print("Verifique se o ambiente virtual de 'metrics' está configurado corretamente.")
    except subprocess.CalledProcessError as e:
        print("\n❌ [ERRO] A avaliação de métricas falhou.")
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
    print(f"🖼️  Layout visual salvo em: {visual_file}\n")



    # Novo fluxo: gerar texto completo de extração
    extraction_text = ''
    for doc in documents:
        if doc.metadata.get("extraction_method") == "pdfplumber_visual_EXTRACTION":
            extraction_text += doc.page_content + '\n'

    # Criar blocos de sessão temporários
    session_blocks = create_session_blocks_from_text(
        extraction_text,
        temp_dir='temp_blocks',
        visual_layout_path=visual_file,
        scanner=args.scanner
    )
    print(f"📦 [INFO] {len(session_blocks)} blocos de sessão criados em temp_blocks/")

    # Processar cada bloco com chunking e extração, propagando contexto
    all_vulnerabilities = extract_vulns_from_blocks(
        session_blocks, llm, profile_config, get_token_based_chunks
    )
    total_chunks = len(session_blocks)

    # Limpeza obrigatória dos temporários
    cleanup_temp_blocks('temp_blocks')

    print(f"\n{'='*60}")
    print(f"📊 [SUMMARY] Total de blocos: {total_chunks}")
    print(f"📊 [SUMMARY] Total de vulnerabilidades extraídas: {len(all_vulnerabilities)}")
    print(f"{'='*60}")

    # Definir prefixo dos arquivos de saída
    run_prefix = os.environ.get("RUN_PREFIX")
    if args.output:
        output_file = args.output
        merge_log_file = args.output.replace('.json', '_merge_log.txt')
        removed_log_file = args.output.replace('.json', '_removed_log.txt')
        xlsx_file = args.output.replace('.json', '.xlsx')
    else:
        pdf_base = os.path.splitext(os.path.basename(args.pdf_path))[0]
        llm_name = getattr(args, 'LLM', None) or llm_config.get('model', 'unknown')
        llm_name = str(llm_name).replace('/', '_').replace(':', '_')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if getattr(args, 'run_experiments', False) or run_prefix:
            output_dir = getattr(args, 'output_dir', None) or 'results_runs'
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            prefix = run_prefix if run_prefix else f"{pdf_base}_{llm_name}_{timestamp}"
            output_file = os.path.join(output_dir, f"{prefix}.json")
            merge_log_file = os.path.join(output_dir, f"{prefix}_merge_log.txt")
            removed_log_file = os.path.join(output_dir, f"{prefix}_removed_log.txt")
            xlsx_file = os.path.join(output_dir, f"{prefix}.xlsx")
        else:
            output_file = f"{pdf_base}_{llm_name}_{timestamp}.json"

    if save_results(all_vulnerabilities, output_file, profile_config, getattr(args, 'allow_duplicates', False)):
        xlsx_output_path = None
        # Salva tokens_info se existir (gerado por extract_vulns_from_blocks)
        import glob, shutil
        os.makedirs('results_tokens', exist_ok=True)
        # Procura tokens_info gerado pelo PID atual
        pid = os.getpid()
        tokens_candidates = glob.glob(f'results_tokens/tokens_info_{pid}.json')
        if tokens_candidates:
            # Renomeia para bater com o nome do output_file
            tokens_final = os.path.join('results_tokens', os.path.splitext(os.path.basename(output_file))[0] + '_tokens.json')
            shutil.move(tokens_candidates[0], tokens_final)
            print(f"[TOKENS] Arquivo de tokens salvo em: {tokens_final}")
        try:
            converted_files = execute_conversions(output_file, args)
            if converted_files:
                print(f"\n🔄 Conversões geradas: {len(converted_files)}")
                for c in converted_files:
                    print(f"  📄 {c}")
                    if c.endswith('.xlsx'):
                        xlsx_output_path = c
        except Exception as e:
            print(f"❌ Erro ao executar conversões: {e}")
        if args.evaluate:
            if xlsx_output_path and os.path.isfile(xlsx_output_path):
                run_evaluation(args, xlsx_output_path)
            else:
                print("\n⚠️ [AVISO] Avaliação de métricas pulada.")
                print("Motivo: A conversão para .xlsx não foi solicitada ou falhou.")
    else:
        print(f"\n❌ [ERRO] Falha ao salvar resultados em {output_file}")


if __name__ == "__main__":
    main()