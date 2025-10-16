import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import argparse
from utils.utils import (
    load_profile, load_llm, init_llm, load_prompt, save_visual_layout,
    merge_vulnerabilities_deepmerge, execute_conversions, convert_single_format
)
# Imports das dependências
from langchain_openai import ChatOpenAI
import json
from tqdm import tqdm
import datetime
# Import utilitário do divisor de texto
from src.utils.text_splitter import get_text_splitter
# Importar conversores
from converters.csv_converter import CSVConverter, TSVConverter
from converters.xlsx_converter import XLSXConverter

from utils.pdf_loader import extract_visual_layout_from_pdf, load_pdf_with_pypdf2




def parse_arguments():
    """Parse argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description='Extrai vulnerabilidades de relatórios PDF de segurança usando LLM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python main.py arquivo.pdf
  python main.py "C:\\path\\to\\arquivo.pdf"
  python main.py arquivo.pdf --convert csv
  python main.py arquivo.pdf --convert xlsx --output report.xlsx
  python main.py arquivo.pdf --convert all
        """
    )
    parser.add_argument('--profile',
                        default='tenable',
                        help='Nome do perfil de configuração a ser usado (padrão: tenable)')
    
    parser.add_argument('pdf_path', 
                        help='Caminho para o arquivo PDF a ser processado')
    
    
    # Opções de conversão
    parser.add_argument('--convert',
                        choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                        default='none',
                        help='Converter saída JSON para formato específico (padrão: none)')
    
    # Argumentos essenciais
    parser.add_argument('--LLM',
                        default='gpt4',
                        help='Modelo LLM a ser usado (ex: gpt4, gemini, llama)')
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

def process_vulnerabilities(doc_texts, llm, profile_config):
    all_vulnerabilities = []
    total_chunks = len(doc_texts)
    for i, doc_chunk in enumerate(tqdm(doc_texts, desc="Processando chunks", unit="chunk")):
        prompt = build_prompt(doc_chunk, profile_config)
        try:
            resposta = llm.invoke(prompt).content
            try:
                vulnerabilities_chunk = json.loads(resposta)
                if isinstance(vulnerabilities_chunk, list):
                    all_vulnerabilities.extend(vulnerabilities_chunk)
                else:
                    print(f"Resposta não é uma lista válida no chunk {i+1}")
            except json.JSONDecodeError:
                start = resposta.find('[')
                end = resposta.rfind(']') + 1
                if start != -1 and end > start:
                    json_str = resposta[start:end]
                    vulnerabilities_chunk = json.loads(json_str)
                    all_vulnerabilities.extend(vulnerabilities_chunk)
                else:
                    print(f"Não foi possível extrair JSON válido do chunk {i+1}")
        except Exception as e:
            if 'quota' in str(e).lower() or '429' in str(e):
                print(f"Limite de quota atingido no chunk {i+1}. Parando processamento.")
                break
            else:
                print(f"Erro ao processar chunk {i+1}: {e}")
    return all_vulnerabilities

def save_results(all_vulnerabilities, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_vulnerabilities, f, indent=2, ensure_ascii=False)
        print(f"Processamento concluído. Vulnerabilidades salvas em: {output_file}")
        return True
    except Exception as e:
        print(f"Erro ao salvar arquivo JSON: {e}")
        return False

def handle_conversions(output_file, args, visual_file):
    print(f"Layout visual salvo em: {visual_file if visual_file else 'Erro ao salvar'}")

def main():
    args = parse_arguments()
    if not validate_pdf_path(args.pdf_path):
        return
    profile_config, llm_config = get_configs(args)
    if not profile_config or not llm_config:
        return
    llm = init_llm(llm_config)
    chunk_size = profile_config.get('chunk_size', 2000)
    chunk_overlap = profile_config.get('chunk_overlap', 200)
    output_file = profile_config['output_file']
    separator = profile_config.get('separator', None)
    default_separators = ["\n\n\n\n", "\n\n\n", "\n\n", "\n"]
    if separator:
        separators = [separator] + default_separators
    else:
        separators = default_separators
    text_splitter = get_text_splitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap, separators=separators)
    documents = load_pdf_with_pypdf2(args.pdf_path)
    if documents is None:
        print("Falha ao carregar o PDF. Verifique se o arquivo não está corrompido.")
        return
    visual_file = save_visual_layout(documents[0].page_content, args.pdf_path)
    doc_texts = text_splitter.split_documents(documents)
    print(f"Total de chunks a processar: {len(doc_texts)}")
    all_vulnerabilities = process_vulnerabilities(doc_texts, llm, profile_config)
    all_vulnerabilities = merge_vulnerabilities_deepmerge(all_vulnerabilities)
    if save_results(all_vulnerabilities, output_file):
        handle_conversions(output_file, args, visual_file)

if __name__ == "__main__":
    main()