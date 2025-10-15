import os
import sys
import argparse

# Adicionar src ao path para importar conversores
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Imports das dependências
from langchain_openai import ChatOpenAI
from langchain.text_splitter import CharacterTextSplitter, RecursiveCharacterTextSplitter
from langchain.schema import Document
import pdfplumber
import json
import datetime

# Importar conversores
from converters.csv_converter import CSVConverter, TSVConverter
from converters.xlsx_converter import XLSXConverter

def extract_visual_layout_from_pdf(pdf_path):
    """
    Extrai o layout visual EXATO do PDF usando pdfplumber em memória
    Preserva posicionamento, espaçamento e estrutura visual
    """
    print(f"Extraindo layout visual do PDF: {os.path.basename(pdf_path)}")
    
    try:
        with pdfplumber.open(pdf_path) as pdf:
            conteudo_visual_completo = ""
            
            print(f"Total de páginas encontradas: {len(pdf.pages)}")
            
            for num_pagina, pagina in enumerate(pdf.pages, 1):
                print(f"Processando página {num_pagina}...")
                
                # Configurações otimizadas para máxima preservação visual
                texto_pagina = pagina.extract_text(
                    layout=True,           # Preserva layout posicional
                    x_tolerance=1,         # Tolerância mínima horizontal (máxima precisão)
                    y_tolerance=1,         # Tolerância mínima vertical (máxima precisão)
                    keep_blank_chars=True  # Mantém espaços em branco
                )
                
                if texto_pagina:
                    # Preservar quebras de linha e espaçamento exatos
                    linhas = texto_pagina.split('\n')
                    texto_processado = ""
                    
                    for linha in linhas:
                        # Preservar espaços em branco exatos (não fazer strip)
                        # Converter tabs em espaços para melhor visualização
                        linha_preservada = linha.replace('\t', '    ')
                        texto_processado += linha_preservada + '\n'
                    
                    conteudo_visual_completo += texto_processado
                    
                    # Separação suave entre páginas (apenas quebra de linha extra)
                    conteudo_visual_completo += "\n"
                
                else:
                    # Marcar páginas sem texto de forma sutil
                    conteudo_visual_completo += f"[Página {num_pagina} - Sem texto detectado]\n\n"
            
            if not conteudo_visual_completo.strip():
                print("Aviso: Nenhum texto foi extraído do PDF. O arquivo pode estar corrompido ou ser apenas imagens.")
                return None
            
            # Retorna um objeto Document compatível com LangChain
            return [Document(page_content=conteudo_visual_completo.rstrip() + '\n', metadata={"source": pdf_path, "extraction_method": "pdfplumber_visual"})]
            
    except Exception as e:
        print(f"Erro ao extrair layout visual: {e}")
        return None

def load_pdf_with_pypdf2(pdf_path):
    """Função mantida para compatibilidade - agora usa extração visual"""
    return extract_visual_layout_from_pdf(pdf_path)

def save_visual_layout(content, pdf_path):
    """
    Salva o layout visual extraído em arquivo TXT para referência
    """
    base_name = os.path.splitext(os.path.basename(pdf_path))[0]
    output_visual_path = f"visual_layout_extracted_{base_name}.txt"
    
    try:
        with open(output_visual_path, 'w', encoding='utf-8') as f:
            # Cabeçalho informativo
            f.write(f"Layout Visual Extraído: {os.path.basename(pdf_path)}\n")
            f.write(f"Extraído em: {datetime.datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Conteúdo visual principal
            f.write(content)
        
        print(f"Layout visual salvo em: {output_visual_path}")
        return output_visual_path
    except Exception as e:
        print(f"Erro ao salvar layout visual: {e}")
        return None

def load_config(config_file="config.json"):
    """Carrega configurações do arquivo JSON"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Erro: Arquivo {config_file} não encontrado!")
        return None
    except Exception as e:
        print(f"Erro ao carregar {config_file}: {e}")
        return None

def parse_arguments():
    """Parse argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description='Extrai vulnerabilidades de relatórios PDF de segurança usando LLM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python main.py arquivo.pdf
  python main.py "C:\\path\\to\\arquivo.pdf"
  python main.py arquivo.pdf --config custom_config.json
  python main.py arquivo.pdf --convert csv
  python main.py arquivo.pdf --convert xlsx --output report.xlsx
  python main.py arquivo.pdf --convert all
        """
    )
    
    parser.add_argument('pdf_path', 
                        help='Caminho para o arquivo PDF a ser processado')
    
    parser.add_argument('--config', '-c',
                        default='config.json',
                        help='Arquivo de configuração JSON (padrão: config.json)')
    
    # Opções de conversão
    parser.add_argument('--convert',
                        choices=['csv', 'xlsx', 'tsv', 'all', 'none'],
                        default='none',
                        help='Converter saída JSON para formato específico (padrão: none)')
    
    parser.add_argument('--output', '-o',
                        help='Arquivo de saída para conversão (opcional)')
    
    parser.add_argument('--output-dir',
                        help='Diretório de saída para conversões múltiplas')
    
    parser.add_argument('--csv-delimiter',
                        default=',',
                        help='Delimitador para CSV (padrão: vírgula)')
    
    parser.add_argument('--csv-encoding',
                        default='utf-8-sig',
                        help='Codificação do arquivo CSV (padrão: utf-8-sig)')
    
    return parser.parse_args()

def remove_duplicates_by_name(vulnerabilities):
    """Remove duplicatas baseadas no campo 'name'"""
    seen_names = set()
    unique_vulnerabilities = []
    
    for vulnerability in vulnerabilities:
        # Verificar se é um dicionário e tem o campo 'name'
        if isinstance(vulnerability, dict) and 'name' in vulnerability:
            name = vulnerability['name']
            if name not in seen_names:
                seen_names.add(name)
                unique_vulnerabilities.append(vulnerability)
        else:
            # Manter itens que não são dicionários ou não têm 'name'
            unique_vulnerabilities.append(vulnerability)
    
    return unique_vulnerabilities

def execute_conversions(json_file_path, args):
    """
    Executa conversões baseadas nos argumentos fornecidos
    
    Args:
        json_file_path: Caminho para o arquivo JSON
        args: Argumentos da linha de comando
    """
    if args.convert == 'none':
        return []
    
    print(f"\n=== CONVERSÃO DE FORMATOS ===")
    converted_files = []
    
    try:
        if args.convert == 'all':
            # Converter para todos os formatos
            formats = ['csv', 'tsv', 'xlsx']
            for format_type in formats:
                try:
                    result = convert_single_format(json_file_path, format_type, args)
                    if result:
                        converted_files.append(result)
                except Exception as e:
                    print(f"Erro ao converter para {format_type.upper()}: {e}")
        else:
            # Converter para formato específico
            result = convert_single_format(json_file_path, args.convert, args)
            if result:
                converted_files.append(result)
    
    except Exception as e:
        print(f"Erro durante conversões: {e}")
    
    return converted_files

def convert_single_format(json_file_path, format_type, args):
    """
    Converte para um formato específico
    
    Args:
        json_file_path: Caminho para o arquivo JSON
        format_type: Tipo de formato ('csv', 'xlsx', 'tsv')
        args: Argumentos da linha de comando
        
    Returns:
        Caminho do arquivo convertido ou None
    """
    try:
        # Determinar arquivo de saída
        if args.output and args.convert != 'all':
            output_file = args.output
        else:
            base_name = os.path.splitext(os.path.basename(json_file_path))[0]
            if args.output_dir:
                output_file = os.path.join(args.output_dir, f"{base_name}_converted.{format_type}")
            else:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"{base_name}_converted_{timestamp}.{format_type}"
        
        # Criar conversor apropriado
        if format_type == 'csv':
            converter = CSVConverter(
                delimiter=args.csv_delimiter,
                encoding=args.csv_encoding,
                include_metadata=False  # Não criar arquivo separado de metadados
            )
        elif format_type == 'tsv':
            converter = TSVConverter(encoding=args.csv_encoding, include_metadata=False)
        elif format_type == 'xlsx':
            converter = XLSXConverter()
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
        
        # Executar conversão
        result = converter.convert(json_file_path, output_file)
        print(f"{format_type.upper()}: {result}")
        return result
        
    except ImportError as e:
        if format_type == 'xlsx':
            print(f"XLSX não disponível: {e}")
            print("   Instale: pip install pandas openpyxl")
        else:
            print(f"Erro de importação para {format_type.upper()}: {e}")
        return None
    except Exception as e:
        print(f" Erro ao converter para {format_type.upper()}: {e}")
        return None

def main():
    # Parse argumentos da linha de comando
    args = parse_arguments()
    
    # Verificar se o arquivo PDF existe
    if not os.path.isfile(args.pdf_path):
        print(f"Erro: Arquivo PDF não encontrado: {args.pdf_path}")
        print("Verifique se o caminho está correto.")
        return
    
    # Carregar configurações do config.json
    config = load_config(args.config)
    if config is None:
        return
    
    # ===== CONFIGURAÇÕES DO LLM - VEM DO CONFIG.JSON =====
    api_key = config['api_key']
    endpoint = config['endpoint']
    model = config['model']
    temperature = config['temperature']
    max_tokens = config['max_tokens']
    chunk_size = config['chunk_size']
    chunk_overlap = config['chunk_overlap']
    separator = config.get('separator', '\n\n')  # Default para \n\n se não especificado
    output_file = config['output_file']
    # ====================================================
        
    # Configure a API key
    os.environ["OPENAI_API_KEY"] = api_key
    
    # Configurar o modelo LLM usando ChatOpenAI corretamente
    llm = ChatOpenAI(
        model=model,
        temperature=temperature,
        base_url=endpoint,
        max_tokens=max_tokens,
        timeout=60
    )
    
    print(f"Arquivo PDF: {args.pdf_path}")
    print(f"Usando modelo: {model}")
    print(f"Endpoint: {endpoint}")
    
    # Configurar o divisor de texto - usando RecursiveCharacterTextSplitter para melhor agrupamento
    text_splitter = RecursiveCharacterTextSplitter(
        separators=["\n\n\n\n", "\n\n\n", "\n\n", "\n", " ", ""],
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
    )
    
    print(f"Usando RecursiveCharacterTextSplitter:")
    print(f"  - chunk_size: {chunk_size}")
    print(f"  - chunk_overlap: {chunk_overlap}")
    print(f"  - separators: múltiplos níveis para agrupamento otimizado")
    
    try:
        print("=== EXTRAÇÃO VISUAL E PROCESSAMENTO DE VULNERABILIDADES ===")
        print("Carregando o PDF com extração visual máxima...")
        documents = load_pdf_with_pypdf2(args.pdf_path)
        
        if documents is None:
            print("Falha ao carregar o PDF. Verifique se o arquivo não está corrompido.")
            return
        
        # Salvar o layout visual extraído para referência
        visual_content = documents[0].page_content
        visual_file = save_visual_layout(visual_content, args.pdf_path)
        
        print("Dividindo o texto visual em chunks...")
        doc_texts = text_splitter.split_documents(documents)
        
        print(f"Texto dividido em {len(doc_texts)} chunks")
        print("Processando layout visual para extrair vulnerabilidades...")
        
        # Lista para acumular todos os JSONs
        all_vulnerabilities = []
        
        # Iterar por todos os chunks do documento
        for i, doc_chunk in enumerate(doc_texts):
            print(f"Processando chunk {i+1}/{len(doc_texts)}...")
            
            try:
                # Create optimized prompt for preserved visual layout
                prompt = f"""Analyze this security report with preserved visual layout and extract vulnerabilities in JSON format:

REPORT CONTENT:
{doc_chunk.page_content}

REQUIRED JSON FORMAT (USE EXACTLY THESE FIELDS ONLY):
[{{"name":"...", "Synopsis":"...", "Description":"...", "Plugin Output":"...", "Solution":"...", "See Also":"...", "CVSSv3":"...", "CVSSv4":"...", "Risk":"..."}}]

INSTRUCTIONS:
1. Extract ONLY real security vulnerabilities
2. Use visual layout to identify structured sections  
3. Use ONLY the 9 fields shown above - no additional fields
4. Put severity information in the "Risk" field
5. Put CWE codes in the "Description" or "See Also" fields
6. If no vulnerabilities found, return []

IMPORTANT: Return ONLY valid JSON with exactly the fields shown above.

JSON:"""
                
                # Para ChatOpenAI, use invoke() e acesse .content
                resposta = llm.invoke(prompt).content
                
                # Tentar fazer parse do JSON retornado
                try:
                    vulnerabilities_chunk = json.loads(resposta)
                    if isinstance(vulnerabilities_chunk, list):
                        all_vulnerabilities.extend(vulnerabilities_chunk)
                        print(f"  Encontradas {len(vulnerabilities_chunk)} vulnerabilidades no chunk {i+1}")
                    else:
                        print(f"  Resposta não é uma lista válida no chunk {i+1}")
                except json.JSONDecodeError:
                    # Tentar extrair JSON da resposta se não estiver limpo
                    try:
                        start = resposta.find('[')
                        end = resposta.rfind(']') + 1
                        if start != -1 and end > start:
                            json_str = resposta[start:end]
                            vulnerabilities_chunk = json.loads(json_str)
                            all_vulnerabilities.extend(vulnerabilities_chunk)
                            print(f"  Extraídas {len(vulnerabilities_chunk)} vulnerabilidades no chunk {i+1}")
                    except:
                        print(f"  Não foi possível extrair JSON válido do chunk {i+1}")
                
            except Exception as e:
                if 'quota' in str(e).lower() or '429' in str(e):
                    print(f"  Limite de quota atingido no chunk {i+1}. Parando processamento.")
                    break
                else:
                    print(f"  Erro ao processar chunk {i+1}: {e}")
        
        print(f"\nRemovendo duplicatas baseadas no campo 'name'...")
        original_count = len(all_vulnerabilities)
        all_vulnerabilities = remove_duplicates_by_name(all_vulnerabilities)
        final_count = len(all_vulnerabilities)
        duplicates_removed = original_count - final_count
        
        print(f"Duplicatas removidas: {duplicates_removed}")
        print(f"Vulnerabilidades únicas: {final_count}")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_vulnerabilities, f, indent=2, ensure_ascii=False)
            
            print(f"\n=== PROCESSAMENTO CONCLUÍDO ===")
            print(f"Layout visual extraído e salvo: {visual_file if visual_file else 'Erro ao salvar'}")
            print(f"Total original de vulnerabilidades: {original_count}")
            print(f"Duplicatas removidas: {duplicates_removed}")
            print(f"Vulnerabilidades únicas salvas: {final_count}")
            print(f"Arquivo JSON de vulnerabilidades: {output_file}")
            print(f"Método de extração: pdfplumber visual layout")
            
            # Executar conversões se solicitado
            if args.convert != 'none':
                converted_files = execute_conversions(output_file, args)
                if converted_files:
                    print(f"\n=== CONVERSÕES CONCLUÍDAS ===")
                    print(f"Arquivos convertidos: {len(converted_files)}")
                    for file_path in converted_files:
                        print(f"{file_path}")
                else:
                    print(f"\nNenhuma conversão foi concluída com sucesso")
            
        except Exception as e:
            print(f"Erro ao salvar arquivo JSON: {e}")
            return  # Não tentar conversões se JSON falhou
        
    except FileNotFoundError:
        print(f"Erro: Arquivo PDF não encontrado no caminho: {args.pdf_path}")
        print("Verifique se o arquivo existe e o caminho está correto.")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    main()