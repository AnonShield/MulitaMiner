import os
import sys
import argparse

def check_dependencies():
    """Verifica se todas as dependências estão instaladas"""
    required_packages = {
        'langchain_openai': 'langchain-openai',
        'langchain_community': 'langchain-community', 
        'langchain': 'langchain',
        'unstructured': 'unstructured[pdf]'
    }
    
    missing_packages = []
    for package, install_name in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(install_name)
    
    if missing_packages:
        print("Dependências faltando:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nInstale com: pip install " + " ".join(missing_packages))
        return False
    return True

try:
    from langchain_openai import ChatOpenAI
    from langchain_community.document_loaders import UnstructuredPDFLoader
    from langchain.text_splitter import CharacterTextSplitter
    from langchain.chains.summarize import load_summarize_chain
    import json
except ImportError as e:
    print(f"Erro ao importar dependências: {e}")
    print("Execute: pip install langchain langchain-openai langchain-community unstructured[pdf]")
    sys.exit(1)

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
        """
    )
    
    parser.add_argument('pdf_path', 
                        help='Caminho para o arquivo PDF a ser processado')
    
    parser.add_argument('--config', '-c',
                        default='config.json',
                        help='Arquivo de configuração JSON (padrão: config.json)')
    
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

def main():
    # Parse argumentos da linha de comando
    args = parse_arguments()
    
    # Verificar dependências primeiro
    if not check_dependencies():
        return
    
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
    
    # Configurar o divisor de texto
    text_splitter = CharacterTextSplitter(        
        separator = "\n\n",
        chunk_size = chunk_size,
        chunk_overlap = chunk_overlap,
        length_function = len,
    )
    
    try:
        print("Carregando o PDF...")
        loader = UnstructuredPDFLoader(args.pdf_path)  # Usa o path da linha de comando
        documents = loader.load()
        
        print("Dividindo o texto em chunks...")
        doc_texts = text_splitter.split_documents(documents)
        
        print("Processando todo o texto para extrair vulnerabilidades...")
        
        # Lista para acumular todos os JSONs
        all_vulnerabilities = []
        
        # Iterar por todos os chunks do documento
        for i, doc_chunk in enumerate(doc_texts):
            print(f"Processando chunk {i+1}/{len(doc_texts)}...")
            
            try:
                # Criar prompt para extrair vulnerabilidades do chunk atual
                prompt = f"""Extract security vulnerabilities from the following text in JSON format:

                            Text:
                            {doc_chunk.page_content}

                            Required JSON format: 
                            [{{"name":"...", "plugin_id":"...", "Description":"...", "severity":"...", "solution":"...","Risk Information":"...","Reference Information":"..."}}, ...]

                            Rules:
                            1. Extract ONLY actual security vulnerabilities
                            2. Include all available fields
                            3. Use exact field names as shown
                            4. Return valid JSON array
                            5. If no vulnerabilities found, return []

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
                    #print(f"  Erro ao decodificar JSON no chunk {i+1}, tentando extrair...")
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
            print(f"Total original de vulnerabilidades: {original_count}")
            print(f"Duplicatas removidas: {duplicates_removed}")
            print(f"Vulnerabilidades únicas salvas: {final_count}")
            print(f"Arquivo salvo: {output_file}")
            
        except Exception as e:
            print(f"Erro ao salvar arquivo JSON: {e}")
        
    except FileNotFoundError:
        print(f"Erro: Arquivo PDF não encontrado no caminho: {args.pdf_path}")
        print("Verifique se o arquivo existe e o caminho está correto.")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    main()