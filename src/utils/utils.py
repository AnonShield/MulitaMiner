import datetime
from converters.csv_converter import CSVConverter, TSVConverter
from deepmerge import Merger

def execute_conversions(json_file_path, args):
    """
    Executa conversões baseadas nos argumentos fornecidos
    """
    if args.convert == 'none':
        return []
    print(f"\n=== CONVERSÃO DE FORMATOS ===")
    converted_files = []
    if args.convert == 'all':
        formats = ['csv', 'tsv']
        for format_type in formats:
            try:
                result = convert_single_format(json_file_path, format_type, args)
                if result:
                    converted_files.append(result)
            except Exception as e:
                print(f"Erro ao converter para {format_type.upper()}: {e}")
    else:
        result = convert_single_format(json_file_path, args.convert, args)
        if result:
            converted_files.append(result)
    return converted_files

def convert_single_format(json_file_path, format_type, args):
    """
    Converte para um formato específico
    """
    try:
        if args.output and args.convert != 'all':
            output_file = args.output
        else:
            base_name = os.path.splitext(os.path.basename(json_file_path))[0]
            if args.output_dir:
                output_file = os.path.join(args.output_dir, f"{base_name}_converted.{format_type}")
            else:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"{base_name}_converted_{timestamp}.{format_type}"
        if format_type == 'csv':
            converter = CSVConverter(
                delimiter=args.csv_delimiter,
                encoding=args.csv_encoding,
                include_metadata=False
            )
        elif format_type == 'tsv':
            converter = TSVConverter(encoding=args.csv_encoding, include_metadata=False)
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
        result = converter.convert(json_file_path, output_file)
        print(f"{format_type.upper()}: {result}")
        return result
    except Exception as e:
        print(f" Erro ao converter para {format_type.upper()}: {e}")
        return None
def remove_duplicates_by_name(vulnerabilities):
    """Remove duplicatas baseadas no campo 'name'"""
    seen_names = set()
    unique_vulnerabilities = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            unique_vulnerabilities.append(vulnerability)
            continue

        # Normalizar: se a entrada usar 'name' em minúsculas, converte para 'Name'
        if 'name' in vulnerability and 'Name' not in vulnerability:
            vulnerability['Name'] = vulnerability.pop('name')

        if 'Name' in vulnerability:
            name = vulnerability['Name']
            if name not in seen_names:
                seen_names.add(name)
                unique_vulnerabilities.append(vulnerability)
        else:
            # Se não houver campo name/Name, mantém o item, mas avisa
            unique_vulnerabilities.append(vulnerability)
    return unique_vulnerabilities
import datetime

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
import os
import json
from langchain_openai import ChatOpenAI

def load_profile(profile_name):
    path = f"src/configs/Profile/{profile_name}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_llm(llm_name):
    path = f"src/configs/LLMs/{llm_name}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def init_llm(llm_config):
    os.environ["OPENAI_API_KEY"] = llm_config["api_key"]
    return ChatOpenAI(
        model=llm_config["model"],
        temperature=llm_config["temperature"],
        base_url=llm_config["endpoint"],
    )

def load_prompt(prompt):
    if os.path.isfile(prompt):
        with open(prompt, "r", encoding="utf-8") as f:
            return f.read()
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    rel_path = os.path.join(project_root, prompt)
    if os.path.isfile(rel_path):
        with open(rel_path, "r", encoding="utf-8") as f:
            return f.read()
    return prompt


# Estratégia: para listas, une; para dicts, faz merge; para outros, mantém o valor mais longo


merger = Merger(
    [(list, "append"), (dict, "merge")],
    ["override"],
    ["override"]
)

def merge_vulnerabilities_deepmerge(vuln_list):
    merged = {}
    for vuln in vuln_list:
        # Aceita tanto 'Name' quanto 'name' e normaliza para 'Name'
        if not isinstance(vuln, dict):
            continue

        if 'Name' not in vuln and 'name' in vuln:
            vuln['Name'] = vuln.pop('name')

        name = vuln.get("Name")
        if name is None:
            # Ignorar ou usar uma representação fallback
            continue
        if name not in merged:
            merged[name] = vuln.copy()
        else:
            merged[name] = merger.merge(merged[name], vuln)
    return list(merged.values())
