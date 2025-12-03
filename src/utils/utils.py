import os
import json
import re
import datetime
import sys

# Ensure imports work from src/ context
_current_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_current_dir)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from converters.csv_converter import CSVConverter, TSVConverter
from langchain_openai import ChatOpenAI

def parse_json_response(resposta, chunk_id=""):
    """
    Parse JSON response from LLM with flexible handling.
    Tries multiple strategies to extract valid JSON.
    
    Strategies:
    1. Direct JSON parse
    2. Extract from wrapped dict with "vulnerabilities" key
    3. Extract from markdown code blocks
    4. Extract any JSON array
    """
    try:
        # Strategy 1: Direct JSON parse
        parsed = json.loads(resposta)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict) and "vulnerabilities" in parsed:
            # Handle wrapped response
            vulns = parsed.get("vulnerabilities", [])
            return vulns if isinstance(vulns, list) else []
        elif isinstance(parsed, dict):
            # Try to extract list from dict
            for key in parsed:
                if isinstance(parsed[key], list) and len(parsed[key]) > 0:
                    first_item = parsed[key][0]
                    if isinstance(first_item, dict) and "Name" in first_item:
                        return parsed[key]
            return []
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Extract JSON from markdown/text
    try:
        start = resposta.find('[')
        end = resposta.rfind(']') + 1
        if start != -1 and end > start:
            json_str = resposta[start:end]
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                return parsed
    except Exception:
        pass
    
    # Strategy 3: Extract JSON code block
    try:
        code_start = resposta.find('```json')
        if code_start != -1:
            code_start += len('```json')
            code_end = resposta.find('```', code_start)
            if code_end != -1:
                json_str = resposta[code_start:code_end].strip()
                parsed = json.loads(json_str)
                if isinstance(parsed, list):
                    return parsed
    except Exception:
        pass
    
    # Strategy 4: Look for any JSON array
    try:
        # Remove common prefixes
        cleaned = resposta.strip()
        if cleaned.startswith('Here') or cleaned.startswith('Based'):
            # Skip intro text, find first [
            idx = cleaned.find('[')
            if idx != -1:
                cleaned = cleaned[idx:]
        
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    
    print(f"[WARN{chunk_id}] Nenhuma estratégia de parse conseguiu extrair JSON válido")
    return []

def validate_and_normalize_vulnerability(vuln):
    """
    Validate and normalize a single vulnerability object.
    Ensures all required fields exist with correct types.
    Removes invalid vulnerabilities (missing Name, wrong types, etc).
    """
    if not isinstance(vuln, dict):
        return None
    
    # Required fields with their expected types
    required_structure = {
        "Name": str,
        "description": list,
        "detection_result": list,
        "detection_method": list,
        "impact": list,
        "solution": list,
        "insight": list,
        "product_detection_result": list,
        "log_method": list,
        "cvss": list,
        "port": (type(None), int, str),
        "protocol": (type(None), str),
        "severity": str,
        "references": list,
        "plugin": list,
        "identification": list,
        "http_info": list,
        "source": str,
    }
    
    # Normalize fields
    for field, expected_type in required_structure.items():
        if field not in vuln:
            # Set default value based on type
            if expected_type == list:
                vuln[field] = []
            elif expected_type == str:
                vuln[field] = ""
            elif expected_type == int:
                vuln[field] = None
            elif expected_type == (type(None), int, str):
                vuln[field] = None
            continue
        
        # Validate and fix type
        value = vuln[field]
        if expected_type == list and not isinstance(value, list):
            if value is None:
                vuln[field] = []
            elif isinstance(value, str):
                vuln[field] = [value] if value.strip() else []
            else:
                vuln[field] = [value]
        elif expected_type == str and not isinstance(value, str):
            vuln[field] = str(value) if value is not None else ""
        elif isinstance(expected_type, tuple) and not isinstance(value, expected_type):
            vuln[field] = None
    
    # Validate Name is not empty
    if not vuln.get("Name") or not str(vuln.get("Name")).strip():
        return None
    
    return vuln

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
        max_tokens=llm_config.get("max_tokens", 4096),
        timeout=llm_config.get("timeout", 120),
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



