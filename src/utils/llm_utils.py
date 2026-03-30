import os
import json
import re
import sys
import tiktoken
from typing import Dict, Any

# Ensure imports work from src/ context
_current_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_current_dir)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

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
    
    print(f"[WARN{chunk_id}] No parsing strategy could extract valid JSON")
    return []

def validate_json_and_tokens(response: str, chunk_content: str, max_tokens: int, prompt_template: str = "") -> Dict[str, Any]:
    """
    Valida resposta JSON e verifica limites de tokens.
    
    Args:
        response: Resposta da LLM
        chunk_content: Conteúdo do chunk
        max_tokens: Máximo de tokens permitido
        prompt_template: Template do prompt usado
    
    Returns:
        Dict com resultado da validação: {
            'json_valid': bool,
            'json_data': list/None,
            'token_valid': bool,
            'token_count': int,
            'errors': list,
            'needs_redivision': bool
        }
    """
    try:
        tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
    except:
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    result = {
        'json_valid': False,
        'json_data': None,
        'token_valid': True,
        'token_count': 0,
        'errors': [],
        'needs_redivision': False
    }
    
    # 1. JSON VALIDATION
    try:
        # Try to extract JSON from response
        json_data = parse_json_response(response)
        if json_data and isinstance(json_data, list):
            result['json_valid'] = True
            result['json_data'] = json_data
        else:
            result['errors'].append("Invalid JSON or not a list")
    except Exception as e:
        result['errors'].append(f"Error parsing JSON: {str(e)}")
    
    # 2. TOKEN VALIDATION
    # Calculate tokens of complete prompt (template + chunk + overhead)
    prompt_tokens = len(tokenizer.encode(prompt_template)) if prompt_template else 800
    chunk_tokens = len(tokenizer.encode(chunk_content))
    response_tokens = len(tokenizer.encode(response))
    total_tokens = prompt_tokens + chunk_tokens + response_tokens
    
    result['token_count'] = total_tokens
    
    # Check if exceeds limit (leave margin of 500 tokens)
    if total_tokens > (max_tokens - 500):
        result['token_valid'] = False
        result['errors'].append(f"Exceeds token limit: {total_tokens}/{max_tokens}")
        result['needs_redivision'] = True
    
    # 3. DETECT REDIVISION NECESSITY
    # If invalid JSON OR exceeds tokens OR chunk too large
    if not result['json_valid'] or not result['token_valid'] or chunk_tokens > (max_tokens * 0.6):
        result['needs_redivision'] = True
    
    # 4. ANALYZE SPECIFIC JSON ERRORS
    if not result['json_valid']:
        if "..." in response or "truncated" in response.lower():
            result['errors'].append("Resposta truncada detectada")
        if response.count('[') != response.count(']'):
            result['errors'].append("JSON mal formado - colchetes desbalanceados")
        if response.count('{') != response.count('}'):
            result['errors'].append("JSON mal formado - chaves desbalanceadas")
    
    return result

def validate_and_normalize_vulnerability(vuln):
    """
    Validate and normalize a single vulnerability object.
    Ensures all required fields exist with correct types.
    Removes invalid vulnerabilities (missing Name, wrong types, etc).
    
    CRITICAL: Rejects vulnerabilities with invalid names (metadata, headings, etc)
    CRITICAL FIX: Validates that INSTANCES vulnerabilities have "Instances (N)" in Name
    """
    if not isinstance(vuln, dict):
        return None
    
    # REJECT invalid name patterns - metadata or index entries
    name = vuln.get("Name", "").strip()
    
    # Reject "VULNERABILITY ... PLUGIN ID ..." pattern (these are metadata, not vulnerability names)
    if re.match(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO|LOG)\s+PLUGIN\s+ID\s+\d+', name, re.IGNORECASE):
        return None
    
    # Reject if name is empty
    if not name:
        return None
    
    # CRITICAL FIX: Check if this should be an INSTANCES vulnerability
    # If it has identification array with URLs, it should have "Instances" in name
    identification = vuln.get('identification', [])
    has_urls = any(isinstance(u, str) and (u.startswith('http://') or u.startswith('https://')) for u in identification)
    
    if has_urls and 'Instances' not in name:
        # This has URLs (typical of INSTANCES) but lacks "Instances" in name
        # This is likely the prompt returning incomplete Name
        # We can try to fix it if we have HTTP info to count instances
        http_info = vuln.get('http_info', [])
        count = len(identification) if identification else len(http_info) if http_info else 0
        
        if count > 0:
            # Try to infer: append "Instances (N)" to the name
            vuln['Name'] = f"{name} Instances ({count})"
        else:
            # Can't determine count, reject as malformed
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
    
    # Map "Info" severity to "LOG" (per SECTION B of prompt)
    if vuln.get("severity", "").upper() == "INFO":
        vuln["severity"] = "LOG"
    
    return vuln

def load_profile(profile_name):
    path = f"src/configs/scanners/{profile_name}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_llm(llm_name):
    import re
    from dotenv import load_dotenv
    load_dotenv()
    path = f"src/configs/llms/{llm_name}.json"
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    # Replace environment variables in format ${NAME}
    for k, v in config.items():
        if isinstance(v, str):
            match = re.fullmatch(r"\$\{([A-Z0-9_]+)\}", v)
            if match:
                env_var = match.group(1)
                config[k] = os.getenv(env_var, "")
    return config

def init_llm(llm_config):
    os.environ["OPENAI_API_KEY"] = llm_config["api_key"]
    
    # Ensure that temperature is not None
    temperature = llm_config.get("temperature", 1.0)
    if temperature is None:
        temperature = 1.0
    temperature = float(temperature)
    
    # Resolver max_tokens/max_completion_tokens
    max_tokens = None
    if "max_completion_tokens" in llm_config:
        max_tokens = llm_config["max_completion_tokens"]
    elif "max_tokens" in llm_config:
        max_tokens = llm_config["max_tokens"]
    else:
        max_tokens = 4096
    
    if max_tokens is None:
        max_tokens = 4096
    max_tokens = int(max_tokens)
    
    # LangChain ChatOpenAI: max_completion_tokens vai em model_kwargs
    kwargs = {
        "model": llm_config["model"],
        "temperature": temperature,
        "base_url": llm_config["endpoint"],
        "timeout": llm_config.get("timeout", 120),
        "model_kwargs": {
            "max_completion_tokens": max_tokens,
        }
    }
    
    llm = ChatOpenAI(**kwargs)
    
    # PRESERVE CUSTOM CONFIGURATIONS IN LLM OBJECT
    # Do not set max_tokens directly - conflicts with max_completion_tokens
    # Removido llm.llm_config - causava ValueError com ChatOpenAI
    
    return llm



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