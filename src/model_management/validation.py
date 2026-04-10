"""
JSON response validation and error detection for LLM outputs.

Provides robust validation of LLM responses, including:
- JSON parsing with multiple fallback strategies
- Token counting and limit validation
- Error detection and redivision determination
"""

import json
import tiktoken
from typing import Dict, Any, List


def parse_json_response(resposta, chunk_id=""):
    """
    Parse JSON response from LLM with flexible handling.
    
    Tries multiple strategies to extract valid JSON:
    1. Direct JSON parse
    2. Extract from wrapped dict with "vulnerabilities" key
    3. Extract from markdown code blocks
    4. Extract any JSON array from text
    
    Args:
        resposta: Response string from LLM
        chunk_id: ID for logging purposes
    
    Returns:
        list: Parsed vulnerabilities list, or empty list if parsing failed
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


def validate_json_and_tokens(response: str, chunk_content: str, max_tokens: int, 
                             prompt_template: str = "", tokenizer=None) -> Dict[str, Any]:
    """
    Validate LLM response JSON and check token limits.
    
    Args:
        response: Response string from LLM
        chunk_content: Original chunk content sent to LLM
        max_tokens: Maximum tokens allowed for this chunk
        prompt_template: Template prompt used (for token counting)
        tokenizer: Tokenizer object (tiktoken or HuggingFace). If None, uses tiktoken fallback.
    
    Returns:
        dict with validation results:
        - json_valid (bool): Whether response is valid JSON
        - json_data (list): Parsed JSON data if valid
        - token_valid (bool): Whether token count is within limits
        - token_count (int): Total tokens used
        - errors (list): List of error messages
        - needs_redivision (bool): Whether chunk should be redivided
    """
    # Use provided tokenizer or create fallback
    if tokenizer is None:
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
