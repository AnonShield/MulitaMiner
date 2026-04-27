"""
JSON response validation and error detection for LLM outputs.

Provides robust validation of LLM responses, including:
- JSON parsing with multiple fallback strategies
- Token counting and limit validation
- Error detection and redivision determination
"""

import json
import re
import tiktoken
from typing import Dict, Any, List, Optional

try:
    from json_repair import repair_json
    _HAS_JSON_REPAIR = True
except ImportError:
    _HAS_JSON_REPAIR = False

_CONCAT_ARRAY_RE = re.compile(r'\]\s*\[')


def parse_json_response(resposta, chunk_id="", return_strategy=False):
    """
    Parse JSON response from LLM with flexible handling.

    Tries multiple strategies to extract valid JSON, in order:
    - "direct"          → json.loads on the raw response
    - "bracket_slice"   → slice between first '[' and last ']'
    - "markdown_block"  → content of ```json ... ``` fence
    - "prefix_strip"    → drop leading prose ("Here is...", "Based on...")
    - "concat_arrays"   → merge `][` artifacts into a single array
    - "json_repair"     → json-repair library (last-resort fixer)

    Args:
        resposta: Response string from LLM.
        chunk_id: ID for logging purposes.
        return_strategy: When True, returns (vulns, strategy_name). The strategy
            is None if parsing failed. Default False keeps the original API.

    Returns:
        list of vulns, or (list, strategy_name) when return_strategy=True.
    """
    def _result(vulns, strategy):
        return (vulns, strategy) if return_strategy else vulns

    # Strategy: direct
    try:
        parsed = json.loads(resposta)
        if isinstance(parsed, list):
            return _result(parsed, "direct")
        if isinstance(parsed, dict) and "vulnerabilities" in parsed:
            vulns = parsed.get("vulnerabilities", [])
            return _result(vulns if isinstance(vulns, list) else [], "direct")
        if isinstance(parsed, dict):
            for key in parsed:
                if isinstance(parsed[key], list) and parsed[key]:
                    first_item = parsed[key][0]
                    if isinstance(first_item, dict) and "Name" in first_item:
                        return _result(parsed[key], "direct")
            return _result([], "direct")
    except json.JSONDecodeError:
        pass

    # Strategy: bracket_slice — first `[` to last `]`
    try:
        start = resposta.find('[')
        end = resposta.rfind(']') + 1
        if start != -1 and end > start:
            parsed = json.loads(resposta[start:end])
            if isinstance(parsed, list):
                return _result(parsed, "bracket_slice")
    except Exception:
        pass

    # Strategy: markdown_block — ```json ... ```
    try:
        code_start = resposta.find('```json')
        if code_start != -1:
            code_start += len('```json')
            code_end = resposta.find('```', code_start)
            if code_end != -1:
                parsed = json.loads(resposta[code_start:code_end].strip())
                if isinstance(parsed, list):
                    return _result(parsed, "markdown_block")
    except Exception:
        pass

    # Strategy: prefix_strip — drop "Here is..." / "Based on..." prefixes
    try:
        cleaned = resposta.strip()
        if cleaned.startswith('Here') or cleaned.startswith('Based'):
            idx = cleaned.find('[')
            if idx != -1:
                cleaned = cleaned[idx:]
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return _result(parsed, "prefix_strip")
    except Exception:
        pass

    # Strategy: concat_arrays — model emitted `[a][b][c]` instead of `[a,b,c]`
    try:
        start = resposta.find('[')
        end = resposta.rfind(']') + 1
        if start != -1 and end > start and _CONCAT_ARRAY_RE.search(resposta[start:end]):
            candidate = _CONCAT_ARRAY_RE.sub(',', resposta[start:end])
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                print(f"[WARN{chunk_id}] Recovered {len(parsed)} vulns via concat_arrays fallback")
                return _result(parsed, "concat_arrays")
    except Exception:
        pass

    # Strategy: json_repair — last-resort recovery for malformed JSON
    if _HAS_JSON_REPAIR:
        try:
            parsed = repair_json(resposta, return_objects=True)
            if isinstance(parsed, list) and parsed:
                print(f"[WARN{chunk_id}] Recovered {len(parsed)} vulns via json_repair")
                return _result(parsed, "json_repair")
            if isinstance(parsed, dict):
                if "vulnerabilities" in parsed and isinstance(parsed["vulnerabilities"], list):
                    vulns = parsed["vulnerabilities"]
                    print(f"[WARN{chunk_id}] Recovered {len(vulns)} vulns via json_repair (wrapped)")
                    return _result(vulns, "json_repair")
                for key in parsed:
                    if isinstance(parsed[key], list) and parsed[key]:
                        first = parsed[key][0]
                        if isinstance(first, dict) and "Name" in first:
                            print(f"[WARN{chunk_id}] Recovered {len(parsed[key])} vulns via json_repair (key={key})")
                            return _result(parsed[key], "json_repair")
        except Exception:
            pass

    print(f"[WARN{chunk_id}] No parsing strategy could extract valid JSON")
    return _result([], None)


def validate_json_and_tokens(response: str, chunk_content: str, max_tokens: int,
                             prompt_template: str = "", tokenizer=None,
                             num_predict: Optional[int] = None) -> Dict[str, Any]:
    """
    Validate LLM response JSON and check token limits.

    Args:
        response: Response string from LLM
        chunk_content: Original chunk content sent to LLM
        max_tokens: Maximum tokens allowed for this chunk (input budget)
        prompt_template: Template prompt used (for token counting)
        tokenizer: Tokenizer object (tiktoken or HuggingFace). If None, uses tiktoken fallback.
        num_predict: Model's output token cap (mapped from llm_config.max_tokens). When the
            response lands within 5% of this cap AND the JSON is invalid, likely_truncated
            is flagged so truncation can be distinguished from format/syntax errors.

    Returns:
        dict with validation results:
        - json_valid (bool): Whether response is valid JSON
        - json_data (list): Parsed JSON data if valid
        - token_valid (bool): Whether token count is within limits
        - token_count (int): Total tokens used
        - errors (list): List of error messages
        - needs_redivision (bool): Whether chunk should be redivided
        - likely_truncated (bool): Response hit the output cap (diagnostic only)
    """
    # Use provided tokenizer or create fallback
    if tokenizer is None:
        try:
            tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except Exception:
            tokenizer = tiktoken.get_encoding("cl100k_base")

    result = {
        'json_valid': False,
        'json_data': None,
        'token_valid': True,
        'token_count': 0,
        'errors': [],
        'needs_redivision': False,
        'likely_truncated': False,
        'recovered_via': None,
    }

    # 1. JSON VALIDATION
    # Empty list `[]` is a VALID response — the LLM legitimately found no vulns
    # in this chunk. Treating it as failure causes wasteful redivision and may
    # split real vulnerabilities across sub-chunks, losing them entirely.
    try:
        json_data, strategy = parse_json_response(response, return_strategy=True)
        result['recovered_via'] = strategy
        if isinstance(json_data, list):
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

    # 5. TRUNCATION DETECTION (diagnostic): response hit the num_predict cap
    # Flagged only when JSON also failed — an intact JSON at cap is just a tight fit.
    if num_predict and num_predict > 0 and not result['json_valid']:
        if response_tokens >= int(num_predict * 0.95):
            result['likely_truncated'] = True
            result['errors'].append(
                f"Response {response_tokens}/{num_predict} tokens (>=95% of num_predict cap) "
                f"AND JSON invalid — likely truncated. Consider bumping max_tokens or shrinking chunk."
            )

    return result
