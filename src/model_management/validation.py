"""LLM response validation: JSON parsing fallbacks, token limits, truncation."""

import json
import re
import tiktoken
from typing import Dict, Any, List, Optional

try:
    from json_repair import repair_json
    _HAS_JSON_REPAIR = True
except ImportError:
    _HAS_JSON_REPAIR = False
    print("[WARN] json-repair not installed in current env. "
          "Install with: pip install json-repair==0.59.5 "
          "(LLM JSON recovery will be limited)")

_CONCAT_ARRAY_RE = re.compile(r'\]\s*\[')


def parse_json_response(resposta, chunk_id="", return_strategy=False):
    """Extract the vulnerability list from an LLM response.

    Strategies tried in order: "direct" (raw json.loads), "bracket_slice"
    (first '[' to last ']'), "markdown_block" (```json fence), "prefix_strip"
    (drop leading prose), "concat_arrays" (merge `][` artifacts), "json_repair"
    (library fixer, last resort). With return_strategy=True returns
    (vulns, strategy_name), strategy None on failure.
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

    # bracket_slice also peels trailing `]` when the slice is unbalanced
    # (e.g. model emits `[...]\n]`)
    try:
        start = resposta.find('[')
        end = resposta.rfind(']') + 1
        if start != -1 and end > start:
            candidate = resposta[start:end]
            for _ in range(candidate.count(']') - candidate.count('[')):
                trim = candidate.rfind(']')
                if trim == -1:
                    break
                candidate = candidate[:trim].rstrip()
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, list):
                    return _result(parsed, "bracket_slice")
            except json.JSONDecodeError:
                parsed = json.loads(resposta[start:end])
                if isinstance(parsed, list):
                    return _result(parsed, "bracket_slice")
    except Exception:
        pass

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

    # concat_arrays: model emitted `[a][b][c]` instead of `[a,b,c]`
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
    """Validate the response JSON and token budget; returns a result dict.

    num_predict is the model's output cap: a response within 5% of it while
    the JSON is invalid is flagged likely_truncated, distinguishing truncation
    from plain syntax errors.
    """
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

    # Empty list `[]` is a VALID response (no vulns in this chunk); treating it
    # as failure causes wasteful redivision that can split and lose real vulns
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
    
    prompt_tokens = len(tokenizer.encode(prompt_template)) if prompt_template else 800
    chunk_tokens = len(tokenizer.encode(chunk_content))
    response_tokens = len(tokenizer.encode(response))
    total_tokens = prompt_tokens + chunk_tokens + response_tokens

    result['token_count'] = total_tokens

    # 500-token safety margin below the hard limit
    if total_tokens > (max_tokens - 500):
        result['token_valid'] = False
        result['errors'].append(f"Exceeds token limit: {total_tokens}/{max_tokens}")
        result['needs_redivision'] = True

    if not result['json_valid'] or not result['token_valid'] or chunk_tokens > (max_tokens * 0.6):
        result['needs_redivision'] = True

    if not result['json_valid']:
        if "..." in response or "truncated" in response.lower():
            result['errors'].append("Resposta truncada detectada")
        if response.count('[') != response.count(']'):
            result['errors'].append("JSON mal formado - colchetes desbalanceados")
        if response.count('{') != response.count('}'):
            result['errors'].append("JSON mal formado - chaves desbalanceadas")

    # Truncation is flagged only when JSON also failed: an intact JSON at the
    # cap is just a tight fit
    if num_predict and num_predict > 0 and not result['json_valid']:
        if response_tokens >= int(num_predict * 0.95):
            result['likely_truncated'] = True
            result['errors'].append(
                f"Response {response_tokens}/{num_predict} tokens (>=95% of num_predict cap) "
                f"AND JSON invalid, likely truncated. Consider bumping max_tokens or shrinking chunk."
            )

    return result
