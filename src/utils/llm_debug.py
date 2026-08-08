"""Raw LLM response logging for debugging.

Writes append-only JSONL under
llm_debug_responses/{scenario}/{pdf_name}/{llm_name}/responses_*.jsonl.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import uuid


DEFAULT_DEBUG_DIR = "llm_debug_responses"

# One filename per (pdf, llm, scenario, dir) so a run appends to a single file
_session_files = {}


def ensure_debug_directory(pdf_name: str, llm_name: str, scenario: str = "default", 
                          debug_dir: str = DEFAULT_DEBUG_DIR) -> Path:
    """Create and return debug_dir/scenario/pdf_name/llm_name/."""
    debug_path = Path(debug_dir) / scenario / pdf_name / llm_name
    debug_path.mkdir(parents=True, exist_ok=True)
    return debug_path


def _get_session_filename(pdf_name: str, llm_name: str, scenario: str, debug_dir: str) -> Path:
    """Unique session filename (timestamp + UUID), created once and reused."""
    session_key = (pdf_name, llm_name, scenario, debug_dir)

    if session_key not in _session_files:
        debug_path = ensure_debug_directory(pdf_name, llm_name, scenario, debug_dir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        filename = f"responses_{timestamp}_{unique_id}.jsonl"
        _session_files[session_key] = debug_path / filename
    
    return _session_files[session_key]


def save_llm_response_debug(
    pdf_name: str,
    llm_name: str,
    chunk_idx: int,
    response_content: str,
    block_idx: int = 0,
    chunk_chars: int = 0,
    vulns_extracted: int = 0,
    recovered_via: Optional[str] = None,
    retry_count: int = 0,
    was_redivided: bool = False,
    parsing_success: bool = True,
    validation_success: bool = True,
    error_message: Optional[str] = None,
    prompt_tokens: int = 0,
    response_tokens: int = 0,
    likely_truncated: bool = False,
    scenario: str = "default",
    debug_dir: str = DEFAULT_DEBUG_DIR
) -> None:
    """Append one LLM response entry to the session JSONL file.

    chunk_idx is the sub-chunk index when redivided (0 for the main attempt);
    block_idx keeps traceability to the original block across redivisions.
    """
    try:
        responses_file = _get_session_filename(pdf_name, llm_name, scenario, debug_dir)

        entry = {
            "block_idx": block_idx,
            "chunk_idx": chunk_idx,
            "retry_count": retry_count,
            "was_redivided": was_redivided,
            "chunk_chars": chunk_chars,
            "prompt_tokens": prompt_tokens,
            "response_tokens": response_tokens,
            "vulns_extracted": vulns_extracted,
            "parsing_success": parsing_success,
            "validation_success": validation_success,
            "likely_truncated": likely_truncated,
            "recovered_via": recovered_via,
            "error_message": error_message,
            "raw_response": response_content,
        }

        with open(responses_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    except Exception:
        # Debug logging must never break the extraction run
        pass


def get_debug_response_path(pdf_name: str, llm_name: str, scenario: str = "default",
                           debug_dir: str = DEFAULT_DEBUG_DIR) -> Path:
    """Directory holding the responses_*.jsonl files for this PDF/LLM."""
    debug_path = ensure_debug_directory(pdf_name, llm_name, scenario, debug_dir)
    return debug_path


def load_debug_responses(pdf_name: str, llm_name: str, scenario: str = "default",
                        debug_dir: str = DEFAULT_DEBUG_DIR) -> list:
    """Load every logged response for this PDF/LLM across all session files."""
    debug_path = get_debug_response_path(pdf_name, llm_name, scenario, debug_dir)
    
    if not debug_path.exists():
        return []
    
    responses = []
    try:
        for responses_file in sorted(debug_path.glob("responses_*.jsonl")):
            with open(responses_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            responses.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except Exception as e:
        pass
    
    return responses


def get_debug_statistics(pdf_name: str, llm_name: str, scenario: str = "default",
                        debug_dir: str = DEFAULT_DEBUG_DIR) -> Dict[str, Any]:
    """Summary stats over the logged responses (counts, tokens, per-chunk)."""
    responses = load_debug_responses(pdf_name, llm_name, scenario, debug_dir)
    
    if not responses:
        return {
            'total_responses': 0,
            'successful': 0,
            'failed': 0,
            'redivided': 0,
            'avg_response_length': 0,
            'total_tokens': 0,
            'chunks': {}
        }
    
    total_responses = len(responses)
    successful = sum(1 for r in responses if r.get('parsing_success') and r.get('validation_success'))
    failed = sum(1 for r in responses if not (r.get('parsing_success') and r.get('validation_success')))
    redivided = sum(1 for r in responses if r.get('was_redivided'))
    
    total_response_length = sum(r.get('response_length', 0) for r in responses)
    avg_response_length = total_response_length / total_responses if total_responses > 0 else 0
    
    total_tokens = sum(r.get('prompt_tokens', 0) + r.get('response_tokens', 0) for r in responses)

    chunks = {}
    for r in responses:
        chunk_idx = r.get('chunk_idx', 0)
        if chunk_idx not in chunks:
            chunks[chunk_idx] = {'count': 0, 'retries': 0, 'success': False}
        chunks[chunk_idx]['count'] += 1
        chunks[chunk_idx]['retries'] = max(chunks[chunk_idx]['retries'], r.get('retry_count', 0))
        chunks[chunk_idx]['success'] = r.get('parsing_success') and r.get('validation_success')
    
    return {
        'total_responses': total_responses,
        'successful': successful,
        'failed': failed,
        'redivided': redivided,
        'avg_response_length': avg_response_length,
        'total_tokens': total_tokens,
        'chunks': chunks
    }
