"""
LLM Debug Response Logging Module

Provides functionality to capture and save raw LLM responses for debugging purposes.
Maintains a modular structure with JSONL format for efficient storage and analysis.

Directory structure:
    llm_debug_responses/
    ├── {scenario}/{pdf_name}/{llm_name}/
    │   ├── responses.jsonl       (append-only log of responses)
    │   └── metadata.json         (summary of processing)
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import uuid


DEFAULT_DEBUG_DIR = "llm_debug_responses"

# Cache for session-specific filenames (stores one per pdf/llm/scenario combination)
_session_files = {}


def ensure_debug_directory(pdf_name: str, llm_name: str, scenario: str = "default", 
                          debug_dir: str = DEFAULT_DEBUG_DIR) -> Path:
    """
    Create debug directory structure if it doesn't exist.
    
    Structure:
        debug_dir/scenario/pdf_name/llm_name/
    
    Args:
        pdf_name: Name of the PDF being processed (without extension)
        llm_name: Name of the LLM model
        scenario: Scenario/context name (default: "default")
        debug_dir: Root debug directory name
    
    Returns:
        Path to the debug directory for this PDF/LLM combination
    """
    debug_path = Path(debug_dir) / scenario / pdf_name / llm_name
    debug_path.mkdir(parents=True, exist_ok=True)
    return debug_path


def _get_session_filename(pdf_name: str, llm_name: str, scenario: str, debug_dir: str) -> Path:
    """
    Get or create a unique session filename (timestamp + UUID).
    Generated once per pdf/llm/scenario combination and reused for all responses.
    """
    session_key = (pdf_name, llm_name, scenario, debug_dir)
    
    if session_key not in _session_files:
        debug_path = ensure_debug_directory(pdf_name, llm_name, scenario, debug_dir)
        # Generate session file ONCE with timestamp + UUID
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
    """
    Save LLM response to JSONL file for debugging.

    Each response is appended as a separate JSON line, allowing for:
    - Efficient append-only operations
    - Memory-efficient parsing of large files
    - Easy filtering and analysis of specific chunks

    Args:
        pdf_name: PDF file name (without extension)
        llm_name: LLM model name
        chunk_idx: Index of the chunk within the PDF (sub-chunk index when
            redivided; 0 for the main chunk attempt).
        response_content: Raw response text from LLM
        block_idx: Index of the original PDF block this chunk belongs to,
            for traceability across redivisions.
        chunk_chars: Length (in characters) of the chunk text sent to the LLM.
            Distinct from response length; useful to spot oversized inputs.
        vulns_extracted: Number of vulnerabilities recovered from the response
            after JSON parsing (0 when parsing failed or response was empty).
        recovered_via: Identifier of the parsing strategy that succeeded
            (e.g. "direct", "markdown_block", "concat_arrays", "json_repair").
            None when parsing failed entirely.
        retry_count: Number of retries for this chunk
        was_redivided: Whether chunk was subdivided due to failure
        parsing_success: Whether JSON parsing succeeded
        validation_success: Whether validation passed
        error_message: Error message if operation failed (None if successful)
        prompt_tokens: Number of tokens in the prompt
        response_tokens: Number of tokens in the response
        likely_truncated: Response hit the model's output cap
        scenario: Processing scenario/context name
        debug_dir: Root debug directory name

    Returns:
        None
    """
    try:
        # Use session-specific filename (generated once, reused for all responses)
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

        # Append to JSONL file (one JSON object per line)
        with open(responses_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    except Exception:
        # Silently fail to avoid breaking main processing
        pass


def get_debug_response_path(pdf_name: str, llm_name: str, scenario: str = "default",
                           debug_dir: str = DEFAULT_DEBUG_DIR) -> Path:
    """
    Get the path to debug responses files (returns directory containing matching files).
    Note: Multiple timestamped files may exist in the directory.
    
    Args:
        pdf_name: PDF file name
        llm_name: LLM model name
        scenario: Processing scenario name
        debug_dir: Root debug directory name
    
    Returns:
        Path to debug directory (contains responses_*.jsonl files)
    """
    debug_path = ensure_debug_directory(pdf_name, llm_name, scenario, debug_dir)
    return debug_path


def load_debug_responses(pdf_name: str, llm_name: str, scenario: str = "default",
                        debug_dir: str = DEFAULT_DEBUG_DIR) -> list:
    """
    Load all debug responses for a specific PDF/LLM combination.
    Reads all responses_*.jsonl files in the debug directory.
    
    Args:
        pdf_name: PDF file name
        llm_name: LLM model name
        scenario: Processing scenario name
        debug_dir: Root debug directory name
    
    Returns:
        List of response dictionaries (empty list if directory doesn't exist)
    """
    debug_path = get_debug_response_path(pdf_name, llm_name, scenario, debug_dir)
    
    if not debug_path.exists():
        return []
    
    responses = []
    try:
        # Read all responses_*.jsonl files in the directory
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
    """
    Analyze debug responses and return statistics.
    
    Args:
        pdf_name: PDF file name
        llm_name: LLM model name
        scenario: Processing scenario name
        debug_dir: Root debug directory name
    
    Returns:
        Dictionary with statistics:
        {
            'total_responses': int,
            'successful': int,
            'failed': int,
            'redivided': int,
            'avg_response_length': float,
            'total_tokens': int,
            'chunks': list
        }
    """
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
    
    # Group by chunk_idx
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
