import tiktoken
import re
from typing import List, Dict, Any
from src.model_management import parse_json_response, load_prompt, validate_json_and_tokens, get_tokenizer
import unicodedata
import os
from tqdm import tqdm

class TokenChunk:
    """Simple wrapper for text chunk with content."""
    def __init__(self, page_content: str):
        self.page_content = page_content


def get_token_based_chunks(text: str, max_tokens: int,
                           reserve_for_response: int = 1000,
                           tokenizer=None,
                           llm_config: dict = None,
                           profile_config: dict = None) -> List[TokenChunk]:
    # Validação: se reserve_for_response >= max_tokens, ajusta os valores
    if reserve_for_response >= max_tokens:
        original_reserve = reserve_for_response
        reserve_for_response = max(100, int(max_tokens * 0.2))  # 20% de margem
        tqdm.write(f"⚠️  [CHUNKING] reserve_for_response ({original_reserve}) >= max_tokens ({max_tokens}). "
                   f"Adjusted to {reserve_for_response} to ensure valid chunk_size.")

    if tokenizer is None:
        try:
            tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except:
            tokenizer = tiktoken.get_encoding("cl100k_base")

    chunks = []
    tokens = tokenizer.encode(text)
    chunk_size = max_tokens - reserve_for_response
    start = 0
    while start < len(tokens):
        end = min(start + chunk_size, len(tokens))
        # Ensure standard list before decode - avoids errors with arrays/tensors
        chunk_tokens = list(tokens[start:end])
        chunk_text = tokenizer.decode(chunk_tokens)
        chunks.append(TokenChunk(chunk_text))
        start = end
    return chunks

def validate_base_instances_pairs(vulnerabilities: List[Dict]) -> List[Dict]:
    valid_pairs = []
    for vuln in vulnerabilities:
        if isinstance(vuln, dict):
            base = vuln.get('Name')
            instances = vuln.get('identification')
            if base and instances:
                valid_pairs.append(vuln)
    return valid_pairs

def build_prompt(doc_chunk: TokenChunk, profile_config: Dict[str, Any]) -> str:
    prompt_template = profile_config.get('prompt_template', '') if profile_config else ''
    # If it's a file path, load content
    if os.path.isfile(prompt_template):
        prompt_template = load_prompt(prompt_template)
    
    from .processing import sanitize_unicode_text
    sanitized_content = sanitize_unicode_text(doc_chunk.page_content)
    
    if "{context}" in prompt_template:
        return prompt_template.replace("{context}", sanitized_content)
    else:
        # concatenates the block text to the end of the template
        return prompt_template.rstrip() + "\n\n" + sanitized_content

def detect_scanner_pattern(text: str, profile_config: dict = None) -> dict:
    """
    Detect scanner pattern based on markers in text and profile settings.
    Return chunking configurations specific to detected scanner.
    """
    # If profile has chunking configurations, use directly
    if profile_config and 'chunking' in profile_config:
        chunking_config = profile_config['chunking'].copy()
        if chunking_config.get('marker_pattern'):
            matches = re.findall(chunking_config['marker_pattern'], text, re.MULTILINE)
            chunking_config['markers_found'] = len(matches)
            if matches:
                return chunking_config

    # Fallback: Auto-detect
    # Detect OpenVAS: starts with "NVT: "
    nvt_matches = re.findall(r'^\s*NVT:\s', text, re.MULTILINE)

    # Detect Tenable WAS: pattern "VULNERABILITY CRITICAL/HIGH/MEDIUM/LOW PLUGIN ID XXXX"
    vuln_matches = re.findall(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+', text, re.MULTILINE)

    if nvt_matches:
        return {
            'scanner_type': 'openvas',
            'marker_pattern': r'^\s*NVT:\s',
            'has_pairs': False,
            'markers_found': len(nvt_matches),
            'min_chunk_tokens': 800,
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 5
        }
    elif vuln_matches:
        return {
            'scanner_type': 'tenable_was',
            'marker_pattern': r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+',
            'has_pairs': True,
            'markers_found': len(vuln_matches),
            'min_chunk_tokens': 1000,
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 3
        }
    else:
        return {
            'scanner_type': 'unknown',
            'marker_pattern': None,
            'has_pairs': False,
            'markers_found': 0,
            'max_vulnerabilities_per_chunk': 3
        }

def register_scanner_pattern(scanner_name: str, marker_pattern: str, has_pairs: bool = False):
    # Stub for scanner pattern registry
    pass

def split_text_to_subchunks(text: str, target_size: int, profile_config: dict = None) -> List[str]:
    """
    Divide text into smaller subchunks - VERSION THAT RESPECTS MARKERS.
    """
    if len(text) <= target_size:
        return [text]

    lines = text.splitlines(keepends=True)
    if not lines:
        return [text]

    # OPTIMIZATION: Use scanner configurations if available
    optimized_target = min(target_size, 8000)  # Maximum 8K chars per chunk

    # Detect pattern with customizable configurations
    pattern_info = detect_scanner_pattern(text, profile_config)

    # If pattern not found, do simple optimized division
    if pattern_info.get('marker_pattern') is None:
        return _simple_split_by_size(text, optimized_target)

    # Find indices of lines with detected marker
    marker_lines = []
    for i, line in enumerate(lines):
        if re.search(pattern_info['marker_pattern'], line):
            marker_lines.append(i)

    # If no markers found even after detection, fallback
    if not marker_lines:
        return _simple_split_by_size(text, optimized_target)

    # CORRECTION: Capture pre-marker context (contains CVSS, severity, port, protocol)
    pre_marker_text = ''.join(lines[:marker_lines[0]]) if marker_lines[0] > 0 else ''

    subchunks = []
    # CUSTOMIZABLE STRATEGY: Use scanner configurations
    vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)
    if pattern_info.get('has_pairs'):
        vulns_per_chunk = max(2, vulns_per_chunk // 2)  # Reduce for pairs

    i = 0
    first_chunk = True  # Flag to prefix pre_marker_text only in first chunk
    while i < len(marker_lines):
        # Determine how many vulns to include in this chunk
        vulns_in_chunk = 0
        chunk_lines = []
        chunk_size = 0

        while i < len(marker_lines) and vulns_in_chunk < vulns_per_chunk:
            # Determine end of current block
            block_start = marker_lines[i]
            block_end = marker_lines[i + 1] if i + 1 < len(marker_lines) else len(lines)

            block_lines = lines[block_start:block_end]
            block_text = ''.join(block_lines)
            block_size = len(block_text)

            # If adding this block exceeds optimized target AND we have at least 1 vuln
            if vulns_in_chunk > 0 and (chunk_size + block_size > optimized_target):
                break

            # If block alone is larger than target, divide internally
            if block_size > optimized_target:
                # Save current chunk if not empty
                if chunk_lines:
                    prefix = pre_marker_text if first_chunk else ''
                    subchunks.append(prefix + ''.join(chunk_lines))
                    first_chunk = False

                # Divide large block
                sub_blocks = _split_block_by_size(block_text, optimized_target)
                # Prefix pre_marker_text to first sub-block if this is first chunk overall
                if first_chunk and sub_blocks:
                    sub_blocks[0] = pre_marker_text + sub_blocks[0]
                    first_chunk = False
                subchunks.extend(sub_blocks)

                # Reset for next chunk
                chunk_lines = []
                chunk_size = 0
                vulns_in_chunk = 0
            else:
                # Add block to the current chunk
                chunk_lines.extend(block_lines)
                chunk_size += block_size
                vulns_in_chunk += 1

            i += 1

        # Save chunk if not empty
        if chunk_lines:
            prefix = pre_marker_text if first_chunk else ''
            subchunks.append(prefix + ''.join(chunk_lines))
            first_chunk = False

    return subchunks if subchunks else [text]

def _split_block_by_size(text: str, target_size: int) -> List[str]:
    """
    Divide a text block into subchunks by lines.
    Avoids infinite recursion with depth limit.
    """
    if len(text) <= target_size:
        return [text]

    # Guard against infinite recursion
    if target_size < 1000:  # Absolute minimum
        chunks = []
        for i in range(0, len(text), 1000):
            chunks.append(text[i:i+1000])
        return chunks

    subchunks = []
    lines = text.splitlines(keepends=True)
    current = []
    current_len = 0

    for line in lines:
        line_len = len(line)

        # If adding this line exceeds target_size, save the current chunk
        if current and (current_len + line_len > target_size):
            subchunks.append(''.join(current))
            current = []
            current_len = 0

        current.append(line)
        current_len += line_len

    if current:
        subchunks.append(''.join(current))

    # AVOID RECURSION - if result still has large chunks, accept as is
    return subchunks if subchunks else [text]

def _simple_split_by_size(text: str, target_size: int) -> List[str]:
    """
    Simple split by size (by lines) when there are no vulnerability markers.
    """
    if len(text) <= target_size:
        return [text]

    subchunks = []
    lines = text.splitlines(keepends=True)
    current = []
    current_len = 0

    for line in lines:
        line_len = len(line)

        if current and (current_len + line_len > target_size):
            subchunks.append(''.join(current))
            current = []
            current_len = 0

        current.append(line)
        current_len += line_len

    if current:
        subchunks.append(''.join(current))

    return subchunks if subchunks else [text]

def intelligent_chunk_redivision(chunk_content: str, max_tokens: int,
                                  error_context: Dict[str, Any],
                                  tokenizer=None) -> List[str]:
    if tokenizer is None:
        try:
            tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except:
            tokenizer = tiktoken.get_encoding("cl100k_base")

    from src.model_management import count_tokens

    base_target = max_tokens - 2000
    token_count = max(count_tokens(chunk_content, tokenizer), 1)
    chars_per_token = len(chunk_content) / token_count
    target_chars = int(base_target * chars_per_token * 0.7)

    if not error_context.get('token_valid', True):
        target_chars = min(target_chars, len(chunk_content) // 3)
    if "JSON mal formado" in str(error_context.get('errors', [])):
        target_chars = min(target_chars, len(chunk_content) // 4)
    if "truncada" in str(error_context.get('errors', [])):
        target_chars = min(target_chars, len(chunk_content) // 5)

    new_chunks = split_text_to_subchunks(chunk_content, target_chars)
    validated_chunks = []
    for chunk in new_chunks:
        chunk_tokens = count_tokens(chunk, tokenizer)
        if chunk_tokens > base_target:
            simple_chunks = _simple_split_by_size(chunk, target_chars // 2)
            validated_chunks.extend(simple_chunks)
        else:
            validated_chunks.append(chunk)
    return validated_chunks

def robust_chunk_processing(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any],
                             max_retries: int = 3, tokenizer=None,
                             max_chunk_size: int = 4096) -> List[Dict]:
    # Use max_chunk_size instead of getattr(llm, 'max_tokens', 4096)
    max_tokens = max_chunk_size
    all_vulnerabilities = []
    try:
        attempt_counter = 1
        prompt = build_prompt(doc_chunk, profile_config)
        response = llm.invoke(prompt)
        validation = validate_json_and_tokens(response, doc_chunk.page_content,
                                              max_tokens, prompt, tokenizer=tokenizer)
        if validation['json_valid'] and validation['token_valid']:
            tqdm.write(f"✅ [CHUNK] Attempt {attempt_counter}: JSON is valid!")
            return validation['json_data']
        if not validation['needs_redivision']:
            for retry in range(2):
                attempt_counter += 1
                response = llm.invoke(prompt)
                validation = validate_json_and_tokens(response, doc_chunk.page_content,
                                                      max_tokens, prompt, tokenizer=tokenizer)
                if validation['json_valid']:
                    return validation['json_data']
        tqdm.write(f"[CHUNK] Performing intelligent redivision...")
        new_chunks = intelligent_chunk_redivision(
            doc_chunk.page_content, max_tokens, validation,
            tokenizer=tokenizer
        )
        for idx, chunk_content in enumerate(new_chunks):
            attempt_counter += 1
            sub_chunk = TokenChunk(chunk_content)
            sub_prompt = build_prompt(sub_chunk, profile_config)
            try:
                sub_response = llm.invoke(sub_prompt)
                sub_validation = validate_json_and_tokens(sub_response, chunk_content,
                                                          max_tokens, sub_prompt, tokenizer=tokenizer)
                if sub_validation['json_valid']:
                    all_vulnerabilities.extend(sub_validation['json_data'])
                else:
                    tqdm.write(f"[CHUNK] Subchunk {idx+1} did not return valid JSON.")
            except Exception as e:
                tqdm.write(f"[CHUNK] Error in subchunk {idx+1}: {e}")
                continue
        return all_vulnerabilities
    except Exception as e:
        tqdm.write(f"[CHUNK] Unexpected error: {e}")
        return []

def retry_chunk_with_subdivision(doc_chunk: TokenChunk, llm,
                                  profile_config: Dict[str, Any],
                                  max_retries: int = 3, tokenizer=None,
                                  max_chunk_size: int = 4096) -> List[Dict]:
    pattern_info = detect_scanner_pattern(doc_chunk.page_content)
    vulnerabilities = robust_chunk_processing(
        doc_chunk, llm, profile_config, max_retries,
        tokenizer=tokenizer,
        max_chunk_size=max_chunk_size
    )
    if vulnerabilities:
        if pattern_info['has_pairs']:
            return validate_base_instances_pairs(vulnerabilities)
        return vulnerabilities
    return []
