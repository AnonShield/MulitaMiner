import tiktoken
import re
from typing import List, Dict, Any
from src.model_management import parse_json_response, load_prompt, validate_json_and_tokens, get_tokenizer
from src.utils.llm_debug import save_llm_response_debug
from src.utils.processing import extract_response_content, sanitize_unicode_text
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
        except Exception:
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

def build_prompt(doc_chunk: TokenChunk, profile_config: Dict[str, Any]) -> str:
    prompt_template = profile_config.get('prompt_template', '') if profile_config else ''
    # If it's a file path, load content
    if os.path.isfile(prompt_template):
        prompt_template = load_prompt(prompt_template)
    
    sanitized_content = sanitize_unicode_text(doc_chunk.page_content)
    
    wrapped = f"<report_content>\n{sanitized_content}\n</report_content>"
    if "{context}" in prompt_template:
        return prompt_template.replace("{context}", wrapped)
    else:
        # concatenates the block text to the end of the template
        return prompt_template.rstrip() + "\n\n" + wrapped

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
            'markers_found': len(nvt_matches),
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 5
        }
    elif vuln_matches:
        return {
            'scanner_type': 'tenable_was',
            'marker_pattern': r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+PLUGIN\s+ID\s+\d+',
            'markers_found': len(vuln_matches),
            'force_break_at_markers': True,
            'max_vulnerabilities_per_chunk': 3
        }
    else:
        return {
            'scanner_type': 'unknown',
            'marker_pattern': None,
            'markers_found': 0,
            'max_vulnerabilities_per_chunk': 3
        }

def split_text_to_subchunks(text: str, target_size: int, profile_config: dict = None) -> List[str]:
    """
    Divide text into smaller subchunks - VERSION THAT RESPECTS MARKERS.
    
    The target_size parameter is expected to already be optimized by the caller
    (typically intelligent_chunk_redivision which calculates it dynamically).
    """
    if len(text) <= target_size:
        return [text]

    lines = text.splitlines(keepends=True)
    if not lines:
        return [text]

    # Use target_size directly without overly aggressive hard limit
    # Allow up to 50K chars for better context preservation
    optimized_target = min(target_size, 50000)

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

    # Capture pre-marker context (section header with severity/port/protocol for OpenVAS).
    # Propagated to every subchunk so the LLM sees the header context even after redivision.
    pre_marker_text = ''.join(lines[:marker_lines[0]]) if marker_lines[0] > 0 else ''

    subchunks = []
    # CUSTOMIZABLE STRATEGY: Use scanner configurations
    vulns_per_chunk = pattern_info.get('max_vulnerabilities_per_chunk', 3)

    i = 0
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
                    subchunks.append(pre_marker_text + ''.join(chunk_lines))

                # Divide large block and prefix pre_marker_text to every sub-block
                sub_blocks = _split_block_by_size(block_text, optimized_target)
                subchunks.extend(pre_marker_text + sb for sb in sub_blocks)

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
            subchunks.append(pre_marker_text + ''.join(chunk_lines))

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

def smart_chunk_vulnerabilities(
    text: str,
    marker_pattern: str,
    max_tokens: int,
    reserve_for_response: int,
    max_vulnerabilities_per_chunk: int,
    tokenizer=None,
    profile_config: dict = None,
    scanner_type: str = None
) -> List[TokenChunk]:
    """
    Intelligent chunking that respects ALL constraints simultaneously:
    - Vulnerability boundaries (marker_pattern)
    - Token limits (max_tokens - reserve_for_response)
    - Character size limits (dynamically calculated from tokenizer)
    - Vulnerability count limits (max_vulnerabilities_per_chunk)
    
    Args:
        text: Full block text to chunk
        marker_pattern: Regex pattern to detect vulnerability start (e.g., "^\\s*NVT:")
        max_tokens: Maximum tokens per chunk (from LLM config)
        reserve_for_response: Token reserve for LLM response
        max_vulnerabilities_per_chunk: Max vulns to group
        tokenizer: tiktoken tokenizer (or will initialize from config)
        profile_config: Profile configuration (optional, used to extract llm_config)
        scanner_type: Scanner type (e.g., 'tenable' or 'openvas')
    
    Returns:
        List[TokenChunk]: Chunks that respect all constraints
    """
    from src.model_management import count_tokens, get_tokenizer
    
    # Initialize tokenizer if needed - prioritize config-based tokenizer
    if tokenizer is None:
        llm_config = None
        if profile_config and 'llm_config' in profile_config:
            llm_config = profile_config['llm_config']
        
        if llm_config:
            tokenizer = get_tokenizer(llm_config)
        else:
            # Fallback only if no config available
            try:
                tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
            except Exception:
                tokenizer = tiktoken.get_encoding("cl100k_base")
    
    # No pair-handling adjustment - Tenable always has instances field
    max_vulns_adjusted = max_vulnerabilities_per_chunk
    
    # If no marker pattern, fallback to simple token-based chunking
    if not marker_pattern:
        return get_token_based_chunks(
            text,
            max_tokens=max_tokens,
            reserve_for_response=reserve_for_response,
            tokenizer=tokenizer,
            profile_config=profile_config
        )
    
    # Parse text into lines
    lines = text.splitlines(keepends=True)
    if not lines:
        return [TokenChunk(text)]
    
    # Find vulnerability boundaries via marker
    marker_indices = []
    for i, line in enumerate(lines):
        if re.search(marker_pattern, line, re.MULTILINE):
            marker_indices.append(i)
    
    # If no markers found, fallback
    if not marker_indices:
        return get_token_based_chunks(
            text,
            max_tokens=max_tokens,
            reserve_for_response=reserve_for_response,
            tokenizer=tokenizer,
            profile_config=profile_config
        )
    
    # Calculate effective chunk size
    chunk_size_tokens = max_tokens - reserve_for_response
    
    # Calculate optimized_target_chars dynamically based on actual text characteristics
    # Use full text for exact proportion (no approximation error from sampling)
    token_count = count_tokens(text, tokenizer)
    chars_per_token = len(text) / max(token_count, 1)
    # Apply 85% safety margin to balance safety and chunk size
    optimized_target_chars = int(chunk_size_tokens * chars_per_token * 0.85)
    # Relaxed limit: respect LLM config capacity instead of hardcoding 8K
    optimized_target_chars = min(optimized_target_chars, max(30000, chunk_size_tokens * 2))
    
    # Build chunks respecting ALL constraints simultaneously
    chunks = []
    i = 0
    
    while i < len(marker_indices):
        current_chunk_lines = []
        current_chunk_tokens = 0
        vulns_in_chunk = 0
        
        # Progressively add vulnerabilities while all constraints are respected
        while i < len(marker_indices) and vulns_in_chunk < max_vulns_adjusted:
            # Determine vulnerability boundaries
            vuln_start = marker_indices[i]
            vuln_end = marker_indices[i + 1] if i + 1 < len(marker_indices) else len(lines)
            
            vuln_lines = lines[vuln_start:vuln_end]
            vuln_text = ''.join(vuln_lines)
            vuln_tokens = count_tokens(vuln_text, tokenizer)
            
            # Check if adding this vuln would exceed ANY constraint
            would_exceed_tokens = (current_chunk_tokens + vuln_tokens) > chunk_size_tokens
            would_exceed_chars = (len(''.join(current_chunk_lines)) + len(vuln_text)) > optimized_target_chars
            would_exceed_vulns = vulns_in_chunk >= max_vulns_adjusted
            
            # If we have at least 1 vuln and would exceed limit, stop and save chunk
            if vulns_in_chunk > 0 and (would_exceed_tokens or would_exceed_chars or would_exceed_vulns):
                break
            
            # If this single vuln exceeds token limit on its own, include it anyway
            # but save the chunk immediately - let intelligent_chunk_redivision handle subdivision if needed
            if vuln_tokens > chunk_size_tokens and vulns_in_chunk == 0:
                tqdm.write(f"[CHUNK] Warning: Vulnerability spans {vuln_tokens} tokens (limit: {chunk_size_tokens}). "
                           "Sending anyway for redivision if needed.")
                current_chunk_lines.extend(vuln_lines)
                current_chunk_tokens += vuln_tokens
                vulns_in_chunk += 1
                i += 1
                break  # Save chunk and let redivision handle it
            
            # Add vuln to current chunk if within all constraints
            if not (would_exceed_tokens or would_exceed_chars or would_exceed_vulns):
                current_chunk_lines.extend(vuln_lines)
                current_chunk_tokens += vuln_tokens
                vulns_in_chunk += 1
                i += 1
            else:
                break
        
        # Save chunk if not empty
        if current_chunk_lines:
            chunk_text = ''.join(current_chunk_lines)
            chunks.append(TokenChunk(chunk_text))
    
    # Fallback if no chunks were created
    if not chunks:
        chunks.append(TokenChunk(text))
    
    return chunks


def intelligent_chunk_redivision(chunk_content: str, max_tokens: int,
                                  error_context: Dict[str, Any],
                                  tokenizer=None, reserve_for_response: int = 1000,
                                  profile_config: dict = None) -> List[str]:
    """
    Intelligently redivide a failed chunk based on error context.
    
    Args:
        chunk_content: Content that failed validation
        max_tokens: Maximum tokens per chunk (from LLM config)
        error_context: Error details that triggered redivision (token_valid, errors, etc.)
        tokenizer: Tokenizer to use for token counting
        reserve_for_response: Token reserve for LLM response (default: 1000, consistent with chunking)
        profile_config: Profile configuration (optional, used to detect vulnerability markers for respecting boundaries)
    
    Returns:
        List of smaller chunks
    """
    if tokenizer is None:
        try:
            tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
        except Exception:
            tokenizer = tiktoken.get_encoding("cl100k_base")

    from src.model_management import count_tokens

    base_target = max_tokens - reserve_for_response
    token_count = max(count_tokens(chunk_content, tokenizer), 1)
    chars_per_token = len(chunk_content) / token_count
    target_chars = int(base_target * chars_per_token * 0.85)

    if not error_context.get('token_valid', True):
        target_chars = min(target_chars, len(chunk_content) // 2)
    if "JSON mal formado" in str(error_context.get('errors', [])):
        target_chars = min(target_chars, len(chunk_content) // 3)
    if "truncada" in str(error_context.get('errors', [])):
        target_chars = min(target_chars, len(chunk_content) // 3)

    new_chunks = split_text_to_subchunks(chunk_content, target_chars, profile_config=profile_config)
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
                             max_chunk_size: int = 4096, pdf_name: str = "unknown",
                             llm_name: str = "unknown", debug_mode: bool = False) -> Dict[str, Any]:
    # Use max_chunk_size instead of getattr(llm, 'max_tokens', 4096)
    max_tokens = max_chunk_size
    all_vulnerabilities = []
    total_tokens_output = 0
    
    # Ensure tokenizer is initialized from LLM config if not provided
    if tokenizer is None:
        from src.model_management import get_tokenizer
        if profile_config and 'llm_config' in profile_config:
            tokenizer = get_tokenizer(profile_config['llm_config'])
        else:
            try:
                tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
            except Exception:
                tokenizer = tiktoken.get_encoding("cl100k_base")
    
    try:
        attempt_counter = 1
        prompt = build_prompt(doc_chunk, profile_config)
        response = llm.invoke(prompt)
        response_content = extract_response_content(response)
        response_tokens = len(tokenizer.encode(response_content)) if response_content else 0
        total_tokens_output += response_tokens
        
        # Validate first before logging
        validation = validate_json_and_tokens(response_content, doc_chunk.page_content,
                                              max_tokens, prompt, tokenizer=tokenizer)
        
        # Debug logging
        if debug_mode:
            prompt_tokens = len(tokenizer.encode(prompt))
            save_llm_response_debug(
                pdf_name=pdf_name,
                llm_name=llm_name,
                chunk_idx=0,
                response_content=response_content or "",
                retry_count=0,
                was_redivided=False,
                parsing_success=validation.get('json_valid', False),
                validation_success=validation.get('json_valid', False),
                prompt_tokens=prompt_tokens,
                response_tokens=response_tokens
            )
        
        # CRITICAL FIX: Detect empty response and retry before redivision
        # GPT-5 mini can be non-deterministic at temperature=0 (o-series architecture)
        # If response is empty, simple retry with same prompt may succeed
        if response_content and response_content.strip() in ('[]', '[ ]', ''):
            tqdm.write(f"[CHUNK] Empty response [] detected. Attempting {2} simple retries...")
            for retry_attempt in range(2):
                attempt_counter += 1
                retry_response = llm.invoke(prompt)
                retry_response_content = extract_response_content(retry_response)
                retry_response_tokens = len(tokenizer.encode(retry_response_content)) if retry_response_content else 0
                total_tokens_output += retry_response_tokens
                
                if retry_response_content and retry_response_content.strip() not in ('[]', '[ ]', ''):
                    # Got non-empty response, validate and return if valid
                    tqdm.write(f"[CHUNK] Retry {retry_attempt + 1} succeeded with non-empty content.")
                    retry_validation = validate_json_and_tokens(retry_response_content, doc_chunk.page_content,
                                                               max_tokens, prompt, tokenizer=tokenizer)
                    if debug_mode:
                        prompt_tokens = len(tokenizer.encode(prompt))
                        save_llm_response_debug(
                            pdf_name=pdf_name,
                            llm_name=llm_name,
                            chunk_idx=0,
                            response_content=retry_response_content or "",
                            retry_count=retry_attempt + 1,
                            was_redivided=False,
                            parsing_success=retry_validation.get('json_valid', False),
                            validation_success=retry_validation.get('json_valid', False) and retry_validation.get('token_valid', False),
                            prompt_tokens=prompt_tokens,
                            response_tokens=retry_response_tokens
                        )
                    if retry_validation['json_valid']:
                        tqdm.write(f"✅ [CHUNK] Retry {retry_attempt + 1}: JSON is valid!")
                        return {'vulnerabilities': retry_validation['json_data'], 'tokens_output': total_tokens_output}
        
        if validation['json_valid'] and validation['token_valid']:
            tqdm.write(f"✅ [CHUNK] Attempt {attempt_counter}: JSON is valid!")
            return {'vulnerabilities': validation['json_data'], 'tokens_output': total_tokens_output}
        if not validation['needs_redivision']:
            for retry in range(2):
                attempt_counter += 1
                response = llm.invoke(prompt)
                response_content = extract_response_content(response)
                response_tokens = len(tokenizer.encode(response_content)) if tokenizer else 0
                total_tokens_output += response_tokens
                
                # Validate first to get real success flags
                validation = validate_json_and_tokens(response_content, doc_chunk.page_content,
                                                      max_tokens, prompt, tokenizer=tokenizer)
                
                # Debug logging with actual validation results
                if debug_mode:
                    prompt_tokens = len(tokenizer.encode(prompt))
                    save_llm_response_debug(
                        pdf_name=pdf_name,
                        llm_name=llm_name,
                        chunk_idx=0,
                        response_content=response_content or "",
                        retry_count=retry + 1,
                        was_redivided=False,
                        parsing_success=validation.get('json_valid', False),
                        validation_success=validation.get('json_valid', False) and validation.get('token_valid', False),
                        prompt_tokens=prompt_tokens,
                        response_tokens=response_tokens
                    )
                
                if validation['json_valid']:
                    return {'vulnerabilities': validation['json_data'], 'tokens_output': total_tokens_output}
        tqdm.write(f"[CHUNK] Performing intelligent redivision...")
        new_chunks = intelligent_chunk_redivision(
            doc_chunk.page_content, max_tokens, validation,
            tokenizer=tokenizer,
            profile_config=profile_config
        )
        for idx, chunk_content in enumerate(new_chunks):
            attempt_counter += 1
            sub_chunk = TokenChunk(chunk_content)
            sub_prompt = build_prompt(sub_chunk, profile_config)
            try:
                sub_response = llm.invoke(sub_prompt)
                sub_response_content = extract_response_content(sub_response)
                response_tokens = len(tokenizer.encode(sub_response_content)) if tokenizer else 0
                total_tokens_output += response_tokens
                
                # Validate first to get real success flags
                sub_validation = validate_json_and_tokens(sub_response_content, chunk_content,
                                                          max_tokens, sub_prompt, tokenizer=tokenizer)
                
                # Debug logging with actual validation results
                if debug_mode:
                    prompt_tokens = len(tokenizer.encode(sub_prompt))
                    save_llm_response_debug(
                        pdf_name=pdf_name,
                        llm_name=llm_name,
                        chunk_idx=idx,
                        response_content=sub_response_content or "",
                        retry_count=0,
                        was_redivided=True,
                        parsing_success=sub_validation.get('json_valid', False),
                        validation_success=sub_validation.get('json_valid', False) and sub_validation.get('token_valid', False),
                        prompt_tokens=prompt_tokens,
                        response_tokens=response_tokens
                    )
                
                if sub_validation['json_valid']:
                    all_vulnerabilities.extend(sub_validation['json_data'])
                else:
                    tqdm.write(f"[CHUNK] Subchunk {idx+1} did not return valid JSON.")
            except Exception as e:
                tqdm.write(f"[CHUNK] Error in subchunk {idx+1}: {e}")
                continue
        return {'vulnerabilities': all_vulnerabilities, 'tokens_output': total_tokens_output}
    except Exception as e:
        tqdm.write(f"[CHUNK] Unexpected error: {e}")
        return {'vulnerabilities': [], 'tokens_output': 0}

def retry_chunk_with_subdivision(doc_chunk: TokenChunk, llm,
                                  profile_config: Dict[str, Any],
                                  max_retries: int = 3, tokenizer=None,
                                  max_chunk_size: int = 4096,
                                  scanner_type: str = None, pdf_name: str = "unknown",
                                  llm_name: str = "unknown", debug_mode: bool = False) -> Dict[str, Any]:
    result = robust_chunk_processing(
        doc_chunk, llm, profile_config, max_retries,
        tokenizer=tokenizer,
        max_chunk_size=max_chunk_size,
        pdf_name=pdf_name,
        llm_name=llm_name,
        debug_mode=debug_mode
    )
    vulnerabilities = result.get('vulnerabilities', [])
    tokens_output = result.get('tokens_output', 0)
    
    if vulnerabilities:
        return {'vulnerabilities': vulnerabilities, 'tokens_output': tokens_output}
    return {'vulnerabilities': [], 'tokens_output': tokens_output}