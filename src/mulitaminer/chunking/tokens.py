"""Chunk production: turn block text into LLM-sized chunks.

TokenChunk + the token/char-budgeted splitters (marker-aware and simple),
prompt assembly, scanner-pattern detection, and the failed-chunk redivision
helper. No LLM calls happen here — see ``retry.py`` for that.
"""
import re
import tiktoken
from typing import List, Dict, Any
from tqdm import tqdm

from mulitaminer.llm import load_prompt
from mulitaminer.chunking.processing import sanitize_unicode_text
from mulitaminer.configs.constants import (
    CHUNK_SAFETY_MARGIN_DEFAULT,
    CHUNK_CHAR_CEILING_MIN,
    CHUNK_CHAR_CEILING_TOKEN_MULT,
)


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
    # Resolve a template path to its content. load_prompt handles absolute and
    # package-relative paths (e.g. "configs/prompts/openvas_prompt.txt") and
    # returns the value unchanged if it isn't a locatable file (inline prompt).
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
            # Match the severity/CVSS header that sits one line above NVT — keeps
            # the `Severity (CVSS: X.Y)` context inside the chunk that owns the
            # NVT. Detection still uses NVT: as the fingerprint above.
            'marker_pattern': r'^\s*(?:Critical|High|Medium|Low|Log)\s+\(CVSS:',
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
    from mulitaminer.llm import count_tokens, get_tokenizer

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
    # Apply the safety margin to balance safety and chunk size
    optimized_target_chars = int(chunk_size_tokens * chars_per_token * CHUNK_SAFETY_MARGIN_DEFAULT)
    # Relaxed limit: respect LLM config capacity instead of hardcoding 8K
    optimized_target_chars = min(
        optimized_target_chars,
        max(CHUNK_CHAR_CEILING_MIN, chunk_size_tokens * CHUNK_CHAR_CEILING_TOKEN_MULT),
    )

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

            # If this single vuln exceeds ANY size limit on its own, include it anyway
            # but save the chunk immediately - let intelligent_chunk_redivision handle subdivision if needed.
            # Covers both token overflow AND char overflow. Without the char clause, a vuln_text
            # larger than optimized_target_chars but smaller than chunk_size_tokens would loop
            # forever: would_exceed_chars=True breaks inner loop without advancing i, and outer
            # loop restarts on the same marker indefinitely.
            single_vuln_exceeds = (
                vuln_tokens > chunk_size_tokens
                or len(vuln_text) > optimized_target_chars
            )
            if single_vuln_exceeds and vulns_in_chunk == 0:
                tqdm.write(
                    f"[CHUNK] Warning: Vulnerability alone exceeds limits "
                    f"(tokens={vuln_tokens}/{chunk_size_tokens}, "
                    f"chars={len(vuln_text):,}/{optimized_target_chars:,}). "
                    "Sending anyway for redivision if needed."
                )
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

    from mulitaminer.llm import count_tokens

    base_target = max_tokens - reserve_for_response
    token_count = max(count_tokens(chunk_content, tokenizer), 1)
    chars_per_token = len(chunk_content) / token_count
    target_chars = int(base_target * chars_per_token * CHUNK_SAFETY_MARGIN_DEFAULT)

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
