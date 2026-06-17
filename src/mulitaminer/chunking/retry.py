"""Chunk processing with validation, empty-response retry and redivision.

This is where the LLM is actually invoked. On failure (empty `[]`, invalid
JSON, underextraction) it retries and, as a last resort, redivides the chunk
(via tokens.py) and processes the sub-chunks.
"""
import re
import tiktoken
from typing import Dict, Any
from tqdm import tqdm

from mulitaminer.llm import validate_json_and_tokens
from mulitaminer.reporting.llm_debug import save_llm_response_debug
from mulitaminer.chunking.processing import extract_response_content
from mulitaminer.chunking.errors import _is_fatal_api_error
from mulitaminer.chunking.tokens import (
    TokenChunk,
    build_prompt,
    split_text_to_subchunks,
    intelligent_chunk_redivision,
)


def _is_empty_response(content: str) -> bool:
    """LLM returned no content or a syntactically valid but empty array (`[]`)."""
    if not content:
        return True
    return content.strip() in ('[]', '[ ]', '')


def _detect_underextraction(chunk_content: str, num_extracted: int,
                             profile_config: Dict[str, Any]) -> bool:
    """
    Local LLMs (gemma4/mistral 7B) often "lost-in-the-middle" on large chunks:
    the response parses as valid JSON but contains far fewer vulnerabilities
    than the chunk actually has. We catch this by comparing the count of
    scanner markers (e.g. NVT:) in the chunk against the number of items the
    LLM returned. If the LLM returned less than half the markers it saw,
    treat as a soft failure and force redivision.
    """
    if not profile_config:
        return False
    marker_pattern = profile_config.get('chunking', {}).get('marker_pattern')
    if not marker_pattern:
        return False
    try:
        markers = len(re.findall(marker_pattern, chunk_content, flags=re.MULTILINE))
    except re.error:
        return False
    if markers < 2:
        return False
    return num_extracted * 2 < markers


def _invoke_validate_log(llm, prompt: str, chunk_content: str, max_tokens: int,
                         tokenizer, num_predict, debug_mode: bool,
                         debug_kwargs: dict) -> tuple:
    """
    Single LLM call: invoke, validate response, optionally log to debug JSONL.

    Args:
        debug_kwargs: pdf_name, llm_name, block_idx, chunk_idx, retry_count,
            was_redivided. Other debug fields (chunk_chars, vulns_extracted,
            recovered_via, etc.) are derived here so callers stay simple.

    Returns:
        (response_content, response_tokens, validation_dict)
    """
    response = llm.invoke(prompt)
    content = extract_response_content(response)
    tokens_used = len(tokenizer.encode(content)) if content else 0

    validation = validate_json_and_tokens(
        content, chunk_content, max_tokens, prompt,
        tokenizer=tokenizer, num_predict=num_predict
    )

    if debug_mode:
        json_data = validation.get('json_data') or []
        save_llm_response_debug(
            **debug_kwargs,
            response_content=content or "",
            chunk_chars=len(chunk_content) if chunk_content else 0,
            vulns_extracted=len(json_data) if isinstance(json_data, list) else 0,
            recovered_via=validation.get('recovered_via'),
            parsing_success=validation.get('json_valid', False),
            validation_success=(validation.get('json_valid', False)
                                and validation.get('token_valid', False)),
            prompt_tokens=len(tokenizer.encode(prompt)),
            response_tokens=tokens_used,
            likely_truncated=validation.get('likely_truncated', False),
        )

    return content, tokens_used, validation


def _retry_empty_response(llm, prompt: str, chunk_content: str, max_tokens: int,
                          tokenizer, num_predict, debug_mode: bool,
                          debug_base: dict, max_retries: int = 2,
                          context_label: str = "CHUNK") -> tuple:
    """
    Re-call the LLM up to `max_retries` times when the initial response was `[]`.

    Empty `[]` may be a legitimate "no vulns here" answer OR a transient LLM
    failure. A simple repeat call often resolves the latter at low cost.

    Args:
        debug_base: pdf_name, llm_name, chunk_idx, was_redivided.
                    `retry_count` is set automatically per attempt.

    Returns:
        (content, total_extra_tokens, validation) of the first successful retry,
        or (None, total_extra_tokens, None) if all retries also returned empty
        or invalid JSON.
    """
    total_extra_tokens = 0
    for attempt in range(max_retries):
        debug_kwargs = {**debug_base, 'retry_count': attempt + 1}
        content, tokens_used, validation = _invoke_validate_log(
            llm, prompt, chunk_content, max_tokens, tokenizer,
            num_predict, debug_mode, debug_kwargs
        )
        total_extra_tokens += tokens_used

        if not _is_empty_response(content) and validation['json_valid']:
            recovered = len(validation['json_data'])
            tqdm.write(f"✅ [{context_label}] Retry {attempt + 1}: recovered {recovered} vulns")
            return content, total_extra_tokens, validation

    return None, total_extra_tokens, None


def robust_chunk_processing(doc_chunk: TokenChunk, llm, profile_config: Dict[str, Any],
                             max_retries: int = 3, tokenizer=None,
                             max_chunk_size: int = 4096, pdf_name: str = "unknown",
                             llm_name: str = "unknown", debug_mode: bool = False,
                             block_idx: int = 0) -> Dict[str, Any]:
    max_tokens = max_chunk_size
    # num_predict = model's output cap (from llm_config.max_tokens); used only for truncation diagnostics
    num_predict = None
    if profile_config and isinstance(profile_config.get('llm_config'), dict):
        num_predict = profile_config['llm_config'].get('max_tokens')
    all_vulnerabilities = []
    total_tokens_output = 0

    # Ensure tokenizer is initialized from LLM config if not provided
    if tokenizer is None:
        from mulitaminer.llm import get_tokenizer
        if profile_config and 'llm_config' in profile_config:
            tokenizer = get_tokenizer(profile_config['llm_config'])
        else:
            try:
                tokenizer = tiktoken.encoding_for_model("gpt-3.5-turbo")
            except Exception:
                tokenizer = tiktoken.get_encoding("cl100k_base")

    try:
        prompt = build_prompt(doc_chunk, profile_config)
        debug_base = {
            'pdf_name': pdf_name,
            'llm_name': llm_name,
            'block_idx': block_idx,
            'chunk_idx': 0,
            'was_redivided': False,
        }

        # First attempt
        response_content, response_tokens, validation = _invoke_validate_log(
            llm, prompt, doc_chunk.page_content, max_tokens, tokenizer,
            num_predict, debug_mode, {**debug_base, 'retry_count': 0}
        )
        total_tokens_output += response_tokens

        # Empty `[]` may be transient — retry before deciding it's the real answer
        if _is_empty_response(response_content):
            tqdm.write("[CHUNK] Empty response [] detected. Retrying...")
            _, extra_tokens, retry_validation = _retry_empty_response(
                llm, prompt, doc_chunk.page_content, max_tokens, tokenizer,
                num_predict, debug_mode, debug_base, max_retries=2, context_label="CHUNK"
            )
            total_tokens_output += extra_tokens
            if retry_validation:
                n = len(retry_validation['json_data']) if isinstance(retry_validation.get('json_data'), list) else 0
                if not _detect_underextraction(doc_chunk.page_content, n, profile_config):
                    return {'vulnerabilities': retry_validation['json_data'],
                            'tokens_output': total_tokens_output}
                tqdm.write(f"[CHUNK] Underextraction detected after retry ({n} vulns vs many markers). Forcing redivision.")
                validation = retry_validation
                validation['needs_redivision'] = True

        if validation['json_valid'] and validation['token_valid']:
            n = len(validation['json_data']) if isinstance(validation.get('json_data'), list) else 0
            if _detect_underextraction(doc_chunk.page_content, n, profile_config):
                tqdm.write(f"[CHUNK] Underextraction detected ({n} vulns vs many markers). Forcing redivision.")
                validation['needs_redivision'] = True
            else:
                return {'vulnerabilities': validation['json_data'],
                        'tokens_output': total_tokens_output}

        # Invalid JSON but chunk size is OK — retry without redivision
        if not validation['needs_redivision']:
            for retry in range(2):
                response_content, response_tokens, validation = _invoke_validate_log(
                    llm, prompt, doc_chunk.page_content, max_tokens, tokenizer,
                    num_predict, debug_mode, {**debug_base, 'retry_count': retry + 1}
                )
                total_tokens_output += response_tokens
                if validation['json_valid']:
                    return {'vulnerabilities': validation['json_data'],
                            'tokens_output': total_tokens_output}

        # Last resort: redivide chunk and process each sub-chunk
        tqdm.write("[CHUNK] Performing intelligent redivision...")
        new_chunks = intelligent_chunk_redivision(
            doc_chunk.page_content, max_tokens, validation,
            tokenizer=tokenizer, profile_config=profile_config
        )

        for idx, chunk_content in enumerate(new_chunks):
            sub_prompt = build_prompt(TokenChunk(chunk_content), profile_config)
            sub_debug_base = {
                'pdf_name': pdf_name,
                'llm_name': llm_name,
                'block_idx': block_idx,
                'chunk_idx': idx,
                'was_redivided': True,
            }

            try:
                sub_content, sub_tokens, sub_validation = _invoke_validate_log(
                    llm, sub_prompt, chunk_content, max_tokens, tokenizer,
                    num_predict, debug_mode, {**sub_debug_base, 'retry_count': 0}
                )
                total_tokens_output += sub_tokens

                # Same empty-retry policy applies to sub-chunks: a fragmented vuln
                # may still hold extractable content even without the leading marker.
                if _is_empty_response(sub_content):
                    tqdm.write(f"[SUB-CHUNK {idx + 1}] Empty response []. Retrying...")
                    _, extra_tokens, retry_validation = _retry_empty_response(
                        llm, sub_prompt, chunk_content, max_tokens, tokenizer,
                        num_predict, debug_mode, sub_debug_base, max_retries=2,
                        context_label=f"SUB-CHUNK {idx + 1}"
                    )
                    total_tokens_output += extra_tokens
                    if retry_validation:
                        sub_validation = retry_validation

                if sub_validation['json_valid']:
                    sub_data = sub_validation['json_data'] or []
                    if _detect_underextraction(chunk_content, len(sub_data), profile_config):
                        tqdm.write(f"[SUB-CHUNK {idx + 1}] Underextraction detected ({len(sub_data)} vulns vs many markers). Splitting further.")
                        deeper = split_text_to_subchunks(
                            chunk_content,
                            max(len(chunk_content) // 2, 1000),
                            profile_config=profile_config,
                        )
                        for d_idx, d_content in enumerate(deeper):
                            d_prompt = build_prompt(TokenChunk(d_content), profile_config)
                            try:
                                d_content_resp, d_tokens, d_validation = _invoke_validate_log(
                                    llm, d_prompt, d_content, max_tokens, tokenizer,
                                    num_predict, debug_mode,
                                    {**sub_debug_base, 'chunk_idx': idx * 100 + d_idx, 'retry_count': 0}
                                )
                                total_tokens_output += d_tokens
                                if d_validation['json_valid']:
                                    all_vulnerabilities.extend(d_validation['json_data'] or [])
                            except Exception as e:
                                tqdm.write(f"[SUB-CHUNK {idx + 1}.{d_idx + 1}] Error: {e}")
                                continue
                    else:
                        all_vulnerabilities.extend(sub_data)
                else:
                    tqdm.write(f"[CHUNK] Subchunk {idx + 1} did not return valid JSON.")
            except Exception as e:
                if _is_fatal_api_error(e):
                    raise
                tqdm.write(f"[CHUNK] Error in subchunk {idx + 1}: {e}")
                continue

        return {'vulnerabilities': all_vulnerabilities, 'tokens_output': total_tokens_output}

    except Exception as e:
        if _is_fatal_api_error(e):
            raise
        tqdm.write(f"[CHUNK] Unexpected error: {e}")
        return {'vulnerabilities': [], 'tokens_output': 0}

def retry_chunk_with_subdivision(doc_chunk: TokenChunk, llm,
                                  profile_config: Dict[str, Any],
                                  max_retries: int = 3, tokenizer=None,
                                  max_chunk_size: int = 4096,
                                  scanner_type: str = None, pdf_name: str = "unknown",
                                  llm_name: str = "unknown", debug_mode: bool = False,
                                  block_idx: int = 0) -> Dict[str, Any]:
    result = robust_chunk_processing(
        doc_chunk, llm, profile_config, max_retries,
        tokenizer=tokenizer,
        max_chunk_size=max_chunk_size,
        pdf_name=pdf_name,
        llm_name=llm_name,
        debug_mode=debug_mode,
        block_idx=block_idx,
    )
    vulnerabilities = result.get('vulnerabilities', [])
    tokens_output = result.get('tokens_output', 0)

    if vulnerabilities:
        return {'vulnerabilities': vulnerabilities, 'tokens_output': tokens_output}
    return {'vulnerabilities': [], 'tokens_output': tokens_output}
