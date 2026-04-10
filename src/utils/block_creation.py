import os
import shutil
import re
from tqdm import tqdm
import tiktoken
from .chunking import retry_chunk_with_subdivision
from src.model_management import get_tokenizer, count_tokens

def create_session_blocks_from_text(report_text: str, temp_dir: str = 'temp_blocks', 
                                    visual_layout_path: str = None, scanner: str = 'openvas') -> list:
    """
    Create temporary session block files from extracted report text.
    Uses scanner-specific strategies for block creation.
    
    Fallback: If scanner has no custom strategy, creates a single block with all text.
    """
    from src.scanner_strategies.registry import get_strategy
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    
    # Get scanner strategy
    strategy = get_strategy(scanner)
    
    if strategy is None:
        # Fallback for unknown scanner: create single block
        block_path = os.path.join(temp_dir, f"block_generic.txt")
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        return [{
            'file': block_path,
            'port': None,
            'protocol': None,
            'severity': None
        }]
    
    # Extract visual context if scanner requires it
    context = ([], None, None, None)
    if strategy.requires_visual_layout and visual_layout_path:
        context = strategy.extract_visual_context(visual_layout_path)
    
    # Delegate block creation to strategy
    return strategy.create_blocks(report_text, temp_dir, context)

def extract_vulns_from_blocks(blocks: list, llm, profile_config: dict,
                               chunk_func, llm_config: dict = None) -> list:
    """
    For each session block, apply chunking and extract vulnerabilities, propagating port/protocol.
    
    Args:
        blocks: List of block dictionaries with file paths
        llm: Initialized LLM instance
        profile_config: Profile configuration
        chunk_func: Chunking function reference (legacy parameter, not used)
        llm_config: LLM configuration from JSON (REQUIRED)
    
    Raises:
        ValueError: If llm_config is None or missing required fields
    """
    from src.utils.chunking import get_token_based_chunks, split_text_to_subchunks, TokenChunk
    from src.model_management import get_tokenizer, count_tokens

    if not llm_config:
        raise ValueError(
            "[ERROR] llm_config is required in extract_vulns_from_blocks. "
            "This config must contain 'max_chunk_size' and 'reserve_for_response' values. "
            "Please ensure llm_config is passed from main.py."
        )

    max_chunk_size = llm_config.get('max_chunk_size')
    reserve_for_response = llm_config.get('reserve_for_response')
    
    if max_chunk_size is None:
        raise ValueError(
            "[ERROR] 'max_chunk_size' not found in llm_config. "
            "Check your LLM JSON configuration file."
        )
    if reserve_for_response is None:
        raise ValueError(
            "[ERROR] 'reserve_for_response' not found in llm_config. "
            "Check your LLM JSON configuration file."
        )

    tokenizer = get_tokenizer(llm_config)

    all_vulns = []
    tokens_info = []
    # Count total chunks for progress bar
    total_chunks = 0
    block_chunks_map = []
    for block_idx, block in enumerate(blocks):
        with open(block['file'], 'r', encoding='utf-8') as f:
            block_text = f.read()
            chunks = []
            
            # MARKER-first for all scanners (respects vulnerability boundaries)
            # Then refine with tokenizer to respect max_chunk_size
            subs = split_text_to_subchunks(block_text, target_size=8000,
                                            profile_config=profile_config)
            for s in subs:
                chunks.extend(get_token_based_chunks(
                    s,
                    max_tokens=max_chunk_size,
                    reserve_for_response=reserve_for_response,
                    tokenizer=tokenizer
                ))
        block_chunks_map.append((block, chunks))
        total_chunks += len(chunks)

    # Process with progress bar
    with tqdm(total=total_chunks, desc="Processing blocks", unit="chunk", ncols=80) as pbar:
        for block_idx, (block, chunks) in enumerate(block_chunks_map):
            for chunk in chunks:
                # Monta prompt
                from src.utils.chunking import build_prompt
                prompt = build_prompt(chunk, profile_config)

                # A lógica de invocação e retry foi movida para retry_chunk_with_subdivision
                # para centralizar o tratamento de erros e redivisão.
                max_retries = 3 # Default
                vulns = retry_chunk_with_subdivision(
                    chunk, llm, profile_config, max_retries,
                    tokenizer=tokenizer,
                    max_chunk_size=max_chunk_size
                )

                # Contagem de tokens apenas do input (output é contabilizado internamente no retry)
                tokens_input = count_tokens(prompt, tokenizer)

                tokens_info.append({
                    'block_idx': block_idx,
                    'chunk_text': chunk.page_content,
                    'tokens_input': tokens_input
                })

                if profile_config and profile_config.get('reader', '').lower() == 'tenable':
                    all_vulns.extend([v for v in vulns if isinstance(v, dict)])
                else:
                    if block.get('port') is not None or block.get('protocol') is not None or block.get('severity') is not None:
                        for idx, v in enumerate(vulns):
                            if not isinstance(v, dict):
                                tqdm.write(f"[WARN] Ignoring non-dict item in vulns: {type(v)} - {repr(v)[:100]}")
                                continue
                            port_val = block['port']
                            if port_val is not None:
                                try:
                                    port_val = int(port_val)
                                except Exception:
                                    pass
                            is_first_block_first_vuln = (block_idx == 0 and idx == 0)
                            def is_invalid_port(val):
                                if val is None or val == '' or val == 'null':
                                    return True
                                try:
                                    if isinstance(val, str) and val.isdigit():
                                        return int(val) == 0
                                    elif isinstance(val, int):
                                        return val == 0
                                except:
                                    return True
                                return False
                            def is_invalid_str(val):
                                return val is None or val == '' or val == 'null'
                            port_val_vuln = v.get('port')
                            if is_first_block_first_vuln or is_invalid_port(port_val_vuln):
                                v['port'] = port_val
                            protocol_val_vuln = v.get('protocol')
                            if is_first_block_first_vuln or is_invalid_str(protocol_val_vuln):
                                v['protocol'] = block['protocol']
                            severity_val_vuln = v.get('severity')
                            if is_first_block_first_vuln or is_invalid_str(severity_val_vuln):
                                v['severity'] = block['severity']
                        all_vulns.extend([v for v in vulns if isinstance(v, dict)])
                    else:
                        all_vulns.extend([v for v in vulns if isinstance(v, dict)])
                pbar.update(1)
    # Salva tokens_info em results_tokens
    import os, json
    os.makedirs('results_tokens', exist_ok=True)
    tokens_path = os.path.join('results_tokens', f'tokens_info_{os.getpid()}.json')
    with open(tokens_path, 'w', encoding='utf-8') as f:
        json.dump(tokens_info, f, ensure_ascii=False, indent=2)
    return all_vulns

def cleanup_temp_blocks(temp_dir: str = 'temp_blocks'):
    """Remove all temporary session block files."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
