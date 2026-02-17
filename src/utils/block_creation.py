import os
import shutil
import re
from tqdm import tqdm
from .chunking import retry_chunk_with_subdivision

def extract_visual_layout_context(visual_layout_path):
    """
    Lê o arquivo de layout visual e extrai contexto inicial (linhas, severity, port, protocol).
    Retorna: (initial_context_lines, initial_severity, initial_port, initial_protocol)
    """
    initial_context_lines = []
    initial_severity = None
    initial_port = None
    initial_protocol = None
    try:
        with open(visual_layout_path, encoding="utf-8") as f:
            layout_lines = [l.strip() for l in f.readlines() if l.strip()]
        # Para Tenable WAS: pega apenas entre 'Scan Results' e o próximo 'Web Application Scanning Detailed Scan Export: ...'
        scan_results_idx = None
        export_idx = None
        for idx, line in enumerate(layout_lines):
            if scan_results_idx is None and line.strip().startswith("Scan Results"):
                scan_results_idx = idx
            elif scan_results_idx is not None and line.startswith("Web Application Scanning Detailed Scan Export:"):
                export_idx = idx
                break
        if scan_results_idx is not None and export_idx is not None:
            context_search_lines = layout_lines[scan_results_idx:export_idx]
        else:
            context_search_lines = layout_lines

        # Busca de baixo para cima pelo primeiro header válido
        header_regex = re.compile(r"^(?:\d+\.\d+\.\d+\s+)?(Critical|High|Medium|Low|Log)\s+(\d+|general)/([a-zA-Z0-9_-]+)", re.IGNORECASE)
        alt_header_regex = re.compile(r"^(High|Medium|Low|Log)\s+(\d+|general)/([a-zA-Z0-9_-]+)", re.IGNORECASE)
        found_idx = None
        for idx in range(len(context_search_lines)-1, -1, -1):
            line = context_search_lines[idx]
            m = header_regex.match(line)
            if not m:
                m = alt_header_regex.match(line)
            if m:
                initial_severity = m.group(1)
                initial_port = m.group(2)
                initial_protocol = m.group(3)
                found_idx = idx
                print(f"[DEBUG] Contexto extraído do visual layout: severity={initial_severity}, port={initial_port}, protocol={initial_protocol}")
                break
        # Define initial_context_lines como as últimas 5 linhas acima do header encontrado (ou todas se não houver)
        if found_idx is not None:
            initial_context_lines = context_search_lines[max(0, found_idx-4):found_idx+1]
        else:
            initial_context_lines = context_search_lines[-5:]
        print(f"[DEBUG] initial_context_lines (auto): {initial_context_lines}")
    except Exception as e:
        print(f"[DEBUG] Erro ao ler visual_layout_path: {e}")
    return initial_context_lines, initial_severity, initial_port, initial_protocol

def create_session_blocks_from_text(report_text: str, temp_dir: str = 'temp_blocks', visual_layout_path: str = None, scanner: str = 'openvas') -> list:
    """
    Cria arquivos temporários de blocos de sessão (por port/protocol) a partir do texto extraído.
    Modularizado por scanner.
    """
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)

    # Extrai contexto do visual layout apenas para OpenVAS
    initial_context_lines, initial_severity, initial_port, initial_protocol = ([], None, None, None)
    if scanner.lower() == 'openvas' and visual_layout_path:
        initial_context_lines, initial_severity, initial_port, initial_protocol = extract_visual_layout_context(visual_layout_path)

    # Modularização por scanner
    if scanner.lower() == 'openvas':
        return _create_blocks_openvas(report_text, temp_dir, initial_context_lines, initial_severity, initial_port, initial_protocol)
    elif scanner.lower() == 'tenable':
        # Para Tenable, nunca usa contexto visual
        return _create_blocks_tenable(report_text, temp_dir, [])
    else:
        # Fallback: bloco único
        block_path = os.path.join(temp_dir, f"block_generic.txt")
        with open(block_path, 'w', encoding='utf-8') as f:
            if initial_context_lines:
                for ctx_line in initial_context_lines:
                    f.write(f"{ctx_line}\n")
                f.write("---\n")
            f.write(report_text)
        return [{
            'file': block_path,
            'port': initial_port,
            'protocol': initial_protocol,
            'severity': initial_severity
        }]

def _create_blocks_openvas(report_text, temp_dir, initial_context_lines, initial_severity, initial_port, initial_protocol):
    # Aceita tanto o formato antigo quanto o novo (ex: '2.1.1 Critical 8019/tcp')
    header_regex = re.compile(r"^(?:\d+\.\d+\.\d+\s+)?(Critical|High|Medium|Low|Log)\s+(\d+|general)/([a-zA-Z0-9_-]+)", re.IGNORECASE)
    lines = report_text.splitlines()
    blocks = []
    current_block = []
    current_port = initial_port
    current_protocol = initial_protocol
    current_severity = initial_severity
    block_idx = 0

    first_nvt_idx = next((i for i, l in enumerate(lines) if l.strip().startswith('NVT:')), None)
    if first_nvt_idx is not None and first_nvt_idx >= 2:
        port_line = lines[first_nvt_idx - 2].strip()
        port_match = header_regex.match(port_line)
        if port_match:
            current_severity = port_match.group(1)
            current_port = port_match.group(2)
            current_protocol = port_match.group(3)
        else:
            alt_match = re.match(r"^(\d+|general)/([a-zA-Z0-9_-]+)", port_line, re.IGNORECASE)
            if alt_match:
                current_port = alt_match.group(1)
                current_protocol = alt_match.group(2)

    for line in lines:
        header_match = header_regex.match(line.strip())
        if header_match:
            if current_block:
                bloco_severity = current_severity
                bloco_port = current_port
                bloco_protocol = current_protocol
                block_idx += 1
                block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}.txt")
                with open(block_path, 'w', encoding='utf-8') as f:
                    if len(blocks) == 0 and initial_context_lines:
                        for ctx_line in initial_context_lines:
                            f.write(f"{ctx_line}\n")
                        f.write("---\n")
                    f.write('\n'.join(current_block))
                if len(blocks) == 0:
                    print(f"[DEBUG] Primeiro bloco salvo com contexto: port={bloco_port}, protocol={bloco_protocol}, severity={bloco_severity}")
                blocks.append({
                    'file': block_path,
                    'port': bloco_port,
                    'protocol': bloco_protocol,
                    'severity': bloco_severity
                })
                current_block = []
            current_severity = header_match.group(1)
            current_port = header_match.group(2)
            current_protocol = header_match.group(3)
        current_block.append(line)

    if current_block:
        block_idx += 1
        bloco_is_first = (len(blocks) == 0)
        bloco_port = current_port
        bloco_protocol = current_protocol
        bloco_severity = current_severity
        if bloco_is_first:
            if bloco_port is None and initial_port is not None:
                bloco_port = initial_port
            if bloco_protocol is None and initial_protocol is not None:
                bloco_protocol = initial_protocol
            if bloco_severity is None and initial_severity is not None:
                bloco_severity = initial_severity
        block_path = os.path.join(temp_dir, f"block_{bloco_severity}_{bloco_port}_{bloco_protocol}_{block_idx}.txt")
        with open(block_path, 'w', encoding='utf-8') as f:
            if bloco_is_first and initial_context_lines:
                print(f"[DEBUG] Escrevendo initial_context_lines no início do bloco: {block_path}")
                for ctx_line in initial_context_lines:
                    f.write(f"{ctx_line}\n")
                f.write("---\n")
            f.write('\n'.join(current_block))
        blocks.append({
            'file': block_path,
            'port': bloco_port,
            'protocol': bloco_protocol,
            'severity': bloco_severity
        })
    return blocks

def _create_blocks_tenable(report_text, temp_dir, initial_context_lines):
    """
    Cria blocos por severidade para Tenable WAS.
    
    Estratégia: Uma única passagem pelo texto, detectando cada header 
    "VULNERABILITY <SEVERITY> PLUGIN ID" e atribuindo todo o conteúdo 
    subsequente até o próximo header à severidade correspondente.
    """
    severidades = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    blocks_por_severidade = {s: [] for s in severidades}
    
    lines = report_text.splitlines()
    
    # Padrão para detectar QUALQUER header de vulnerabilidade
    header_pattern = re.compile(
        r'VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+PLUGIN\s+ID\s+\d+',
        re.IGNORECASE
    )
    
    current_severity = None
    current_block = []
    headers_found = []
    
    for line in lines:
        # Verifica se a linha contém um header de vulnerabilidade
        header_match = header_pattern.search(line)
        
        if header_match:
            # Salva o bloco anterior se existir
            if current_severity and current_block:
                blocks_por_severidade[current_severity].extend(current_block)
            
            # Inicia novo bloco com a severidade encontrada
            current_severity = header_match.group(1).upper()
            current_block = [line]
            headers_found.append(f"{current_severity}: {line.strip()[:80]}")
        elif current_severity:
            # Continua acumulando no bloco atual
            current_block.append(line)
    
    # Salva o último bloco
    if current_severity and current_block:
        blocks_por_severidade[current_severity].extend(current_block)
    
    print(f"[DEBUG] Headers encontrados: {len(headers_found)}")
    for h in headers_found[:5]:
        print(f"  - {h}")
    if len(headers_found) > 5:
        print(f"  ... e mais {len(headers_found) - 5} headers")
    
    # Cria arquivos de bloco apenas para severidades com conteúdo
    blocks = []
    for severidade in severidades:
        bloco = blocks_por_severidade[severidade]
        if bloco:
            block_path = os.path.join(temp_dir, f"block_tenable_{severidade}.txt")
            with open(block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(bloco))
            blocks.append({
                'file': block_path,
                'port': None,
                'protocol': None,
                'severity': severidade
            })
            print(f"[DEBUG] Bloco {severidade}: {len(bloco)} linhas")
    
    print(f"[DEBUG] Severities finais: {[b['severity'] for b in blocks]}")
    print(f"[DEBUG] Total de blocos criados: {len(blocks)}")
    return blocks

def extract_vulns_from_blocks(blocks: list, llm, profile_config: dict, chunk_func) -> list:
    """
    Para cada bloco de sessão, aplica chunking e extrai vulnerabilidades, propagando port/protocol.
    chunk_func: função de chunking (ex: get_token_based_chunks)
    """
    all_vulns = []
    tokens_info = []
    # Contar total de chunks para a barra de progresso
    total_chunks = 0
    block_chunks_map = []
    for block in blocks:
        with open(block['file'], 'r', encoding='utf-8') as f:
            block_text = f.read()
        chunks = chunk_func(block_text, max_tokens=4096, profile_config=profile_config)
        block_chunks_map.append((block, chunks))
        total_chunks += len(chunks)

    from src.utils.llm_utils import validate_json_and_tokens

    # Processar com barra de progresso
    with tqdm(total=total_chunks, desc="Processando blocos", unit="chunk", ncols=80) as pbar:
        for block_idx, (block, chunks) in enumerate(block_chunks_map):
            for chunk in chunks:
                # Monta prompt
                from src.utils.chunking import build_prompt
                prompt = build_prompt(chunk, profile_config)
                # Chama LLM
                response = llm.invoke(prompt).content
                # Conta tokens
                max_tokens = getattr(llm, 'max_tokens', 4096) or 4096
                validation = validate_json_and_tokens(response, chunk.page_content, max_tokens, prompt)
                tokens_input = len(prompt)  # Aproximação: pode usar tokenizer.encode(prompt) se quiser precisão
                tokens_output = len(response)  # Aproximação idem
                tokens_info.append({
                    'block_idx': block_idx,
                    'chunk_text': chunk.page_content[:100],
                    'tokens_input': tokens_input,
                    'tokens_output': tokens_output
                })
                vulns = validation['json_data'] if validation['json_valid'] else []
                # ...existing code for context propagation and all_vulns...
                if profile_config and profile_config.get('reader', '').lower() == 'tenable':
                    all_vulns.extend([v for v in vulns if isinstance(v, dict)])
                else:
                    if block.get('port') is not None or block.get('protocol') is not None or block.get('severity') is not None:
                        for idx, v in enumerate(vulns):
                            if not isinstance(v, dict):
                                tqdm.write(f"[WARN] Ignorando item não-dict em vulns: {type(v)} - {repr(v)[:100]}")
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
                            if len(all_vulns) == 0 and idx == 0:
                                tqdm.write(f"[DEBUG] Primeira vulnerabilidade propagada: port={v['port']}, protocol={v['protocol']}, severity={v['severity']}")
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
    """Remove todos os arquivos temporários de blocos de sessão."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
