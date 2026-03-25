import os
import re
import unicodedata
from langchain_core.documents import Document
import pdfplumber
import datetime

def merge_page_continuations(text_pages):
    """
    Mescla seções cortadas por quebras de página.

    Estratégias:
    1. OpenVAS: Detecta marcadores '...continues on next page...'
    2. Tenable: Detecta quebras de sentença sem pontuação final
    """
    if len(text_pages) <= 1:
        return text_pages

    merged_pages = []

    for i, (page_num, page_text) in enumerate(text_pages):
        lines = page_text.split('\n')
        processed_lines = []
        skip_until_next_section = False

        for j, line in enumerate(lines):
            # === ESTRATÉGIA 1: Marcadores explícitos ===
            if '. . . continues on next page' in line.lower() or '...continues on next page' in line.lower() or 'continues on next page' in line.lower():
                continuation_found = False
                for next_page_idx in range(i+1, len(text_pages)):
                    next_page_num, next_page_text = text_pages[next_page_idx]
                    next_lines = next_page_text.split('\n')

                    for k, next_line in enumerate(next_lines):
                        if '. . . continued from previous page' in next_line.lower() or '...continued from previous page' in next_line.lower() or 'continued from previous page' in next_line.lower():
                            # Encontrou continuação - mesclar
                            continuation_text = []
                            for m in range(k+1, len(next_lines)):
                                cont_line = next_lines[m]
                                if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                                    # Verificar se é um header de seção que indica fim da continuação
                                    header_text = cont_line.strip()
                                    if any(keyword in header_text.lower() for keyword in [
                                        'vulnerability detection result', 'solution', 'vulnerability detection method',
                                        'impact', 'product detection result', 'nvt:', 'high ', 'medium ', 'low ', 'log '
                                    ]):
                                        break
                                if cont_line.strip():
                                    continuation_text.append(cont_line)

                            if continuation_text:
                                # Mesclar continuação com a linha anterior
                                if processed_lines and processed_lines[-1].strip():
                                    processed_lines[-1] += ' ' + ' '.join(continuation_text)
                                else:
                                    processed_lines.extend(continuation_text)
                                continuation_found = True

                                # Marcar continuação como processada
                                text_pages[next_page_idx] = (next_page_num,
                                    '\n'.join(next_lines[:k]) + '\n' + '\n'.join(next_lines[k+1:]))
                            break

                    if continuation_found:
                        break

                # Não adicionar o marcador
                continue

            # === ESTRATÉGIA 2: Detecção por contexto ===
            elif _is_incomplete_line(line) and i+1 < len(text_pages):
                # Linha parece incompleta - verificar se próxima página continua
                next_page_text = text_pages[i+1][1]
                next_lines = next_page_text.split('\n')

                # Procurar primeira linha não vazia na próxima página
                continuation_start = None
                for k, next_line in enumerate(next_lines):
                    if next_line.strip():
                        continuation_start = k
                        break

                if continuation_start is not None:
                    # Verificar se a continuação faz sentido contextualmente
                    continuation_text = []
                    for m in range(continuation_start, len(next_lines)):
                        cont_line = next_lines[m]
                        if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                            # Verificar se é um header que indica nova seção
                            header_text = cont_line.strip()
                            if any(keyword in header_text.lower() for keyword in [
                                'solution', 'references', 'cvss', 'cve-', 'plugin details',
                                'synopsis', 'description', 'see also', 'risk information'
                            ]):
                                break
                        if cont_line.strip():
                            continuation_text.append(cont_line)

                    if continuation_text and _makes_sense_as_continuation(line, continuation_text[0]):
                        # Mesclar continuação
                        processed_lines[-1] += ' ' + ' '.join(continuation_text)

                        # Marcar continuação como processada
                        text_pages[i+1] = (text_pages[i+1][0],
                            '\n'.join(next_lines[:continuation_start]) + '\n' +
                            '\n'.join(next_lines[continuation_start + len(continuation_text):]))
                        continue

            elif '. . . continued from previous page' in line.lower() or '...continued from previous page' in line.lower() or 'continued from previous page' in line.lower():
                # Esta é uma continuação já mesclada - pular
                skip_until_next_section = True
                continue
            elif skip_until_next_section:
                # Pular linhas até encontrar próxima seção
                if line.strip() and not line.startswith(' ') and len(line.strip()) > 3:
                    header_text = line.strip()
                    if any(keyword in header_text.lower() for keyword in [
                        'summary', 'detection result', 'detection method', 'impact',
                        'solution', 'insight', 'product detection result', 'log method', 'references', 'nvt:'
                    ]):
                        skip_until_next_section = False
                    else:
                        continue
                else:
                    continue

            processed_lines.append(line)

        merged_pages.append((page_num, '\n'.join(processed_lines)))

    return merged_pages

def _is_incomplete_line(line):
    """
    Verifica se uma linha parece estar incompleta
    """
    line = line.strip()
    if not line:
        return False

    # Linha muito curta provavelmente não está incompleta
    if len(line) < 20:
        return False

    # Se termina com pontuação, provavelmente está completa
    if line.endswith(('.', '!', '?', ':', ';')):
        return False

    # Se termina com palavra completa seguida de espaço, pode estar incompleta
    words = line.split()
    if len(words) > 3 and not line.endswith(' '):
        return True

    return False

def _makes_sense_as_continuation(prev_line, next_line):
    """
    Verifica se a próxima linha faz sentido como continuação da anterior.
    """
    prev_line = prev_line.strip().lower()
    next_line = next_line.strip().lower()

    # Se próxima linha começa com palavra comum, provavelmente é continuação
    common_starts = ['the', 'a', 'an', 'and', 'or', 'but', 'however', 'therefore', 'thus', 'hence']

    first_word = next_line.split()[0] if next_line.split() else ""
    if first_word in common_starts:
        return True

    # Se próxima linha começa com minúscula, provavelmente continua
    if next_line and next_line[0].islower():
        return True

    return False

def extract_visual_layout_from_pdf(pdf_path):
    print(f"Extracting visual layout from PDF: {os.path.basename(pdf_path)}")
    try:
        with pdfplumber.open(pdf_path) as pdf:
            documentos = []
            print(f"Total pages found: {len(pdf.pages)}")
            paginas_texto = []
            for num_pagina, pagina in enumerate(pdf.pages, 1):
                texto_pagina = pagina.extract_text(
                    layout=True,
                    x_tolerance=1,
                    y_tolerance=1,
                    keep_blank_chars=True
                )
                if texto_pagina:
                    linhas = texto_pagina.split('\n')
                    texto_processado = ""
                    for linha in linhas:
                        # Remove rodapés típicos de relatórios (ex: 'Page X of Y')
                        if re.search(r'Page \d+ of \d+', linha):
                            continue
                        # Remove rodapés com nome do relatório e página
                        if re.search(r'Web Application Scanning Detailed Scan Export:.*Page \d+ of \d+', linha):
                            continue
                        linha_preservada = linha.replace('\t', '    ')
                        texto_processado += linha_preservada + '\n'
                    # Sanitização por página
                    texto_processado = re.sub(r"\(cid:\d+\)", "", texto_processado)
                    texto_processado = texto_processado.replace('→', '->')
                    texto_processado = texto_processado.replace('’', "'")
                    texto_processado = texto_processado.replace('“', '"').replace('”', '"')
                    texto_processado = re.sub(r"[ ]{2,}", ' ', texto_processado)
                    paginas_texto.append((num_pagina, texto_processado.rstrip() + '\n'))
                else:
                    paginas_texto.append((num_pagina, f"[Página {num_pagina} - Sem texto detectado]\n\n"))




            # MESCLAR SEÇÕES CORTADAS POR PAGE BREAKS
            paginas_texto = merge_page_continuations(paginas_texto)


            # Extrair o texto completo do PDF
            texto_completo = ''.join([p[1] for p in paginas_texto])
            
            # Normalizar ligaduras tipográficas (ﬁ → fi, ﬂ → fl, etc.)
            # Isso é importante pois PDFs frequentemente usam ligaduras que são caracteres únicos
            texto_completo = unicodedata.normalize('NFKC', texto_completo)

            # Encontrar início da primeira vulnerabilidade
            # OpenVAS: marcador 'NVT:'
            # Tenable: tudo até o primeiro 'Web Application Scanning Detailed Scan Export...' após 'Scan Results'
            # Unifica separação usando os mesmos padrões do chunking
            scanner = None
            if 'openvas' in os.path.basename(pdf_path).lower():
                scanner = 'openvas'
            elif 'tenable' in os.path.basename(pdf_path).lower():
                scanner = 'tenable'

            if scanner == 'openvas':
                marker_pattern = r'^\s*NVT:'
                match_inicio_vuln = re.search(marker_pattern, texto_completo, re.MULTILINE)
                if match_inicio_vuln:
                    start_pos = match_inicio_vuln.start()
                    sumario = texto_completo[:start_pos]
                    texto_extracao = texto_completo[start_pos:]
                    print(f"[VISUAL] Table of contents extracted up to {start_pos} characters using marker '{marker_pattern}'.")
                else:
                    sumario = ''
                    texto_extracao = texto_completo
                    print(f"[VISUAL] No marker '{marker_pattern}' found. Table of contents empty.")
            
            elif scanner == 'tenable':
                export_marker = 'Web Application Scanning Detailed Scan Export:'

                # Procura o primeiro sinal de conteúdo real de vulnerabilidade
                # Pode ser o header formal OU o bloco BASE sem header (CVSS, Plugin Details)
                early_patterns = [
                    re.compile(r'VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+PLUGIN\s+ID\s+\d+', re.IGNORECASE),
                    re.compile(r'CVSSV[34]\s+BASE\s+SCORE\s+[\d.]+', re.IGNORECASE),
                    re.compile(r'PUBLICATION\s+DATE\s+\d{4}-\d{2}-\d{2}', re.IGNORECASE),
                ]

                earliest_pos = len(texto_completo)
                for pattern in early_patterns:
                    m = pattern.search(texto_completo)
                    if m and m.start() < earliest_pos:
                        earliest_pos = m.start()

                if earliest_pos < len(texto_completo):
                    # Busca o último export marker antes do conteúdo de vulnerabilidade
                    last_export_pos = texto_completo.rfind(export_marker, 0, earliest_pos)

                    if last_export_pos != -1:
                        line_start_export = texto_completo.rfind('\n', 0, last_export_pos)
                        cut_pos = line_start_export + 1 if line_start_export != -1 else 0
                    else:
                        cut_pos = earliest_pos

                    print(f"[DEBUG] earliest_pos={earliest_pos}")
                    print(f"[DEBUG] last_export_pos={last_export_pos}")
                    print(f"[DEBUG] cut_pos={cut_pos}")

                    sumario = texto_completo[:cut_pos].rstrip()
                    texto_extracao = texto_completo[cut_pos:]
                    texto_extracao = re.sub(r'Web Application Scanning Detailed Scan Export:[^\n]*', '', texto_extracao)
                    print(f"[VISUAL] Tenable WAS: Table of contents extracted up to {cut_pos} characters.")
                else:
                    sumario = ''
                    texto_extracao = texto_completo
                    print("[VISUAL] Tenable WAS: No marker found. Table of contents empty.")
            else:
                sumario = ''
                texto_extracao = texto_completo
                print("[VISUAL] Scanner not identified or without marker. Table of contents empty.")

            # Salvar o layout visual (apenas sumário/índice)
            if sumario.strip():
                documentos.append(Document(
                    page_content=sumario,
                    metadata={
                        "source": pdf_path,
                        "pages": "SUMARIO",
                        "extraction_method": "pdfplumber_visual_SUMMARY"
                    }
                ))

            # Documento de extração (apenas conteúdo após sumário)
            documentos.append(Document(
                page_content=texto_extracao,
                metadata={
                    "source": pdf_path,
                    "pages": "EXTRACAO",
                    "extraction_method": "pdfplumber_visual_EXTRACTION"
                }
            ))

            # Retornar documentos (primeiro sumário, depois extração)
            if not documentos or all(not d.page_content.strip() for d in documentos):
                print("Warning: No text was extracted from PDF. The file may be corrupted or contain only images.")
                return None
            return documentos
    except Exception as e:
        print(f"Error extracting visual layout: {e}")
        return None
    
def save_visual_layout(content, pdf_path):
    """
    Salva o layout visual extraído em arquivo TXT para referência
    """
    base_name = os.path.splitext(os.path.basename(pdf_path))[0]
    output_visual_path = f"visual_layout_extracted_{base_name}.txt"
    try:
        with open(output_visual_path, 'w', encoding='utf-8') as f:
            # Cabeçalho informativo
            f.write(f"Layout Visual Extraído: {os.path.basename(pdf_path)}\n")
            f.write(f"Extraído em: {datetime.datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write(content)
        return output_visual_path
    except Exception as e:
        print(f"Error saving visual layout: {e}")
        return None

def load_pdf_with_pypdf2(pdf_path):
    return extract_visual_layout_from_pdf(pdf_path)
