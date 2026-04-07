import os
import re
import unicodedata
from langchain_core.documents import Document
import pdfplumber
import datetime

def merge_page_continuations(text_pages):
    """
    Merge sections cut by page breaks.

    Strategies:
    1. OpenVAS: Detects markers '...continues on next page...'
    2. Tenable: Detects sentence breaks without final punctuation
    """
    if len(text_pages) <= 1:
        return text_pages

    merged_pages = []

    for i, (page_num, page_text) in enumerate(text_pages):
        lines = page_text.split('\n')
        processed_lines = []
        skip_until_next_section = False

        for j, line in enumerate(lines):
            # === STRATEGY 1: Explicit markers ===
            if '. . . continues on next page' in line.lower() or '...continues on next page' in line.lower() or 'continues on next page' in line.lower():
                continuation_found = False
                for next_page_idx in range(i+1, len(text_pages)):
                    next_page_num, next_page_text = text_pages[next_page_idx]
                    next_lines = next_page_text.split('\n')

                    for k, next_line in enumerate(next_lines):
                        if '. . . continued from previous page' in next_line.lower() or '...continued from previous page' in next_line.lower() or 'continued from previous page' in next_line.lower():
                            # Found continuation - merge
                            continuation_text = []
                            for m in range(k+1, len(next_lines)):
                                cont_line = next_lines[m]
                                if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                                    # Check if it's a section header indicating end of continuation
                                    header_text = cont_line.strip()
                                    if any(keyword in header_text.lower() for keyword in [
                                        'vulnerability detection result', 'solution', 'vulnerability detection method',
                                        'impact', 'product detection result', 'nvt:', 'high ', 'medium ', 'low ', 'log '
                                    ]):
                                        break
                                if cont_line.strip():
                                    continuation_text.append(cont_line)

                            if continuation_text:
                                # Merge continuation with previous line
                                if processed_lines and processed_lines[-1].strip():
                                    processed_lines[-1] += ' ' + ' '.join(continuation_text)
                                else:
                                    processed_lines.extend(continuation_text)
                                continuation_found = True

                                # Mark continuation as processed
                                text_pages[next_page_idx] = (next_page_num,
                                    '\n'.join(next_lines[:k]) + '\n' + '\n'.join(next_lines[k+1:]))
                            break

                    if continuation_found:
                        break

                # Do not add the marker
                continue

            # === STRATEGY 2: Detection by context ===
            elif _is_incomplete_line(line) and i+1 < len(text_pages):
                # Line seems incomplete - check if next page continues
                next_page_text = text_pages[i+1][1]
                next_lines = next_page_text.split('\n')

                # Look for first non-empty line in next page
                continuation_start = None
                for k, next_line in enumerate(next_lines):
                    if next_line.strip():
                        continuation_start = k
                        break

                if continuation_start is not None:
                    # Check if continuation makes contextual sense
                    continuation_text = []
                    for m in range(continuation_start, len(next_lines)):
                        cont_line = next_lines[m]
                        if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                            # Check if it's a header indicating new section
                            header_text = cont_line.strip()
                            if any(keyword in header_text.lower() for keyword in [
                                'solution', 'references', 'cvss', 'cve-', 'plugin details',
                                'synopsis', 'description', 'see also', 'risk information'
                            ]):
                                break
                        if cont_line.strip():
                            continuation_text.append(cont_line)

                    if continuation_text and _makes_sense_as_continuation(line, continuation_text[0]):
                        # Merge continuation
                        processed_lines[-1] += ' ' + ' '.join(continuation_text)

                        # Mark continuation as processed
                        text_pages[i+1] = (text_pages[i+1][0],
                            '\n'.join(next_lines[:continuation_start]) + '\n' +
                            '\n'.join(next_lines[continuation_start + len(continuation_text):]))
                        continue

            elif '. . . continued from previous page' in line.lower() or '...continued from previous page' in line.lower() or 'continued from previous page' in line.lower():
                # This is an already merged continuation - skip
                skip_until_next_section = True
                continue
            elif skip_until_next_section:
                # Skip lines until finding next section
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
    Check if a line seems to be incomplete
    """
    line = line.strip()
    if not line:
        return False

    # Short line probably is not incomplete
    if len(line) < 20:
        return False

    # If ends with punctuation, probably complete
    if line.endswith(('.', '!', '?', ':', ';')):
        return False

    # If ends with complete word followed by space, may be incomplete
    words = line.split()
    if len(words) > 3 and not line.endswith(' '):
        return True

    return False

def _makes_sense_as_continuation(prev_line, next_line):
     """
     Check if next line makes sense as continuation of previous one.
     """
     prev_line = prev_line.strip().lower()
     next_line = next_line.strip().lower()

     # If next line starts with common word, probably is continuation
     common_starts = ['the', 'a', 'an', 'and', 'or', 'but', 'however', 'therefore', 'thus', 'hence']

     first_word = next_line.split()[0] if next_line.split() else ""
     if first_word in common_starts:
         return True

     # If next line starts with lowercase, probably continues
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
                         # Remove typical report footers (ex: 'Page X of Y')
                         if re.search(r'Page \d+ of \d+', linha):
                             continue
                         # Remove footers with report name and page
                         if re.search(r'Web Application Scanning Detailed Scan Export:.*Page \d+ of \d+', linha):
                             continue
                         linha_preservada = linha.replace('\t', '    ')
                         texto_processado += linha_preservada + '\n'
                     # Sanitization by page
                     texto_processado = re.sub(r"\(cid:\d+\)", "", texto_processado)
                     texto_processado = texto_processado.replace('ÔåÆ', '->')
                     texto_processado = texto_processado.replace('ÔÇÖ', "'")
                     texto_processado = texto_processado.replace('ÔÇ£', '"').replace('ÔÇØ', '"')
                     texto_processado = re.sub(r"[ ]{2,}", ' ', texto_processado)
                     paginas_texto.append((num_pagina, texto_processado.rstrip() + '\n'))
                 else:
                     paginas_texto.append((num_pagina, f"[Página {num_pagina} - Sem texto detectado]\n\n"))

             # MERGE SECTIONS CUT BY PAGE BREAKS
             paginas_texto = merge_page_continuations(paginas_texto)

             # Extrair o texto completo do PDF
             texto_completo = ''.join([p[1] for p in paginas_texto])
             
             # Normalize typographic ligatures
             texto_completo = unicodedata.normalize('NFKC', texto_completo)

             # Find start of first vulnerability
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
                     last_export_pos = texto_completo.rfind(export_marker, 0, earliest_pos)
                     if last_export_pos != -1:
                         line_start_export = texto_completo.rfind('\n', 0, last_export_pos)
                         cut_pos = line_start_export + 1 if line_start_export != -1 else 0
                     else:
                         cut_pos = earliest_pos

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

             # Save visual layout (summary/index only)
             if sumario.strip():
                 documentos.append(Document(
                     page_content=sumario,
                     metadata={
                         "source": pdf_path,
                         "pages": "SUMARIO",
                         "extraction_method": "pdfplumber_visual_SUMMARY"
                     }
                 ))

             # Extraction document (only content after summary)
             documentos.append(Document(
                 page_content=texto_extracao,
                 metadata={
                     "source": pdf_path,
                     "pages": "EXTRACAO",
                     "extraction_method": "pdfplumber_visual_EXTRACTION"
                 }
             ))

             # Return documents (first summary, then extraction)
             if not documentos or all(not d.page_content.strip() for d in documentos):
                 print("Warning: No text was extracted from PDF. The file may be corrupted or contain only images.")
                 return None
             return documentos
     except Exception as e:
         print(f"Error extracting visual layout: {e}")
         return None

def save_visual_layout(content, pdf_path, process_id=None):
     """
     Salva o layout visual extraído em arquivo TXT para referência.
     """
     base_name = os.path.splitext(os.path.basename(pdf_path))[0]
     if process_id:
         output_visual_path = f"visual_layout_extracted_{base_name}_{process_id}.txt"
     else:
         output_visual_path = f"visual_layout_extracted_{base_name}.txt"
     try:
         with open(output_visual_path, 'w', encoding='utf-8') as f:
             # Informative header
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
