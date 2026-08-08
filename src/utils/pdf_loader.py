import os
import re
import unicodedata
from langchain_core.documents import Document
import pdfplumber
import datetime

_CID_MAP = {
    16: '"',
    17: '"',
    27: 'ff',
    28: 'fi',
    29: 'fl',
    30: 'ffi',
    31: 'ffl',
}

def _restore_cid_glyphs(text: str) -> str:
    # "word-part\n   (cid:44)->rest" is one word split across a wrap
    text = re.sub(r'\n[ \t]*\(cid:44\)→', '', text)
    for cid, glyph in _CID_MAP.items():
        text = text.replace(f'(cid:{cid})', glyph)
    # Unknown CIDs are dropped
    text = re.sub(r'\(cid:\d+\)', '', text)
    # De-hyphenate soft-wrapped words ("down-\n loaded" -> "downloaded")
    text = re.sub(r'(\w)-\n[ \t]*(\w)', r'\1\2', text)
    return text

def merge_page_continuations(text_pages):
    """Merge sections cut by page breaks.

    Two strategies: explicit '...continues on next page' markers (OpenVAS)
    and sentence breaks without final punctuation (Tenable).
    """
    if len(text_pages) <= 1:
        return text_pages

    merged_pages = []

    for i, (page_num, page_text) in enumerate(text_pages):
        lines = page_text.split('\n')
        processed_lines = []
        skip_until_next_section = False

        for j, line in enumerate(lines):
            # Strategy 1: explicit continuation markers
            if '. . . continues on next page' in line.lower() or '...continues on next page' in line.lower() or 'continues on next page' in line.lower():
                continuation_found = False
                for next_page_idx in range(i+1, len(text_pages)):
                    next_page_num, next_page_text = text_pages[next_page_idx]
                    next_lines = next_page_text.split('\n')

                    for k, next_line in enumerate(next_lines):
                        if '. . . continued from previous page' in next_line.lower() or '...continued from previous page' in next_line.lower() or 'continued from previous page' in next_line.lower():
                            continuation_text = []
                            for m in range(k+1, len(next_lines)):
                                cont_line = next_lines[m]
                                if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                                    # A section header ends the continuation
                                    header_text = cont_line.strip()
                                    if any(keyword in header_text.lower() for keyword in [
                                        'vulnerability detection result', 'solution', 'vulnerability detection method',
                                        'impact', 'product detection result', 'nvt:', 'high ', 'medium ', 'low ', 'log '
                                    ]):
                                        break
                                if cont_line.strip():
                                    continuation_text.append(cont_line)

                            if continuation_text:
                                if processed_lines and processed_lines[-1].strip():
                                    processed_lines[-1] += ' ' + ' '.join(continuation_text)
                                else:
                                    processed_lines.extend(continuation_text)
                                continuation_found = True

                                # Strip the merged text from the source page
                                text_pages[next_page_idx] = (next_page_num,
                                    '\n'.join(next_lines[:k]) + '\n' + '\n'.join(next_lines[k+1:]))
                            break

                    if continuation_found:
                        break

                # The marker line itself is dropped
                continue

            # Strategy 2: incomplete line, check if the next page continues it
            elif _is_incomplete_line(line) and i+1 < len(text_pages):
                next_page_text = text_pages[i+1][1]
                next_lines = next_page_text.split('\n')

                continuation_start = None
                for k, next_line in enumerate(next_lines):
                    if next_line.strip():
                        continuation_start = k
                        break

                if continuation_start is not None:
                    continuation_text = []
                    for m in range(continuation_start, len(next_lines)):
                        cont_line = next_lines[m]
                        if cont_line.strip() and not cont_line.startswith(' ') and len(cont_line.strip()) > 3:
                            header_text = cont_line.strip()
                            if any(keyword in header_text.lower() for keyword in [
                                'solution', 'references', 'cvss', 'cve-', 'plugin details',
                                'synopsis', 'description', 'see also', 'risk information'
                            ]):
                                break
                        if cont_line.strip():
                            continuation_text.append(cont_line)

                    if continuation_text and _makes_sense_as_continuation(line, continuation_text[0]):
                        processed_lines[-1] += ' ' + ' '.join(continuation_text)

                        text_pages[i+1] = (text_pages[i+1][0],
                            '\n'.join(next_lines[:continuation_start]) + '\n' +
                            '\n'.join(next_lines[continuation_start + len(continuation_text):]))
                        continue

            elif '. . . continued from previous page' in line.lower() or '...continued from previous page' in line.lower() or 'continued from previous page' in line.lower():
                # Already merged above; skip until the next section header
                skip_until_next_section = True
                continue
            elif skip_until_next_section:
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
    """Heuristic: does this line look cut off mid-sentence?"""
    line = line.strip()
    if not line:
        return False

    if len(line) < 20:
        return False

    if line.endswith(('.', '!', '?', ':', ';')):
        return False

    words = line.split()
    if len(words) > 3 and not line.endswith(' '):
        return True

    return False

def _makes_sense_as_continuation(prev_line, next_line):
     """Heuristic: does next_line read as a continuation of prev_line?"""
     prev_line = prev_line.strip().lower()
     next_line = next_line.strip().lower()

     common_starts = ['the', 'a', 'an', 'and', 'or', 'but', 'however', 'therefore', 'thus', 'hence']

     first_word = next_line.split()[0] if next_line.split() else ""
     if first_word in common_starts:
         return True

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
                         # Drop report footers ("Page X of Y", export header)
                         if re.search(r'Page \d+ of \d+', linha):
                             continue
                         if re.search(r'Web Application Scanning Detailed Scan Export:.*Page \d+ of \d+', linha):
                             continue
                         linha_preservada = linha.replace('\t', '    ')
                         texto_processado += linha_preservada + '\n'
                     # Per-page sanitization; CID restoration runs after the join
                     # so cross-page wrap markers can be merged first
                     texto_processado = texto_processado.replace('ÔåÆ', '->')
                     texto_processado = texto_processado.replace('ÔÇÖ', "'")
                     texto_processado = texto_processado.replace('ÔÇ£', '"').replace('ÔÇØ', '"')
                     texto_processado = re.sub(r"[ ]{2,}", ' ', texto_processado)
                     paginas_texto.append((num_pagina, texto_processado.rstrip() + '\n'))
                 else:
                     paginas_texto.append((num_pagina, f"[Página {num_pagina} - Sem texto detectado]\n\n"))

             paginas_texto = merge_page_continuations(paginas_texto)

             texto_completo = ''.join([p[1] for p in paginas_texto])

             texto_completo = unicodedata.normalize('NFKC', texto_completo)
             texto_completo = _restore_cid_glyphs(texto_completo)

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

             if sumario.strip():
                 documentos.append(Document(
                     page_content=sumario,
                     metadata={
                         "source": pdf_path,
                         "pages": "SUMARIO",
                         "extraction_method": "pdfplumber_visual_SUMMARY"
                     }
                 ))

             documentos.append(Document(
                 page_content=texto_extracao,
                 metadata={
                     "source": pdf_path,
                     "pages": "EXTRACAO",
                     "extraction_method": "pdfplumber_visual_EXTRACTION"
                 }
             ))

             # Documents are ordered: summary first, then extraction
             if not documentos or all(not d.page_content.strip() for d in documentos):
                 print("Warning: No text was extracted from PDF. The file may be corrupted or contain only images.")
                 return None
             return documentos
     except Exception as e:
         print(f"Error extracting visual layout: {e}")
         return None

def _resolve_visual_cache_dir(output_dir):
     """Locate the visual_layouts cache dir.

     Inside an experiments tree the cache sits at <results_runs*>/visual_layouts/
     (co-located with the outputs); otherwise it falls back to the project root.
     """
     if output_dir:
         current = os.path.abspath(output_dir)
         # 6 levels is plenty for results_runs/<baseline>/<llm>/<run>/
         for _ in range(6):
             parent = os.path.dirname(current)
             if parent == current:
                 break
             if os.path.basename(current).lower().startswith("results_runs"):
                 return os.path.join(current, "visual_layouts")
             current = parent
     project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
     return os.path.join(project_root, "visual_layouts")


def save_visual_layout(content, pdf_path, process_id=None, output_ext="txt", output_dir=None):
     """Cache the extracted visual layout and return its path (None on error).

     The layout is deterministic per PDF, so later runs of the same file reuse
     the cached copy. process_id is ignored, kept for caller compatibility.
     """
     base_name = os.path.splitext(os.path.basename(pdf_path))[0]
     filename = f"{base_name}.{output_ext}"

     cache_dir = _resolve_visual_cache_dir(output_dir)
     os.makedirs(cache_dir, exist_ok=True)
     cached_path = os.path.join(cache_dir, filename)

     if os.path.isfile(cached_path):
         return cached_path

     try:
         with open(cached_path, 'w', encoding='utf-8') as f:
             f.write(f"Layout Visual Extraído: {os.path.basename(pdf_path)}\n")
             f.write(f"Extraído em: {datetime.datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}\n")
             f.write("=" * 80 + "\n\n")
             f.write(content)
         return cached_path
     except Exception as e:
         print(f"Error saving visual layout: {e}")
         return None

def load_pdf_with_marker(pdf_path):
    """Extract the PDF to Markdown via Marker; returns Documents or None."""
    try:
        from marker.converters.pdf import PdfConverter
        from marker.models import create_model_dict
        from marker.output import text_from_rendered
    except ImportError:
        print("ERROR: marker-pdf not installed. Install with: pip install marker-pdf")
        return None

    try:
        print(f"Extracting PDF with Marker: {os.path.basename(pdf_path)}")

        converter = PdfConverter(artifact_dict=create_model_dict())
        rendered = converter(pdf_path)
        full_text, _, _ = text_from_rendered(rendered)

        # Marker injects <span id="page-X-Y"></span> anchors that would break
        # the downstream header regexes
        full_text = re.sub(r'<span[^>]*></span>\s*', '', full_text)

        if not full_text or not full_text.strip():
            print("Warning: No text extracted by Marker. The file may be corrupted or contain only images.")
            return None
        
        scanner = None
        if 'openvas' in os.path.basename(pdf_path).lower():
            scanner = 'openvas'
        elif 'tenable' in os.path.basename(pdf_path).lower():
            scanner = 'tenable'

        if scanner == 'openvas':
            # Cut at the first severity header, not at "^NVT:": marker fuses
            # severity and NVT into one line, so an NVT cut would drop the first
            # finding. TOC rows start with "|" and do not match.
            marker_pattern = r'^\s*#*\s*(?:Critical|High|Medium|Low|Log)\s+(?:\d+|general)/[a-zA-Z0-9_-]+'
            match_inicio_vuln = re.search(marker_pattern, full_text, re.MULTILINE | re.IGNORECASE)
            if match_inicio_vuln:
                start_pos = match_inicio_vuln.start()
                sumario = full_text[:start_pos]
                texto_extracao = full_text[start_pos:]
                print(f"[MARKER] Table of contents extracted up to {start_pos} characters.")
            else:
                sumario = ''
                texto_extracao = full_text
                print(f"[MARKER] No severity header found. Table of contents empty.")
        elif scanner == 'tenable':
            sumario = ''
            texto_extracao = full_text
            print("[MARKER] Tenable WAS: Treating entire content as extraction.")
        else:
            sumario = ''
            texto_extracao = full_text
            print("[MARKER] Scanner not identified. Treating entire content as extraction.")

        documentos = []
        
        if sumario.strip():
            documentos.append(Document(
                page_content=sumario,
                metadata={
                    "source": pdf_path,
                    "pages": "SUMARIO",
                    "extraction_method": "marker_SUMMARY"
                }
            ))
        
        documentos.append(Document(
            page_content=texto_extracao,
            metadata={
                "source": pdf_path,
                "pages": "EXTRACAO",
                "extraction_method": "marker_EXTRACTION"
            }
        ))
        
        return documentos if documentos else None
        
    except Exception as e:
        print(f"Error extracting with Marker: {e}")
        return None


def load_pdf_with_pypdf2(pdf_path):
     return extract_visual_layout_from_pdf(pdf_path)
