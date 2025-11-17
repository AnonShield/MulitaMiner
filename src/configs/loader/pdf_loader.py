import os
from langchain.schema import Document
import pdfplumber

def extract_visual_layout_from_pdf(pdf_path):
    """
    Extrai o layout visual EXATO do PDF usando pdfplumber em memória
    Preserva posicionamento, espaçamento e estrutura visual
    """
    print(f"Extraindo layout visual do PDF: {os.path.basename(pdf_path)}")
    try:
        with pdfplumber.open(pdf_path) as pdf:
            conteudo_visual_completo = ""
            print(f"Total de páginas encontradas: {len(pdf.pages)}")
            for num_pagina, pagina in enumerate(pdf.pages, 1):
                print(f"Processando página {num_pagina}...")
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
                        linha_preservada = linha.replace('\t', '    ')
                        texto_processado += linha_preservada + '\n'
                    conteudo_visual_completo += texto_processado
                    conteudo_visual_completo += "\n"
                else:
                    conteudo_visual_completo += f"[Página {num_pagina} - Sem texto detectado]\n\n"
            if not conteudo_visual_completo.strip():
                print("Aviso: Nenhum texto foi extraído do PDF. O arquivo pode estar corrompido ou ser apenas imagens.")
                return None
            return [Document(page_content=conteudo_visual_completo.rstrip() + '\n', metadata={"source": pdf_path, "extraction_method": "pdfplumber_visual"})]
    except Exception as e:
        print(f"Erro ao extrair layout visual: {e}")
        return None

def load_pdf_with_pypdf2(pdf_path):
    """Função mantida para compatibilidade - agora usa extração visual"""
    return extract_visual_layout_from_pdf(pdf_path)
import os
from langchain.schema import Document
import pdfplumber

def extract_visual_layout_from_pdf(pdf_path):
    """
    Extrai o layout visual EXATO do PDF usando pdfplumber em memória
    Preserva posicionamento, espaçamento e estrutura visual
    """
    print(f"Extraindo layout visual do PDF: {os.path.basename(pdf_path)}")
    try:
        with pdfplumber.open(pdf_path) as pdf:
            conteudo_visual_completo = ""
            print(f"Total de páginas encontradas: {len(pdf.pages)}")
            for num_pagina, pagina in enumerate(pdf.pages, 1):
                print(f"Processando página {num_pagina}...")
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
                        linha_preservada = linha.replace('\t', '    ')
                        texto_processado += linha_preservada + '\n'
                    conteudo_visual_completo += texto_processado
                    conteudo_visual_completo += "\n"
                else:
                    conteudo_visual_completo += f"[Página {num_pagina} - Sem texto detectado]\n\n"
            if not conteudo_visual_completo.strip():
                print("Aviso: Nenhum texto foi extraído do PDF. O arquivo pode estar corrompido ou ser apenas imagens.")
                return None
            return [Document(page_content=conteudo_visual_completo.rstrip() + '\n', metadata={"source": pdf_path, "extraction_method": "pdfplumber_visual"})]
    except Exception as e:
        print(f"Erro ao extrair layout visual: {e}")
        return None

def load_pdf_with_pypdf2(pdf_path):
    """Função mantida para compatibilidade - agora usa extração visual"""
    return extract_visual_layout_from_pdf(pdf_path)
