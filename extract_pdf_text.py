import sys
from PyPDF2 import PdfReader

def extract_pdf_text(pdf_path, txt_path):
    reader = PdfReader(pdf_path)
    with open(txt_path, "w", encoding="utf-8") as f:
        for page in reader.pages:
            text = page.extract_text()
            if text:
                f.write(text + "\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python extract_pdf_text.py <arquivo.pdf> <saida.txt>")
    else:
        extract_pdf_text(sys.argv[1], sys.argv[2])
