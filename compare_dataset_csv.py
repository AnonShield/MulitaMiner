import os
import re
import csv
from glob import glob
import pdfplumber
from collections import Counter, defaultdict
from rapidfuzz import fuzz, process

# --- ETAPA 0: Extração de IPs dos PDFs e debug das primeiras linhas ---
PDF_DIR = 'pdfs/'
PDF_REGEX = re.compile(r'^2\.1\s+([\d.]+)', re.MULTILINE)
pdf_files = glob(os.path.join(PDF_DIR, '*.pdf'))

def extrair_texto_pdf(pdf_path):
    texto = ''
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    texto += t + '\n'
    except Exception as e:
        texto += f'ERRO: {e}'
    return texto

# Só extrai os IPs dos PDFs se o arquivo de mapeamento ainda não existir
if not os.path.exists('ips_extraidos_dos_pdfs.txt'):
    with open('ips_extraidos_dos_pdfs.txt', 'w', encoding='utf-8') as out, \
         open('debug_primeiras_linhas_pdfs.txt', 'w', encoding='utf-8') as debug:
        for pdf_path in pdf_files:
            pdf_name = os.path.basename(pdf_path)
            content = extrair_texto_pdf(pdf_path)
            # Salva as 10 primeiras linhas extraídas para debug
            primeiras_linhas = '\n'.join(content.splitlines()[:10])
            debug.write(f'--- {pdf_name} ---\n{primeiras_linhas}\n\n')
            match = PDF_REGEX.search(content)
            if match:
                ip = match.group(1)
                out.write(f'{pdf_name}: IP={ip}\n')
            else:
                out.write(f'{pdf_name}: NÃO ENCONTRADO\n')
    print('Arquivo ips_extraidos_dos_pdfs.txt gerado!')
    print('Arquivo debug_primeiras_linhas_pdfs.txt gerado!')
else:
    print('Arquivo ips_extraidos_dos_pdfs.txt já existe, pulando extração dos PDFs.')

# Caminhos dos arquivos
DATASET_PATH = 'data\dataset_20260228_101711_fd9fd9dc-9df8-4e4d-b1ed-cca66e5c344e.csv'
VULNNET_PATH = 'vulnnet_openvas_17230143.csv'  # csv "baseline"
MAPPING_PATH = 'ips_extraidos_dos_pdfs.txt'  # mapeamento report -> IP
OUTPUT_TXT = 'comparativo_extracao.txt'

# 1. Mapeia o campo 'report' do dataset para o IP real
# ---------------------------------------------------
def map_report_to_ip_from_txt(txt_path=MAPPING_PATH):
    report_to_ip = {}
    with open(txt_path, encoding='utf-8') as f:
        for line in f:
            if ': IP=' in line:
                pdf_name, ip = line.strip().split(': IP=')
                report = pdf_name.lower().replace('openvas_', '').replace('.pdf', '').replace('_', ' ').strip()
                report_to_ip[report] = ip
    return report_to_ip

# 2. Carrega o dataset extraído, já mapeando para IP
# --------------------------------------------------
def load_dataset(dataset_path, report_to_ip):
    dataset = []
    with open(dataset_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            report = row['report'].strip().lower()
            ip = report_to_ip.get(report)
            if not ip:
                report_alt = report.replace('_', ' ').replace('openvas ', '').replace('.pdf', '').strip()
                ip = report_to_ip.get(report_alt)
            if ip:
                dataset.append({'ip': ip, 'name': row['Name'].strip(), 'orig_name': row['Name'], 'report': report})
    return dataset

# 3. Carrega o vulnnet de referência
# ----------------------------------
def load_vulnnet(vulnnet_path):
    vulnnet = defaultdict(list)
    with open(vulnnet_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['IP'].strip()
            nvt_name = row['NVT Name'].strip()
            vulnnet[ip].append(nvt_name)
    return vulnnet

# 4. Pipeline de comparação e geração do relatório
# ------------------------------------------------
def gerar_relatorio():
    # Mapeia report -> IP
    report_to_ip = map_report_to_ip_from_txt()
    # Carrega dataset e vulnnet
    dataset = load_dataset(DATASET_PATH, report_to_ip)
    vulnnet = load_vulnnet(VULNNET_PATH)

    threshold = 85  # similaridade mínima para considerar match

    # Cria multiconjuntos (Counter) para (ip, nvt_name)
    vulnnet_counter = Counter()
    for ip, nvt_names in vulnnet.items():
        for nvt in nvt_names:
            vulnnet_counter[(ip, nvt)] += 1

    dataset_counter = Counter()
    acertos = []  # (ip, dataset_name, vulnnet_name, score)
    inventadas = []  # (ip, dataset_name)
    match_map = {}  # (ip, dataset_name) -> (vulnnet_name, score)

    # Fuzzy match para cada item do dataset
    for item in dataset:
        ip = item['ip']
        name = item['name']
        if ip in vulnnet:
            best_match, score, _ = process.extractOne(name, vulnnet[ip], scorer=fuzz.token_sort_ratio)
            if score >= threshold:
                dataset_counter[(ip, best_match)] += 1
                acertos.append((ip, name, best_match, score))
                match_map[(ip, name)] = (best_match, score)
            else:
                dataset_counter[(ip, name)] += 1
                inventadas.append((ip, name))
        else:
            dataset_counter[(ip, name)] += 1
            inventadas.append((ip, name))

    # Calcula acertos, inventadas e faltantes considerando as contagens
    acertos_count = 0
    for k in dataset_counter:
        if k in vulnnet_counter:
            acertos_count += min(dataset_counter[k], vulnnet_counter[k])

    inventadas_count = 0
    for k in dataset_counter:
        if dataset_counter[k] > vulnnet_counter.get(k, 0):
            inventadas_count += dataset_counter[k] - vulnnet_counter.get(k, 0)

    faltantes_count = 0
    for k in vulnnet_counter:
        if vulnnet_counter[k] > dataset_counter.get(k, 0):
            faltantes_count += vulnnet_counter[k] - dataset_counter.get(k, 0)

    total_vulnnet = sum(vulnnet_counter.values())
    total_dataset = sum(dataset_counter.values())
    pct_acerto = (acertos_count / total_vulnnet * 100) if total_vulnnet else 0
    pct_inventadas = (inventadas_count / total_dataset * 100) if total_dataset else 0
    pct_faltantes = (faltantes_count / total_vulnnet * 100) if total_vulnnet else 0

    # 5. Gera o relatório final
    # ------------------------
    with open(OUTPUT_TXT, 'w', encoding='utf-8') as out:
        out.write(f"Total vulnerabilidades no vulnnet: {total_vulnnet}\n")
        out.write(f"Total vulnerabilidades extraídas: {total_dataset}\n")
        out.write(f"Acertos: {acertos_count} ({pct_acerto:.2f}%)\n")
        out.write(f"Inventadas (no dataset mas não no vulnnet): {inventadas_count} ({pct_inventadas:.2f}%)\n")
        out.write(f"Faltantes (no vulnnet mas não no dataset): {faltantes_count} ({pct_faltantes:.2f}%)\n\n")
        out.write("--- Inventadas (exemplos) ---\n")
        for (ip, name), count in dataset_counter.items():
            diff = count - vulnnet_counter.get((ip, name), 0)
            if diff > 0:
                out.write(f"{ip} | {name} | {diff} a mais\n")
        out.write("\n--- Faltantes (exemplos) ---\n")
        for (ip, nvt), count in vulnnet_counter.items():
            diff = count - dataset_counter.get((ip, nvt), 0)
            if diff > 0:
                out.write(f"{ip} | {nvt} | {diff} faltando\n")
        out.write("\n--- Acertos (dataset_name | vulnnet_name | score) ---\n")
        for ip, name, best_match, score in acertos:
            out.write(f"{ip} | {name} | {best_match} | {score}\n")
    print(f'Relatório gerado em {OUTPUT_TXT}')

if __name__ == '__main__':
    gerar_relatorio()
