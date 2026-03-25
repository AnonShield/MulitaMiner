import os
import re
import csv
from glob import glob
import pdfplumber
from collections import Counter, defaultdict
from rapidfuzz import fuzz, process
import pandas as pd

# --- ETAPA 0: Extração de IPs dos PDFs e debug das primeiras linhas ---
PDF_DIR = 'pdfs/'
PDF_REGEX = re.compile(r'^2\.1\s+([\d.]+)', re.MULTILINE)
pdf_files = glob(os.path.join(PDF_DIR, '*.pdf'))

def extract_text_from_pdf(pdf_path):
    text = ''
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    text += t + '\n'
    except Exception as e:
        text += f'ERROR: {e}'
    return text

# Extrai os IPs dos PDFs apenas se o arquivo de mapeamento ainda não existir
if not os.path.exists('extracted_ips.txt'):
    with open('extracted_ips.txt', 'w', encoding='utf-8') as out:
        for pdf_path in pdf_files:
            pdf_name = os.path.basename(pdf_path)
            content = extract_text_from_pdf(pdf_path)
            match = PDF_REGEX.search(content)
            if match:
                ip = match.group(1)
                out.write(f'{pdf_name}: IP={ip}\n')
            else:
                out.write(f'{pdf_name}: NOT FOUND\n')
    print('File extracted_ips.txt generated!')
else:
    print('File extracted_ips.txt already exists, skipping PDF extraction.')

# Caminhos dos arquivos
DATASET_PATH = r'dataset\dataset_20260301_113151_1622da90-cb16-49bd-a78d-e498b7b4bbc5.csv'
VULNNET_PATH = 'dataset/vulnnet_scans_openvas.csv'  # csv "baseline"
MAPPING_PATH = 'extracted_ips.txt'  # mapeamento: report -> IP
OUTPUT_TXT = 'extraction_comparison.txt'

# Função de validação preventiva de integridade do mapeamento
# -----------------------------------------------
def validate_mapping_integrity(mapping_file, dataset_file, vulnnet_file):
    """
    Valida se:
    1. Todos os PDFs na pasta 'pdfs/' estão no arquivo de mapeamento
    2. Todos os reports no dataset estão mapeados
    3. Todos os IPs do Vulnnet tem um correspondente no mapeamento
    """
    from glob import glob
    from pathlib import Path
    
    print("\n" + "="*80)
    print("VALIDACAO DE INTEGRIDADE DO MAPEAMENTO")
    print("="*80)

    # 1. Carrega mapeamento
    mapping_dict = {}
    with open(mapping_file, encoding='utf-8') as f:
        for line in f:
            if ': IP=' in line:
                pdf_name, ip = line.strip().split(': IP=')
                mapping_dict[pdf_name] = ip
            elif ': NOT FOUND' in line:
                pdf_name = line.strip().replace(': NOT FOUND', '')
                mapping_dict[pdf_name] = None
    
    # 2. Valida PDFs na pasta
    pdf_dir = Path('pdfs')
    all_pdfs = set([f.name for f in pdf_dir.glob('*.pdf')])
    pdfs_in_mapping = set(mapping_dict.keys())
    
    missing_pdfs = all_pdfs - pdfs_in_mapping
    extra_pdfs = pdfs_in_mapping - all_pdfs
    pdfs_no_ip = {k: v for k, v in mapping_dict.items() if v is None}
    
    print(f"\n1) PDF Files:")
    print(f"   Total PDFs in folder: {len(all_pdfs)}")
    print(f"   Total PDFs in mapping: {len(pdfs_in_mapping)}")
    
    if missing_pdfs:
        print(f"\n   WARNING: {len(missing_pdfs)} PDFs in folder but NOT in mapping:")
        for pdf in sorted(missing_pdfs)[:5]:
            print(f"     - {pdf}")
        if len(missing_pdfs) > 5:
            print(f"     ... and {len(missing_pdfs) - 5} more")
    else:
        print(f"   OK: All PDFs from folder are in mapping")
    
    if extra_pdfs:
        print(f"\n   WARNING: {len(extra_pdfs)} PDFs in mapping but NOT in folder:")
        for pdf in sorted(extra_pdfs)[:5]:
            print(f"     - {pdf}")
        if len(extra_pdfs) > 5:
            print(f"     ... and {len(extra_pdfs) - 5} more")
    
    if pdfs_no_ip:
        print(f"\n   WARNING: {len(pdfs_no_ip)} PDFs with no extracted IP:")
        for pdf in pdfs_no_ip:
            print(f"     - {pdf}")
    
    # 3. Valida IPs do Vulnnet
    df_vulnnet = pd.read_csv(vulnnet_file)
    ips_in_vulnnet = set(df_vulnnet['IP'].unique())
    ips_in_mapping = set([v for v in mapping_dict.values() if v])
    
    missing_ips = ips_in_vulnnet - ips_in_mapping
    extra_ips = ips_in_mapping - ips_in_vulnnet
    
    print(f"\n2) IPs in Vulnnet:")
    print(f"   Total unique IPs in Vulnnet: {len(ips_in_vulnnet)}")
    print(f"   Total IPs in mapping: {len(ips_in_mapping)}")
    
    if missing_ips:
        print(f"\n   WARNING: {len(missing_ips)} IPs in Vulnnet but NOT in mapping:")
        for ip in sorted(missing_ips)[:5]:
            print(f"     - {ip}")
        if len(missing_ips) > 5:
            print(f"     ... and {len(missing_ips) - 5} more")
    else:
        print(f"   OK: All IPs from Vulnnet are mapped")
    
    if extra_ips:
        print(f"\n   WARNING: {len(extra_ips)} IPs in mapping but NOT in Vulnnet:")
        for ip in sorted(extra_ips)[:5]:
            pdfs = [k for k, v in mapping_dict.items() if v == ip]
            print(f"     - {ip} ({pdfs})")
        if len(extra_ips) > 5:
            print(f"     ... and {len(extra_ips) - 5} more")
    
    # Resumo
    has_issues = bool(missing_pdfs or extra_pdfs or pdfs_no_ip or missing_ips or extra_ips)
    
    print(f"\n" + "="*80)
    if has_issues:
        print("RESULTADO: Existem problemas de integridade que precisam ser resolvidos!")
    else:
        print("RESULTADO: Mapeamento íntegro e consistente. Prosseguindo...")
    print("="*80 + "\n")
    
    return not has_issues

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
    unmapped_reports = []
    
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
            else:
                unmapped_reports.append(report)
    
    # Validação preventiva: detecta reports não mapeados
    if unmapped_reports:
        print("\n" + "="*80)
        print("WARNING: REPORTS WERE NOT MAPPED TO IP!")
        print("="*80)
        print(f"Total unmapped records: {len(unmapped_reports)}")
        print("\nFirst unmapped reports:")
        for report in unmapped_reports[:10]:
            count = sum(1 for r in open(dataset_path, encoding='utf-8').readlines())
            print(f"  - '{report}'")
        if len(unmapped_reports) > 10:
            print(f"  ... and {len(unmapped_reports) - 10} more")
        print("\nThese records will be IGNORED in the report!")
        print("="*80 + "\n")
    
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
def generate_report():
    # Valida integridade do mapeamento ANTES de processar
    if not validate_mapping_integrity(MAPPING_PATH, DATASET_PATH, VULNNET_PATH):
        print("\nCANNOT GENERATE REPORT WITH INCONSISTENT MAPPING!")
        print("Please fix the issues identified above.")
        return
    
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


    # 5. Calcula métricas de avaliação
    # -------------------------------
    # 5. Calcula métricas de avaliação
    # -------------------------------
    precision = (acertos_count / (acertos_count + inventadas_count)) if (acertos_count + inventadas_count) else 0
    recall = (acertos_count / (acertos_count + faltantes_count)) if (acertos_count + faltantes_count) else 0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0


    # Geração do relatório TXT
    with open(OUTPUT_TXT, 'w', encoding='utf-8') as out:
        out.write(f"Total vulnerabilities: {total_vulnnet}\n")
        out.write(f"Total extracted vulnerabilities: {total_dataset}\n\n")
        out.write(f"Recall: {acertos_count} of {total_vulnnet} ({recall:.4f}) (coverage: of the real ones, how many were extracted)\n")
        out.write(f"Invented (in dataset but not in vulnnet): {inventadas_count} ({pct_inventadas:.2f}%)\n")
        out.write(f"Missing (in vulnnet but not in dataset): {faltantes_count} ({pct_faltantes:.2f}%)\n")
        out.write(f"Precision: {precision:.4f} (accuracy: of the total extracted, how many are correct)\n")
        out.write(f"F1-score: {f1_score:.4f} (harmonic mean of precision and recall)\n\n")
    print(f'Report generated at {OUTPUT_TXT}')

    # Geração do XLSX com abas separadas para vulnerabilidades não-existentes e ausentes
    xlsx_path = OUTPUT_TXT.replace('.txt', '.xlsx')
    # Para inventadas: encontrar o report correspondente ao ip
    ip_to_report = {v: k for k, v in report_to_ip.items()}
    invented_rows = []
    for (ip, name), count in dataset_counter.items():
        diff = count - vulnnet_counter.get((ip, name), 0)
        if diff > 0:
            report = ip_to_report.get(ip, '')
            invented_rows.append({
                'report': report,
                'ip': ip,
                'vulnerability': name,
                'count': diff
            })
    missing_rows = []
    for (ip, nvt), count in vulnnet_counter.items():
        diff = count - dataset_counter.get((ip, nvt), 0)
        if diff > 0:
            report = ip_to_report.get(ip, '')
            missing_rows.append({
                'report': report,
                'ip': ip,
                'vulnerability': nvt,
                'count': diff
            })
    # Cria DataFrames
    df_invented = pd.DataFrame(invented_rows)
    df_missing = pd.DataFrame(missing_rows)
    # Salva em abas separadas
    with pd.ExcelWriter(xlsx_path) as writer:
        df_invented.to_excel(writer, sheet_name='non-existent', index=False)
        df_missing.to_excel(writer, sheet_name='absent', index=False)
    print(f'XLSX file generated at {xlsx_path}')

if __name__ == '__main__':
    generate_report()
