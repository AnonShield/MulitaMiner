import os
import json
import csv
import uuid
from datetime import datetime
import argparse
import pandas as pd

FIELDS = [
    "id", "Name", "description", "detection_result", "detection_method", "impact", "solution", "insight",
    "product_detection_result", "log_method", "cvss", "port", "protocol", "severity", "references",
    "plugin", "plugin_details", "instances", "report", "source"
]

# Função para carregar vulnerabilidades de arquivos JSON
def load_vulnerabilities(input_folder):
    vulnerabilities = []
    json_files_used = 0
    reports_info = {}
    for file_name in os.listdir(input_folder):
        if file_name.endswith('.json'):
            json_files_used += 1
            file_path = os.path.join(input_folder, file_name)
            report_name = file_name
            if '_' in report_name:
                report_name = report_name.split('_', 1)[1]  # Remove o prefixo (ex: openvas_)
            report_name = report_name.rsplit('.', 1)[0]  # Remove a extensão .json
            report_name = report_name.replace('_', ' ')   # Substitui underscores por espaço
            vuln_count = 0
            with open(file_path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    # Adiciona o campo 'report' em cada vulnerabilidade
                    for vuln in data:
                        vuln['report'] = report_name
                    vulnerabilities.extend(data)
                    vuln_count = len(data)
                except json.JSONDecodeError:
                    print(f"Error loading json file: {file_path}")
            reports_info[report_name] = {'file_name': file_name, 'vuln_count': vuln_count}
    return vulnerabilities, json_files_used, reports_info

# Função para gerar a tabela de metadata
def generate_metadata_xlsx(vulnerabilities, output_folder, timestamp, unique_id, reports_info):
    output_file = os.path.join(output_folder, f"metadata_{timestamp}_{unique_id}.xlsx")
    # Cria um mapa de contagem por relatório/source/severidade
    metadata = {}
    severities = set()
    for vuln in vulnerabilities:
        report = vuln.get('report', 'unknown')
        source = vuln.get('source', None)
        severity = (vuln.get('severity') or '').strip().capitalize() or 'Unknown'
        severities.add(severity)
        if not source:
            if '_' in report:
                source = report.split('_')[0]
            else:
                source = 'unknown'
        key = (report, source)
        if key not in metadata:
            metadata[key] = {'vulnerability_count': 0}
        metadata[key]['vulnerability_count'] += 1
        if severity not in metadata[key]:
            metadata[key][severity] = 0
        metadata[key][severity] += 1

    # Monta lista de linhas
    rows = []
    for (report, source), counts in metadata.items():
        row = {'report': report, 'source': source, 'vulnerability_count': counts['vulnerability_count']}
        for sev in severities:
            row[sev] = counts.get(sev, 0)
        rows.append(row)

    # Adiciona os relatórios com 0 vulnerabilidades
    for report_name, info in reports_info.items():
        source = 'unknown'
        if '_' in report_name:
            source = report_name.split('_')[0]
        if not any(r['report'] == report_name for r in rows):
            row = {'report': report_name, 'source': source, 'vulnerability_count': 0}
            for sev in severities:
                row[sev] = 0
            rows.append(row)

    # Ordena colunas: report, vulnerability_count, severities..., source
    # Ordem desejada para severidades
    sev_order = ['Critical', 'High', 'Medium', 'Low', 'Log', 'Unknown']
    sev_sorted = [s for s in sev_order if s in severities] + [s for s in sorted(severities) if s not in sev_order]
    columns = ['report', 'vulnerability_count'] + sev_sorted + ['source']
    df = pd.DataFrame(rows)
    df = df[columns]
    df = df.sort_values(by='vulnerability_count', ascending=False)
    df.to_excel(output_file, index=False, engine='openpyxl')
    print(f"Metadata summary generated successfully: {output_file}")

def generate_csv(vulnerabilities, output_folder, timestamp, unique_id):
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.csv")

    fields = FIELDS

    vulnerabilities.sort(key=lambda x: x.get("Name", "").lower())

    def process_field_fieldname(field, value):
        if field == "severity" and isinstance(value, str):
            return value.upper()
        if isinstance(value, list):
            return ";".join(str(v) for v in value) if value else ""
        elif isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False) if value else ""
        elif value is None:
            return ""
        return value

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        for i, vuln in enumerate(vulnerabilities, start=1):
            vuln["id"] = i
            row = {k: process_field_fieldname(k, vuln.get(k, "")) for k in fields}
            writer.writerow(row)

    print(f"Dataset generated successfully: {output_file}")

def generate_json(vulnerabilities, output_folder, timestamp, unique_id):
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.json")

    fields = FIELDS
    def order_fields(vuln):
        return {k: vuln.get(k, "") for k in fields}
    ordered_vulns = [order_fields(v) for v in vulnerabilities]
    with open(output_file, 'w', encoding='utf-8') as jsonfile:
        json.dump(ordered_vulns, jsonfile, ensure_ascii=False, indent=4)

    print(f"Dataset generated successfully: {output_file}")

def generate_jsonl(vulnerabilities, output_folder, timestamp, unique_id):
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.jsonl")

    fields = FIELDS
    def order_fields(vuln):
        return {k: vuln.get(k, "") for k in fields}
    with open(output_file, 'w', encoding='utf-8') as jsonlfile:
        for vuln in vulnerabilities:
            jsonlfile.write(json.dumps(order_fields(vuln), ensure_ascii=False) + '\n')

    print(f"Dataset generated successfully: {output_file}")

def generate_xlsx(vulnerabilities, output_folder, timestamp, unique_id):
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.xlsx")

    fields = FIELDS

    vulnerabilities.sort(key=lambda x: x.get("Name", "").lower())

    # Adiciona IDs sequenciais
    for i, vuln in enumerate(vulnerabilities, start=1):
        vuln["id"] = i

    def process_field_fieldname(field, value):
        if field == "severity" and isinstance(value, str):
            return value.upper()
        if isinstance(value, list):
            return ";".join(str(v) for v in value) if value else ""
        elif isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False) if value else ""
        elif value is None:
            return ""
        return value

    processed = []
    for vuln in vulnerabilities:
        row = {k: process_field_fieldname(k, vuln.get(k, "")) for k in fields}
        processed.append(row)

    df = pd.DataFrame(processed, columns=fields)
    df.to_excel(output_file, index=False, engine='openpyxl')

    print(f"Dataset generated successfully: {output_file}")

# Função principal para CLI
def main():
    parser = argparse.ArgumentParser(description="Generates a dataset from JSON vulnerability files.")
    parser.add_argument(
        "--input-folder", 
        type=str, 
        default="jsons", 
        help="Directory containing the input JSON vulnerability files (default: jsons)"
    )
    parser.add_argument(
        "--output-folder", 
        type=str, 
        default="data", 
        help="Directory where the output file will be saved (default: data)"
    )
    parser.add_argument(
        "--format", 
        type=str, 
        choices=["csv", "json", "jsonl", "xlsx", "all"], 
        default="csv", 
        help="Output format for the dataset (default: csv). Use 'all' to generate all formats."
    )
    args = parser.parse_args()

    if not os.path.exists(args.input_folder):
        print(f"Error: The input folder '{args.input_folder}' does not exist.")
        return

    os.makedirs(args.output_folder, exist_ok=True)

    vulnerabilities, json_files_used, reports_info = load_vulnerabilities(args.input_folder)
    print(f"{json_files_used} json files loaded successfully. Total vulnerabilities: {len(vulnerabilities)}")

    # Gera um único timestamp e id para todos os formatos
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4()

    if args.format == "csv":
        generate_csv(vulnerabilities, args.output_folder, timestamp, unique_id)
    elif args.format == "json":
        generate_json(vulnerabilities, args.output_folder, timestamp, unique_id)
    elif args.format == "jsonl":
        generate_jsonl(vulnerabilities, args.output_folder, timestamp, unique_id)
    elif args.format == "xlsx":
        generate_xlsx(vulnerabilities, args.output_folder, timestamp, unique_id)
    elif args.format == "all":
        generate_csv(vulnerabilities, args.output_folder, timestamp, unique_id)
        generate_json(vulnerabilities, args.output_folder, timestamp, unique_id)
        generate_jsonl(vulnerabilities, args.output_folder, timestamp, unique_id)
        generate_xlsx(vulnerabilities, args.output_folder, timestamp, unique_id)

    # Sempre gera o metadata
    generate_metadata_xlsx(vulnerabilities, args.output_folder, timestamp, unique_id, reports_info)

if __name__ == "__main__":
    main()