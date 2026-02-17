import os
import json
import csv
import uuid
from datetime import datetime
import argparse
import pandas as pd

# Função para carregar vulnerabilidades de arquivos JSON
def load_vulnerabilities(input_folder):
    vulnerabilities = []
    for file_name in os.listdir(input_folder):
        if file_name.endswith('.json'):
            file_path = os.path.join(input_folder, file_name)
            with open(file_path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    vulnerabilities.extend(data)
                except json.JSONDecodeError:
                    print(f"Erro ao carregar o arquivo JSON: {file_path}")
    return vulnerabilities

# Função para gerar o CSV
def generate_csv(vulnerabilities, output_folder):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4()
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.csv")

    fields = [
        "id", "Name", "description", "detection_result", "detection_method", "impact", "solution", "insight",
        "product_detection_result", "log_method", "cvss", "port", "protocol", "severity", "references",
        "plugin", "identification", "http_info", "source"
    ]

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

    print(f"Dataset gerado com sucesso: {output_file}")

# Função para gerar o JSON
def generate_json(vulnerabilities, output_folder):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4()
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.json")

    # Garante que o campo 'ID' seja o primeiro
    fields = [
        "id", "Name", "description", "detection_result", "detection_method", "impact", "solution", "insight",
        "product_detection_result", "log_method", "cvss", "port", "protocol", "severity", "references",
        "plugin", "identification", "http_info", "source"
    ]
    def order_fields(vuln):
        return {k: vuln.get(k, "") for k in fields}
    ordered_vulns = [order_fields(v) for v in vulnerabilities]
    with open(output_file, 'w', encoding='utf-8') as jsonfile:
        json.dump(ordered_vulns, jsonfile, ensure_ascii=False, indent=4)

    print(f"Dataset gerado com sucesso: {output_file}")

# Função para gerar o JSONL
def generate_jsonl(vulnerabilities, output_folder):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4()
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.jsonl")

    fields = [
        "id", "Name", "description", "detection_result", "detection_method", "impact", "solution", "insight",
        "product_detection_result", "log_method", "cvss", "port", "protocol", "severity", "references",
        "plugin", "identification", "http_info", "source"
    ]
    def order_fields(vuln):
        return {k: vuln.get(k, "") for k in fields}
    with open(output_file, 'w', encoding='utf-8') as jsonlfile:
        for vuln in vulnerabilities:
            jsonlfile.write(json.dumps(order_fields(vuln), ensure_ascii=False) + '\n')

    print(f"Dataset gerado com sucesso: {output_file}")

# Função para gerar o XLSX
def generate_xlsx(vulnerabilities, output_folder):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = uuid.uuid4()
    output_file = os.path.join(output_folder, f"dataset_{timestamp}_{unique_id}.xlsx")

    fields = [
        "id", "Name", "description", "detection_result", "detection_method", "impact", "solution", "insight",
        "product_detection_result", "log_method", "cvss", "port", "protocol", "severity", "references",
        "plugin", "identification", "http_info", "source"
    ]

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

    print(f"Dataset gerado com sucesso: {output_file}")

# Função principal para CLI
def main():
    parser = argparse.ArgumentParser(description="Gera um dataset a partir de extrações JSON.")
    parser.add_argument(
        "--input-folder", 
        type=str, 
        default="jsons", 
        help="Pasta contendo os arquivos JSON de entrada (padrão: jsons)."
    )
    parser.add_argument(
        "--output-folder", 
        type=str, 
        default="data", 
        help="Pasta onde o arquivo será salvo (padrão: data)."
    )
    parser.add_argument(
        "--format", 
        type=str, 
        choices=["csv", "json", "jsonl", "xlsx", "all"], 
        default="csv", 
        help="Formato de saída do dataset (padrão: csv). Use 'all' para gerar todos os formatos."
    )
    args = parser.parse_args()

    if not os.path.exists(args.input_folder):
        print(f"Erro: A pasta de entrada '{args.input_folder}' não existe.")
        return

    os.makedirs(args.output_folder, exist_ok=True)

    vulnerabilities = load_vulnerabilities(args.input_folder)

    if args.format == "csv":
        generate_csv(vulnerabilities, args.output_folder)
    elif args.format == "json":
        generate_json(vulnerabilities, args.output_folder)
    elif args.format == "jsonl":
        generate_jsonl(vulnerabilities, args.output_folder)
    elif args.format == "xlsx":
        generate_xlsx(vulnerabilities, args.output_folder)
    elif args.format == "all":
        generate_csv(vulnerabilities, args.output_folder)
        generate_json(vulnerabilities, args.output_folder)
        generate_jsonl(vulnerabilities, args.output_folder)
        generate_xlsx(vulnerabilities, args.output_folder)

if __name__ == "__main__":
    main()