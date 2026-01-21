import pandas as pd
import json
import openpyxl
from pathlib import Path

def create_combined_excel_for_metrics(
    json_extraction_path: str,
    baseline_excel_path: str,
    output_excel_path: str,
    extraction_sheet_name: str = "Extração Llama3"
):
    """
    Combina um arquivo de extração JSON com um arquivo Excel de baseline em um único
    arquivo Excel para ser usado pelos scripts de métricas.

    Args:
        json_extraction_path (str): Caminho para o arquivo JSON gerado.
        baseline_excel_path (str): Caminho para o arquivo .xlsx da baseline.
        output_excel_path (str): Caminho onde o novo arquivo .xlsx será salvo.
        extraction_sheet_name (str): Nome da nova aba para os dados de extração.
    """
    print(f"Lendo extração JSON de: {json_extraction_path}")
    try:
        with open(json_extraction_path, 'r', encoding='utf-8') as f:
            extraction_data = json.load(f)
        extraction_df = pd.DataFrame(extraction_data)
        print(f"Extração JSON carregada. {len(extraction_df)} vulnerabilidades encontradas.")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Erro ao ler o arquivo JSON de extração: {e}")
        return

    print(f"Lendo baseline Excel de: {baseline_excel_path}")
    try:
        baseline_xls = pd.ExcelFile(baseline_excel_path)
    except FileNotFoundError as e:
        print(f"❌ Erro: Arquivo de baseline Excel não encontrado: {e}")
        return

    print(f"Criando arquivo Excel combinado em: {output_excel_path}")
    with pd.ExcelWriter(output_excel_path, engine='openpyxl') as writer:
        # Copia todas as abas do arquivo de baseline original para o novo arquivo
        for sheet_name in baseline_xls.sheet_names:
            print(f"  Copiando aba da baseline: '{sheet_name}'")
            df = baseline_xls.parse(sheet_name)
            df.to_excel(writer, sheet_name=sheet_name, index=False)

        # Adiciona a extração do JSON como uma nova aba
        print(f"  Adicionando nova aba de extração: '{extraction_sheet_name}'")
        extraction_df.to_excel(writer, sheet_name=extraction_sheet_name, index=False)

    print("✅ Arquivo Excel combinado criado com sucesso.")

if __name__ == '__main__':
    # Caminhos dos arquivos
    JSON_PATH = Path("vulnerabilities_default_tenable.json")
    BASELINE_PATH = Path("metrics/baselines/tenable/TenableWAS_JuiceShop.xlsx")
    
    # O arquivo de saída será colocado na mesma pasta do script de métricas para facilitar
    OUTPUT_PATH = Path("metrics/bert/TenableWAS_JuiceShop_with_extraction.xlsx")

    # Nome da aba para a nova extração
    SHEET_NAME = "Extração Llama3"

    create_combined_excel_for_metrics(
        json_extraction_path=str(JSON_PATH),
        baseline_excel_path=str(BASELINE_PATH),
        output_excel_path=str(OUTPUT_PATH),
        extraction_sheet_name=SHEET_NAME
    )
