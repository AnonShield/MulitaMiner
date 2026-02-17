import os
import datetime

from converters.csv_converter import CSVConverter, TSVConverter
from converters.xlsx_converter import XLSXConverter

def execute_conversions(json_file_path, args):
    """
    Executa conversões baseadas nos argumentos fornecidos
    """
    if args.convert == 'none':
        return []
    print(f"\n=== CONVERSÃO DE FORMATOS ===")
    converted_files = []
    if args.convert == 'all':
        formats = ['csv', 'tsv', 'xlsx']
        for format_type in formats:
            try:
                result = convert_single_format(json_file_path, format_type, args)
                if result:
                    converted_files.append(result)
            except Exception as e:
                print(f"Erro ao converter para {format_type.upper()}: {e}")
    else:
        result = convert_single_format(json_file_path, args.convert, args)
        if result:
            converted_files.append(result)
    return converted_files

def convert_single_format(json_file_path, format_type, args):
    """
    Converte para um formato específico.
    O nome do arquivo convertido segue o padrão do JSON de origem (incluindo modelo e timestamp).
    """
    try:
        base_name = os.path.splitext(os.path.basename(json_file_path))[0]
        # Gera o nome do arquivo convertido com a extensão correta
        # Mantém o nome base do JSON (que já inclui modelo e timestamp)
        if args.output and args.convert != 'all':
            # Se for xlsx, força extensão .xlsx
            if format_type == 'xlsx':
                output_file = os.path.splitext(args.output)[0] + '.xlsx'
            elif format_type == 'csv':
                output_file = os.path.splitext(args.output)[0] + '.csv'
            elif format_type == 'tsv':
                output_file = os.path.splitext(args.output)[0] + '.tsv'
            else:
                output_file = args.output
        else:
            if args.output_dir:
                output_file = os.path.join(args.output_dir, f"{base_name}.{format_type}")
            else:
                # Usa o mesmo nome base do JSON (já tem modelo + timestamp)
                output_file = f"{base_name}.{format_type}"
        if format_type == 'csv':
            converter = CSVConverter(
                delimiter=args.csv_delimiter,
                encoding=args.csv_encoding,
                include_metadata=False
            )
        elif format_type == 'tsv':
            converter = TSVConverter(encoding=args.csv_encoding, include_metadata=False)
        elif format_type == 'xlsx':
            converter = XLSXConverter()
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
        result = converter.convert(json_file_path, output_file)
        print(f"{format_type.upper()}: {result}")
        return result
    except Exception as e:
        print(f" Erro ao converter para {format_type.upper()}: {e}")
        return None