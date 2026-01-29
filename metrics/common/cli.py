import argparse
import os
from pathlib import Path

def parse_arguments_common(require_model: bool = False):
    """
    Parser padrão para scripts de métrica (bert, rouge, etc).
    Args:
        require_model: se True, obriga o argumento --model.
    Returns:
        argparse.Namespace com os argumentos.
    """
    parser = argparse.ArgumentParser(
        description='Compara extrações com baseline usando métricas.'
    )
    parser.add_argument('--baseline_file', type=str, required=True,
                       help='Caminho para o arquivo Excel da baseline')
    parser.add_argument('--extraction_file', type=str, required=True,
                       help='Caminho para o arquivo Excel com as extrações')
    parser.add_argument('--output_dir', type=str, required=True,
                       help='Diretório onde salvar os resultados')
    parser.add_argument('--model', type=str, required=require_model, default=None,
                       help='Nome do modelo LLM utilizado (opcional, mas recomendado para nomear o arquivo de saída)')
    parser.add_argument('--allow_duplicates', action='store_true',
                       help='Permite duplicatas legítimas na baseline durante avaliação')
    args = parser.parse_args()
    # Validação básica
    if not os.path.isfile(args.baseline_file):
        parser.error(f"Arquivo de baseline não encontrado: {args.baseline_file}")
    if not os.path.isfile(args.extraction_file):
        parser.error(f"Arquivo de extração não encontrado: {args.extraction_file}")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return args
