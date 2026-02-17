import os
import json
import argparse
from glob import glob

def parse_args():
    parser = argparse.ArgumentParser(description="Calcula tokens gastos por LLM nas extrações.")
    parser.add_argument('--llm', type=str, required=True, help='Nome da LLM (ex: llama3, gpt4, etc)')
    parser.add_argument('--tokens-dir', type=str, default='results_tokens', help='Pasta dos arquivos de tokens')
    parser.add_argument('--show-files', action='store_true', help='Mostra o total de cada arquivo')
    parser.add_argument('--price-per-1M', type=float, default=None, help='Preço por 1M tokens (USD)')
    return parser.parse_args()

def main():
    args = parse_args()
    pattern = os.path.join(args.tokens_dir, f"*{args.llm}*.json")
    files = glob(pattern)
    if not files:
        print(f"Nenhum arquivo encontrado para LLM '{args.llm}' em {args.tokens_dir}")
        return
    total_input = 0
    total_output = 0
    for fpath in files:
        with open(fpath, encoding='utf-8') as f:
            data = json.load(f)
        file_input = sum(chunk.get('tokens_input', 0) for chunk in data)
        file_output = sum(chunk.get('tokens_output', 0) for chunk in data)
        total_input += file_input
        total_output += file_output
        if args.show_files:
            print(f"{os.path.basename(fpath)}: input={file_input}, output={file_output}, total={file_input+file_output}")
    print(f"\nResumo para LLM: {args.llm}")
    print(f"Total de arquivos: {len(files)}")
    print(f"Tokens enviados (input): {total_input}")
    print(f"Tokens recebidos (output): {total_output}")
    print(f"Tokens totais: {total_input + total_output}")
    if args.price_per_1M:
        total_cost = (total_input + total_output) / 1_000_000 * args.price_per_1M
        print(f"Custo estimado (@{args.price_per_1M:.4f} USD/1M): ${total_cost:.4f}")

if __name__ == "__main__":
    main()
