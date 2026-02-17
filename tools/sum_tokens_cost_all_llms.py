import os
import json
from glob import glob
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Soma tokens e custo de todas as LLMs em results_tokens.")
    parser.add_argument('--tokens-dir', type=str, default='results_tokens', help='Pasta dos arquivos de tokens')
    parser.add_argument('--price-per-1k', type=float, default=None, help='Preço por 1k tokens (USD)')
    return parser.parse_args()

def main():
    args = parse_args()
    files = glob(os.path.join(args.tokens_dir, '*_tokens.json'))
    if not files:
        print(f"Nenhum arquivo *_tokens.json encontrado em {args.tokens_dir}")
        return
    # Dicionário de preços por modelo (US$ por 1 milhão de tokens)
    LLM_PRICES = {
        "gpt5": {"input": 0.25, "output": 2.0},
        "deepseek": {"input": 0.28, "output": 0.42},
        "llama3": {"input": 0.59, "output": 0.79},
        "llama4": {"input": 0.20, "output": 0.60},
        "gpt4": {"input": 0.30, "output": 1.20},
    }
    llm_totals = {}
    llm_costs = {}
    for fpath in files:
        fname = os.path.basename(fpath)
        # Extrai nome do modelo (padrão: pega primeiro match conhecido)
        parts = fname.lower().split('_')
        llm = None
        # Primeiro tenta match exato
        for p in parts:
            if p in LLM_PRICES:
                llm = p
                break
        # Se não achou, tenta por prefixo (ex: gpt-5-mini-2025-08-07 → gpt-5-mini)
        if not llm:
            for p in parts:
                for key in LLM_PRICES:
                    if p.startswith(key):
                        llm = key
                        break
                if llm:
                    break
        # Se ainda não achou, tenta por substring (deepseek-coder → deepseek)
        if not llm:
            for p in parts:
                for key in LLM_PRICES:
                    if key in p:
                        llm = key
                        break
                if llm:
                    break
        if not llm:
            llm = 'desconhecida'
        with open(fpath, encoding='utf-8') as f:
            data = json.load(f)
        file_input = sum(chunk.get('tokens_input', 0) for chunk in data)
        file_output = sum(chunk.get('tokens_output', 0) for chunk in data)
        if llm not in llm_totals:
            llm_totals[llm] = {'input': 0, 'output': 0, 'files': 0}
            llm_costs[llm] = 0.0
        llm_totals[llm]['input'] += file_input
        llm_totals[llm]['output'] += file_output
        llm_totals[llm]['files'] += 1
        # Calcula custo se modelo conhecido
        if llm in LLM_PRICES:
            # Agora calcula por 1 milhão de tokens
            cost = (file_input / 1_000_000) * LLM_PRICES[llm]['input'] + (file_output / 1_000_000) * LLM_PRICES[llm]['output']
            llm_costs[llm] += cost
    print("Resumo de tokens por LLM:")
    for llm, stats in llm_totals.items():
        total = stats['input'] + stats['output']
        print(f"\nLLM: {llm}")
        print(f"  Arquivos: {stats['files']}")
        print(f"  Tokens input: {stats['input']}")
        print(f"  Tokens output: {stats['output']}")
        print(f"  Tokens totais: {total}")
        if llm in LLM_PRICES:
            print(f"  Custo estimado: US$ {llm_costs[llm]:.2f}")
        else:
            print("  [!] Modelo não reconhecido para cálculo de custo.")
    total_all = sum(stats['input'] + stats['output'] for stats in llm_totals.values())
    print(f"\nTOTAL GERAL DE TOKENS: {total_all}")
    total_cost = sum(llm_costs.values())
    print(f"CUSTO TOTAL ESTIMADO (US$): {total_cost:.2f}")

if __name__ == "__main__":
    main()
