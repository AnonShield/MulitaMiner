import os
import json
from glob import glob
import argparse
import re

# Preços por 1M de tokens (USD). ⚠️ CONFERIR na página oficial (mudam + têm desconto off-peak).
# DeepSeek: "deepseek-coder" hoje é alias de "deepseek-chat" (V3.x) — use o preço do deepseek-chat.
#   'cache_hit' = input que bateu no cache (bem mais barato); 'input' = input cache-miss; 'output' = saída.
#   Os 3 só são usados com o usage REAL (results_tokens/usage_real_*.jsonl) via `calc_real_usage`.
LLM_PRICES = {
    "gpt5": {"input": 0.25, "output": 2.0},
    "deepseek": {"input": 0.14, "output": 0.28, "cache_hit": 0.0028},  # deepseek-v4-flash (aliases chat/coder caem aqui), USD/1M: cache-miss / output / cache-hit (jun/2026)
    "llama3": {"input": 0.59, "output": 0.79},
    "llama4": {"input": 0.11, "output": 0.34},
    "gpt4": {"input": 0.15, "output": 0.6},
}

# Map model names to LLM_PRICES keys
MODEL_NAME_MAPPING = {
    "llama-3.3-70b-versatile": "llama3",
    "meta-llama/llama-4-scout-17b-16e-instruct": "llama4",
    "gpt-4o-mini-2024-07-18": "gpt4",
    "gpt-5-mini-2025-08-07": "gpt5",
    "deepseek-coder": "deepseek",
}

def normalize_model_name(name: str) -> str:
    """Normalize model names for consistent comparison (/ and : become _)."""
    return name.lower().replace('/', '_').replace(':', '_').replace('-', '_').replace('.', '_')

def calc_tokens_and_cost(tokens_dir):
    files = glob(os.path.join(tokens_dir, '*_tokens.json'))
    llm_totals = {}
    llm_costs = {}
    for fpath in files:
        fname = os.path.basename(fpath)
        parts = fname.lower().split('_')
        llm = None
        
        # Extract potential model name from filename
        fname_no_ext = fname.replace('_tokens.json', '')
        fname_normalized = normalize_model_name(fname_no_ext)
        
        # Check against all known model names
        for original_name, key in MODEL_NAME_MAPPING.items():
            if normalize_model_name(original_name) in fname_normalized:
                llm = key
                break
        
        # If not found, try simple key matching
        if not llm:
            for p in parts:
                if p in LLM_PRICES:
                    llm = p
                    break
        
        # Try prefix matching
        if not llm:
            for p in parts:
                for key in LLM_PRICES:
                    if p.startswith(key):
                        llm = key
                        break
                if llm:
                    break
        
        # Try substring matching
        if not llm:
            for p in parts:
                for key in LLM_PRICES:
                    if key in p:
                        llm = key
                        break
                if llm:
                    break
        
        if not llm:
            llm = 'unknown'
        
        with open(fpath, encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception:
                continue
        file_input = sum(chunk.get('tokens_input', 0) for chunk in data)
        file_output = sum(chunk.get('tokens_output', 0) for chunk in data)
        if llm not in llm_totals:
            llm_totals[llm] = {'input': 0, 'output': 0, 'files': 0}
            llm_costs[llm] = 0.0
        llm_totals[llm]['input'] += file_input
        llm_totals[llm]['output'] += file_output
        llm_totals[llm]['files'] += 1
        if llm in LLM_PRICES:
            cost = (file_input / 1_000_000) * LLM_PRICES[llm]['input'] + (file_output / 1_000_000) * LLM_PRICES[llm]['output']
            llm_costs[llm] += cost
    total_all_tokens = sum(stats['input'] + stats['output'] for stats in llm_totals.values())
    total_cost = sum(llm_costs.values())
    return llm_totals, llm_costs, total_all_tokens, total_cost

def _price_key(name):
    """Mapeia o nome do --llm pra uma chave de LLM_PRICES. Modelos locais (Ollama) = None (sem custo de API)."""
    n = normalize_model_name(name or "")
    if "_local" in n:
        return None  # roda local -> sem custo de API
    for original, key in MODEL_NAME_MAPPING.items():
        if normalize_model_name(original) in n:
            return key
    for key in LLM_PRICES:
        if key in n:
            return key
    return None


def calc_real_usage(tokens_dir):
    """Lê os usage_real_*.jsonl (usage REAL da API) e calcula o custo com a tabela escalonada.

    Para o DeepSeek usa o split de cache: custo = cache_hit*preço_hit + cache_miss*preço_input + output*preço_output.
    Retorna {llm: {input, output, cache_hit, cache_miss, cost}}. cost=None se o modelo não tem preço (ex.: local).
    """
    files = glob(os.path.join(tokens_dir, "usage_real_*.jsonl"))
    agg = {}
    for fp in files:
        with open(fp, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                llm = r.get("llm") or "unknown"
                a = agg.setdefault(llm, {"input": 0, "output": 0, "cache_hit": 0, "cache_miss": 0})
                a["input"] += r.get("input_tokens") or 0
                a["output"] += r.get("output_tokens") or 0
                a["cache_hit"] += r.get("cache_hit_tokens") or 0
                a["cache_miss"] += r.get("cache_miss_tokens") or 0
    out = {}
    for llm, a in agg.items():
        key = _price_key(llm)
        price = LLM_PRICES.get(key) if key else None
        cost = None
        if price:
            if price.get("cache_hit") is not None and (a["cache_hit"] or a["cache_miss"]):
                cost = (a["cache_hit"] / 1e6) * price["cache_hit"] + (a["cache_miss"] / 1e6) * price["input"] + (a["output"] / 1e6) * price["output"]
            else:
                cost = (a["input"] / 1e6) * price["input"] + (a["output"] / 1e6) * price["output"]
        out[llm] = {**a, "cost": cost}
    return out


def calc_tokens_cost_llm(tokens_dir, llm_name, show_files=False, price_per_1M=None):
    pattern = os.path.join(tokens_dir, f"*{llm_name}*.json")
    files = glob(pattern)
    total_input = 0
    total_output = 0
    for fpath in files:
        with open(fpath, encoding='utf-8') as f:
            data = json.load(f)
        file_input = sum(chunk.get('tokens_input', 0) for chunk in data)
        file_output = sum(chunk.get('tokens_output', 0) for chunk in data)
        total_input += file_input
        total_output += file_output
        if show_files:
            print(f"{os.path.basename(fpath)}: input={file_input}, output={file_output}, total={file_input+file_output}")
    print(f"\nSummary for LLM: {llm_name}")
    print(f"Total files: {len(files)}")
    print(f"Tokens sent (input): {total_input}")
    print(f"Tokens received (output): {total_output}")
    print(f"Total tokens: {total_input + total_output}")
    if price_per_1M:
        total_cost = (total_input + total_output) / 1_000_000 * price_per_1M
        print(f"Estimated cost (@{price_per_1M:.4f} USD/1M): ${total_cost:.4f}")

def main():
    parser = argparse.ArgumentParser(description="Token and cost summary for LLM usage in vulnerability extraction.")
    subparsers = parser.add_subparsers(dest='mode', required=True)

    parser_all = subparsers.add_parser('all', help='Summary of tokens and costs for all LLMs')
    parser_all.add_argument('--tokens-dir', type=str, default='results_tokens', help='Directory of token files')

    parser_llm = subparsers.add_parser('llm', help='Summary of tokens and costs for a specific LLM')
    parser_llm.add_argument('--llm', type=str, required=True, help='Name of the LLM (e.g., llama3, gpt4, etc.)')
    parser_llm.add_argument('--tokens-dir', type=str, default='results_tokens', help='Directory of token files')
    parser_llm.add_argument('--show-files', action='store_true', help='Show token counts for individual files')
    parser_llm.add_argument('--price-per-1M', type=float, default=None, help='Price per 1M tokens (USD)')

    parser_real = subparsers.add_parser('real', help='Custo a partir do usage REAL da API (usage_real_*.jsonl)')
    parser_real.add_argument('--tokens-dir', type=str, default='results_tokens', help='Directory of token files')

    args = parser.parse_args()

    if args.mode == 'all':
        llm_totals, llm_costs, total_all_tokens, total_cost = calc_tokens_and_cost(args.tokens_dir)
        print("Token summary by LLM:")
        for llm, stats in llm_totals.items():
            total = stats['input'] + stats['output']
            print(f"\nLLM: {llm}")
            print(f"  Files: {stats['files']}")
            print(f"  Tokens input: {stats['input']}")
            print(f"  Tokens output: {stats['output']}")
            print(f"  Total tokens: {total}")
            if llm in LLM_PRICES:
                print(f"  Estimated cost: US$ {llm_costs[llm]:.2f}")
            else:
                print("  [!] Model not recognized for cost calculation.")
        print(f"\nTOTAL TOKENS: {total_all_tokens}")
        print(f"TOTAL ESTIMATED COST (US$): {total_cost:.2f}")
    elif args.mode == 'llm':
        calc_tokens_cost_llm(
            tokens_dir=args.tokens_dir,
            llm_name=args.llm,
            show_files=args.show_files,
            price_per_1M=args.price_per_1M
        )
    elif args.mode == 'real':
        rows = calc_real_usage(args.tokens_dir)
        if not rows:
            print(f"Nenhum usage_real_*.jsonl em {args.tokens_dir} (rode uma extração com modelo de API primeiro).")
        for llm, a in rows.items():
            print(f"\nLLM: {llm}")
            print(f"  input REAL: {a['input']:,}  (cache_hit={a['cache_hit']:,}, cache_miss={a['cache_miss']:,})")
            print(f"  output REAL: {a['output']:,}")
            print("  custo REAL: " + (f"US$ {a['cost']:.4f}" if a['cost'] is not None else "— (sem preço / modelo local)"))

if __name__ == "__main__":
    main()
