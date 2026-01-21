import pandas as pd
from pathlib import Path
import numpy as np
import re
import sys
import argparse
import os
from typing import Dict, List, Tuple, Optional
from tqdm import tqdm
from rapidfuzz import fuzz
import warnings
warnings.filterwarnings("ignore")

# Configuração de encoding UTF-8 para compatibilidade Windows/Linux
if sys.platform.startswith('win'):
    # Force UTF-8 encoding on Windows
    if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    
    # Set environment variable for subprocess
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Adiciona o diretório raiz ao path para importar o módulo comum
sys.path.insert(0, str(Path(__file__).parents[1]))

# Imports do módulo comum
from common.config import BASELINE_DIR, FUZZY_THRESHOLD, SPARSE_FIELDS, DEFAULT_EXTRACTION_SHEETS
from common.normalization import normalize_name, normalize_field_data
from common.matching import best_fuzzy_match

# =========================
# CONFIG (específico para ROUGE)
# =========================
BASELINE_SHEET = "Vulnerabilities"

# Abas de extração para comparar
EXTRACTION_SHEETS = DEFAULT_EXTRACTION_SHEETS

# Controle de duplicatas na baseline
# False: sem duplicatas legítimas - dedup baseline antes de parear
# True: duplicatas legítimas - cada instância da baseline pode ser matched independentemente
ALLOW_BASELINE_DUPLICATES = False

# =========================
# ROUGE-L METRIC
# =========================
def lcs_length(x: List[str], y: List[str]) -> int:
    m, n = len(x), len(y)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m):
        for j in range(n):
            if x[i] == y[j]:
                dp[i+1][j+1] = dp[i][j] + 1
            else:
                dp[i+1][j+1] = max(dp[i][j+1], dp[i+1][j])
    return dp[m][n]

def rouge_l_score(pred: str, ref: str) -> float:
    pt = str(pred).split()
    rt = str(ref).split()
    if not pt or not rt:
        return 0.0
    lcs = lcs_length(pt, rt)
    prec = lcs / len(pt)
    rec  = lcs / len(rt)
    return (2*prec*rec)/(prec+rec) if (prec+rec) > 0 else 0.0

def process_extraction_comparison(baseline_df: pd.DataFrame, extraction_df: pd.DataFrame, extraction_name: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Processa comparação entre baseline e uma aba de extração."""
    
    print(f"Processando {extraction_name}...")
    
    # Exemplo de normalização (primeiros dados para debug)
    if len(extraction_df) > 0:
        sample_col = 'description' if 'description' in extraction_df.columns else extraction_df.columns[1] 
        sample_baseline = baseline_df.iloc[0][sample_col] if len(baseline_df) > 0 else ""
        sample_extraction = extraction_df.iloc[0][sample_col]
        
        print(f"   Exemplo de normalização ({sample_col}):")
        print(f"     Baseline original: {str(sample_baseline)[:100]}...")
        print(f"     Baseline normalizado: {normalize_field_data(sample_baseline)[:100]}...")
        print(f"     Extração original: {str(sample_extraction)[:100]}...")
        print(f"     Extração normalizado: {normalize_field_data(sample_extraction)[:100]}...")
    
    # Normaliza nomes para pareamento
    baseline_df["_Name_norm"] = baseline_df["Name"].map(normalize_name)
    extraction_df["_Name_norm"] = extraction_df["Name"].map(normalize_name)

    # Tratamento de duplicatas na baseline
    if not ALLOW_BASELINE_DUPLICATES:
        baseline_dedup = baseline_df.drop_duplicates(subset=["_Name_norm"], keep="first")
        if len(baseline_dedup) < len(baseline_df):
            dup_count = len(baseline_df) - len(baseline_dedup)
            print(f"   ℹ️ Removidas {dup_count} duplicatas da baseline (sem duplicatas legítimas)")
    else:
        baseline_dedup = baseline_df.copy()
        baseline_dedup["_baseline_row_id"] = range(len(baseline_dedup))
        print(f"   ℹ️ Mantendo {len(baseline_dedup)} instâncias da baseline (duplicatas legítimas)")
    # 1) Pareamento EXATO
    exact_map: Dict[str, str] = {}
    baseline_set = set(baseline_dedup["_Name_norm"].tolist())
    for n in extraction_df["_Name_norm"]:
        if n in baseline_set:
            exact_map[n] = n

    # 2) Fuzzy para os que faltaram
    baseline_norm_list = baseline_dedup["_Name_norm"].tolist()
    fuzzy_map: Dict[str, str] = {}
    
    # Filtra os que precisam de fuzzy matching
    fuzzy_candidates = [n for n in extraction_df["_Name_norm"] if n not in exact_map and n != ""]
    
    print(f"   🔍 Fuzzy matching: {len(fuzzy_candidates)} vulnerabilidades...")
    for n in tqdm(fuzzy_candidates, desc="   Fuzzy matching", leave=False, disable=len(fuzzy_candidates) < 10):
        match_norm, score = best_fuzzy_match(n, baseline_norm_list)
        if match_norm and score >= FUZZY_THRESHOLD:
            fuzzy_map[n] = match_norm

    # Monta mapping final
    final_map: Dict[str, Optional[str]] = {}
    for n in extraction_df["_Name_norm"]:
        if n in exact_map:
            final_map[n] = exact_map[n]
        elif n in fuzzy_map:
            final_map[n] = fuzzy_map[n]
        else:
            final_map[n] = None

    # Salva debug mapping (será incluído no Excel final)
    debug_rows = []
    for idx, r in extraction_df.iterrows():
        n_show = r["Name"]
        n_norm = r["_Name_norm"]
        m_norm = final_map.get(n_norm)
        if m_norm is None:
            debug_rows.append([n_show, n_norm, None, 0.0, "UNMATCHED"])
        else:
            # Usa RapidFuzz para consistência
            score = fuzz.ratio(n_norm, m_norm) / 100.0
            base_name_orig = baseline_dedup.loc[baseline_dedup["_Name_norm"] == m_norm, "Name"]
            base_name_orig = base_name_orig.iloc[0] if len(base_name_orig) else None
            debug_rows.append([n_show, n_norm, base_name_orig, score, "MATCHED"])
    
    mapping_debug_df = pd.DataFrame(debug_rows, columns=["Extraction_Name", "Extraction_Name_norm", "Baseline_Name_matched", "match_score", "Status"])

    # Índice rápido baseline por nome normalizado
    base_idx = baseline_dedup.set_index("_Name_norm")

    # Colunas comparáveis
    common_cols = [c for c in extraction_df.columns if c not in ["Name", "_Name_norm"] and c in baseline_dedup.columns]
    
    print(f"Colunas comparáveis encontradas: {len(common_cols)}")
    print(f"Colunas: {common_cols}")

    # Tracking de linhas já usadas da baseline (para matching 1:1)
    used_baseline_rows = set()

    # Comparação ROUGE-L
    print(f"   📊 Calculando scores ROUGE-L...")
    records = []
    for _, row in tqdm(extraction_df.iterrows(), total=len(extraction_df), desc="   ROUGE-L scoring", leave=False):
        name_show = row["Name"]
        key = row["_Name_norm"]
        match_norm = final_map.get(key)
        
        if match_norm is None or match_norm not in base_idx.index:
            # Sem par: registra 0 em todas
            out = {"Name": name_show, "_status": "UNMATCHED"}
            for col in common_cols:
                out[f"{col}_rouge_l"] = 0.0
            records.append(out)
            continue

        # Pega candidatos da baseline
        base_match = base_idx.loc[match_norm]
        
        if isinstance(base_match, pd.DataFrame):
            # Múltiplas linhas com mesmo nome ( duplicatas legítimas mode)
            # Filtra apenas as que ainda não foram usadas
            available_candidates = []
            for i in range(len(base_match)):
                row_id = (match_norm, i)
                if row_id not in used_baseline_rows:
                    available_candidates.append((i, base_match.iloc[i]))
            
            if not available_candidates:
                # Todas as instâncias já foram usadas - extraction tem mais que baseline
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_rouge_l"] = 0.0
                records.append(out)
                continue
            
            # Escolhe a candidata com maior similaridade
            best_candidate_idx = available_candidates[0][0]
            best_score = -1
            
            for cand_idx, candidate in available_candidates:
                scores = []
                for col in common_cols:
                    ext_text = normalize_field_data(row[col])
                    base_text = normalize_field_data(candidate[col])
                    if ext_text.strip() and base_text.strip():
                        scores.append(rouge_l_score(ext_text, base_text))
                
                if scores:
                    avg_score = sum(scores) / len(scores)
                    if avg_score > best_score:
                        best_score = avg_score
                        best_candidate_idx = cand_idx
            
            base_row = base_match.iloc[best_candidate_idx]
            used_baseline_rows.add((match_norm, best_candidate_idx))
        else:
            # Única linha (sem duplicatas legítimas mode)
            row_id = (match_norm, 0)
            if row_id in used_baseline_rows:
                # Já foi usada (não deveria acontecer no sem duplicatas legítimas mode)
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_rouge_l"] = 0.0
                records.append(out)
                continue
            
            base_row = base_match
            used_baseline_rows.add(row_id)
        
        out = {"Name": name_show, "_status": "OK"}
        
        for col in common_cols:
            # Aplicar normalização consistente em ambos os textos
            extraction_text = normalize_field_data(row[col])
            base_text = normalize_field_data(base_row[col])
            
            # ROUGE-L Score apenas se ambos não estiverem vazios
            if extraction_text.strip() and base_text.strip():
                rouge_score = rouge_l_score(extraction_text, base_text)
            elif not extraction_text.strip() and not base_text.strip():
                # Ambos vazios = match perfeito
                rouge_score = 1.0
            else:
                # Um vazio, outro não = sem match
                rouge_score = 0.0
                
            out[f"{col}_rouge_l"] = rouge_score
            
        records.append(out)

    per_vuln_df = pd.DataFrame(records)
    
    # ==== CATEGORIZAÇÃO ====
    categorization_records = []
    
    # 1) Vulnerabilidades da extração que foram pareadas
    for _, row in per_vuln_df.iterrows():
        if row["_status"] == "OK":
            # Calcula média dos scores ROUGE-L
            rouge_cols = [c for c in row.index if c.endswith("_rouge_l")]
            rouge_scores = [row[c] for c in rouge_cols]
            avg_rouge = sum(rouge_scores) / len(rouge_scores) if rouge_scores else 0.0
            
            # Categoriza baseado na média
            if avg_rouge > 0.7:
                category = "Highly Similar"
            elif avg_rouge > 0.6:
                category = "Moderately Similar"
            elif avg_rouge > 0.4:
                category = "Slightly Similar"
            else:
                category = "Divergent"
            
            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_ROUGE_L": avg_rouge,
                "Category": category,
                "Type": "Matched"
            })
        elif row["_status"] == "UNMATCHED_EXCESS":
            # 2a) Duplicata excedente: extraction tem mais instâncias que baseline
            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_ROUGE_L": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (excess duplicate)"
            })
        else:
            # 2b) Non-existent: da extração sem match na baseline
            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_ROUGE_L": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (LLM invention)"
            })
    
    # 3) Absent: vulnerabilidades da baseline que não foram extraídas
    from collections import Counter
    
    # Conta quantas vezes cada nome normalizado da baseline foi pareado
    # IMPORTANTE: Itera sobre extraction_df, não sobre final_map (que é dict e perde duplicatas)
    matched_counts = Counter()
    for _, row in extraction_df.iterrows():
        extraction_norm = row["_Name_norm"]
        match_norm = final_map.get(extraction_norm)
        if match_norm is not None:
            matched_counts[match_norm] += 1
    
    # Conta quantas vezes cada nome aparece na baseline
    baseline_counts = Counter(baseline_df["_Name_norm"])
    
    # Para cada nome na baseline, calcula quantas instâncias estão ausentes
    for name_norm, total_baseline in baseline_counts.items():
        if name_norm == "":
            continue
        
        matched = matched_counts.get(name_norm, 0)
        # Limita matches ao total da baseline (evita contagem negativa se extração > baseline)
        matched = min(matched, total_baseline)
        absent_count = total_baseline - matched
        
        # Adiciona as instâncias ausentes
        if absent_count > 0:
            # Pega linhas da baseline com esse nome para obter os nomes originais
            baseline_rows = baseline_df[baseline_df["_Name_norm"] == name_norm]
            
            # Se matched > 0, pula as primeiras 'matched' linhas
            # Se matched == 0, todas são absent
            absent_rows = baseline_rows.iloc[matched:] if matched > 0 else baseline_rows
            
            for _, base_row in absent_rows.iterrows():
                categorization_records.append({
                    "Vulnerability_Name": base_row["Name"],
                    "Avg_ROUGE_L": 0.0,
                    "Category": "Absent",
                    "Type": "Absent (not extracted)"
                })
    
    categorization_df = pd.DataFrame(categorization_records)
    
    # Calcula quantas INSTÂNCIAS da baseline foram pareadas (não nomes únicos)
    # Limita cada nome ao máximo de instâncias disponíveis na baseline
    baseline_instances_matched = 0
    for name_norm, matched_count in matched_counts.items():
        baseline_count = baseline_counts.get(name_norm, 0)
        # Conta apenas até o limite da baseline (ignora duplicatas extras da extraction)
        baseline_instances_matched += min(matched_count, baseline_count)
    
    total_baseline_instances = len(baseline_dedup)
    
    # Summary estatísticas
    summary_data = []
    for col in common_cols:
        # Apenas dos que tiveram match
        matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"]
        
        if len(matched_data) > 0:
            rouge_vals = matched_data[f"{col}_rouge_l"].astype(float)
            
            summary_data.append({
                "Column": col,
                "Count_Matched": len(matched_data),
                "Avg_ROUGE_L": float(rouge_vals.mean()),
                "Std_ROUGE_L": float(rouge_vals.std()),
                "Min_ROUGE_L": float(rouge_vals.min()),
                "Max_ROUGE_L": float(rouge_vals.max()),
                "Median_ROUGE_L": float(rouge_vals.median())
            })
        else:
            summary_data.append({
                "Column": col,
                "Count_Matched": 0,
                "Avg_ROUGE_L": 0.0,
                "Std_ROUGE_L": 0.0,
                "Min_ROUGE_L": 0.0,
                "Max_ROUGE_L": 0.0,
                "Median_ROUGE_L": 0.0
            })

    summary_df = pd.DataFrame(summary_data)
    
    return per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances

def parse_arguments():
    """Parse argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description='Compara extrações com baseline usando métricas ROUGE-L'
    )
    
    parser.add_argument('--baseline_file', type=str, required=True,
                       help='Caminho para o arquivo Excel da baseline')
    parser.add_argument('--extraction_file', type=str, required=True,
                       help='Caminho para o arquivo Excel com as extrações')
    parser.add_argument('--output_dir', type=str, required=True,
                       help='Diretório onde salvar os resultados')
    
    return parser.parse_args()

def main():
    # Parse argumentos da linha de comando
    args = parse_arguments()
    
    baseline_file = args.baseline_file
    extraction_file = args.extraction_file
    output_dir = Path(args.output_dir)
    
    print("=== Comparacao de Multiplas Extracoes com Baseline (ROUGE-L) ===")
    
    # Configuração automática para duplicatas (sem interação manual)
    allow_duplicates = True  # Permite duplicatas legítimas por padrão
    print(f"\n[OK] Modo automatico: duplicatas legitimas permitidas")
    
    # Atualiza a configuração globalmente
    global ALLOW_BASELINE_DUPLICATES
    ALLOW_BASELINE_DUPLICATES = allow_duplicates
    
    print(f"\nCarregando arquivo: {baseline_file}")
    
    # Verifica se os arquivos existem
    if not Path(baseline_file).exists():
        print(f"[ERRO] Arquivo baseline nao encontrado: {baseline_file}")
        sys.exit(1)
    
    if not Path(extraction_file).exists():
        print(f"[ERRO] Arquivo de extracao nao encontrado: {extraction_file}")
        sys.exit(1)
    
    # Cria diretório de saída se não existir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Carrega arquivo Excel
    excel_data = pd.ExcelFile(baseline_file)
    
    # Carrega baseline
    print(f"Carregando aba baseline: {BASELINE_SHEET}")
    baseline_df = pd.read_excel(baseline_file, sheet_name=BASELINE_SHEET)
    
    print(f"Baseline carregado - Shape: {baseline_df.shape}")
    print(f"Colunas baseline: {list(baseline_df.columns)}")
    
    # Verifica se precisamos carregar do arquivo de extracao para comparacoes
    extraction_excel_data = pd.ExcelFile(extraction_file)
    
    # Primeiro tenta encontrar abas de extração múltipla
    available_sheets = [sheet for sheet in EXTRACTION_SHEETS if sheet in extraction_excel_data.sheet_names]
    
    # Se não encontrou abas de extração múltipla, verifica se é um arquivo de extração simples
    if not available_sheets and 'Vulnerabilities' in extraction_excel_data.sheet_names:
        print("Arquivo de extração simples detectado - usando aba 'Vulnerabilities'")
        available_sheets = ['Vulnerabilities']
        EXTRACTION_SHEETS_TO_USE = ['Vulnerabilities']
    else:
        EXTRACTION_SHEETS_TO_USE = EXTRACTION_SHEETS
    
    missing_sheets = [sheet for sheet in EXTRACTION_SHEETS_TO_USE if sheet not in extraction_excel_data.sheet_names]
    
    if missing_sheets and available_sheets:
        print(f"\nAbas nao encontradas: {missing_sheets}")
    
    print(f"\nAbas de extracao encontradas: {available_sheets}")
    
    if not available_sheets:
        print("Nenhuma aba de extracao encontrada para comparacao!")
        return

    # prepara o diretório de saída por baseline
    baseline_name = Path(baseline_file).stem
    # sanitize: replace spaces with underscore
    baseline_name = "_".join(baseline_name.split())
    
    # Cria resumo geral das comparações
    general_summary = []
    
    # Processa cada aba de extração
    for extraction_sheet in available_sheets:
        print(f"\n{'='*60}")
        print(f"Processando: {extraction_sheet}")
        print('='*60)
        
        try:
            # Carrega aba de extração
            extraction_df = pd.read_excel(extraction_file, sheet_name=extraction_sheet)
            print(f"Shape da extração: {extraction_df.shape}")
            
            # Processa comparação
            per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances = process_extraction_comparison(
                baseline_df.copy(), 
                extraction_df.copy(), 
                extraction_sheet
            )
            
            # Gera nome do arquivo de saída
            if extraction_sheet == 'Vulnerabilities':
                # Para extração simples, usa o nome do arquivo
                extraction_name = Path(extraction_file).stem.replace('vulnerabilities_', '').replace('_converted', '')
                clean_name = extraction_name.lower()
            else:
                # Para extração múltipla, usa o nome da aba
                clean_name = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            output_file = f"rouge_comparison_{clean_name}.xlsx"
            output_path = output_dir / output_file

            # Salva tudo em um único arquivo Excel com 4 abas
            with pd.ExcelWriter(output_path) as writer:
                per_vuln_df.to_excel(writer, sheet_name="Per_Vulnerability", index=False)
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                categorization_df.to_excel(writer, sheet_name="Categorization", index=False)
                mapping_debug_df.to_excel(writer, sheet_name="Mapping_Debug", index=False)
            
            # Estatísticas do processamento
            unmatched_count = (per_vuln_df["_status"] == "UNMATCHED").sum()
            unmatched_excess_count = (per_vuln_df["_status"] == "UNMATCHED_EXCESS").sum()
            total_nonexistent = unmatched_count + unmatched_excess_count
            matched_count = len(per_vuln_df) - total_nonexistent
            
            # Contagens de categorização
            cat_counts = categorization_df["Category"].value_counts().to_dict()
            
            # Relatório de resultados
            print(f"✅ Comparação concluída!")
            print(f"   → Arquivo: {output_path}")
            print(f"\n   📊 Resumo da Comparação:")
            print(f"      • Instâncias da baseline pareadas: {baseline_instances_matched}/{total_baseline_instances}")
            print(f"      • Vulnerabilidades não extraídas (Absent): {cat_counts.get('Absent', 0)}")
            print(f"      • Vulnerabilidades inventadas (Non-existent): {total_nonexistent}")
            if unmatched_excess_count > 0:
                print(f"        ↳ Duplicatas excedentes: {unmatched_excess_count}")
                print(f"        ↳ Invenções sem match: {unmatched_count}")
            
            print(f"\n   📊 Categorização de Similaridade:")
            print(f"      • Highly Similar (>0.7): {cat_counts.get('Highly Similar', 0)}")
            print(f"      • Moderately Similar (0.6-0.7): {cat_counts.get('Moderately Similar', 0)}")
            print(f"      • Slightly Similar (0.4-0.6): {cat_counts.get('Slightly Similar', 0)}")
            print(f"      • Divergent (≤0.4): {cat_counts.get('Divergent', 0)}")
            print(f"      • Non-existent (inventadas): {cat_counts.get('Non-existent', 0)}")
            print(f"      • Absent (não extraídas): {cat_counts.get('Absent', 0)}")
            
            # Calcular médias para TODOS os campos ROUGE-L
            rouge_columns = [col for col in per_vuln_df.columns if col.endswith('_rouge_l')]
            extraction_stats = {
                'Extraction': extraction_sheet,
                'Total_Vulnerabilities': len(per_vuln_df),
                'Matched_Vulnerabilities': matched_count,
                'Match_Rate': matched_count / len(per_vuln_df) if len(per_vuln_df) > 0 else 0
            }
            
            # Calcular média geral de todos os campos
            all_rouge_scores = []
            matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"]
            
            if len(matched_data) > 0:
                for rouge_col in rouge_columns:
                    field_avg = matched_data[rouge_col].mean()
                    field_name = rouge_col.replace('_rouge_l', '')
                    extraction_stats[f'{field_name}_rouge_l'] = field_avg
                    all_rouge_scores.append(field_avg)
                
                # Média geral de todos os campos
                extraction_stats['Overall_ROUGE_L_Mean'] = sum(all_rouge_scores) / len(all_rouge_scores) if all_rouge_scores else 0
            else:
                for rouge_col in rouge_columns:
                    field_name = rouge_col.replace('_rouge_l', '')
                    extraction_stats[f'{field_name}_rouge_l'] = 0.0
                extraction_stats['Overall_ROUGE_L_Mean'] = 0.0
            
            print(f"\n   Estatísticas por campo:")
            key_columns = ['description', 'impact', 'solution']
            for col in key_columns:
                if f'{col}_rouge_l' in extraction_stats:
                    rouge_avg = extraction_stats[f'{col}_rouge_l']
                    print(f"   → {col}: ROUGE-L={rouge_avg:.3f}")
            
            print(f"   → Média geral de todos os {len(rouge_columns)} campos: {extraction_stats['Overall_ROUGE_L_Mean']:.3f}")
            
            general_summary.append(extraction_stats)
            
        except Exception as e:
            print(f"[ERRO] Erro ao processar {extraction_sheet}: {e}")
            continue
    
    # Salva resumo geral de todas as extrações
    if general_summary:
        general_df = pd.DataFrame(general_summary)
        summary_path = output_dir / "summary_all_extractions.xlsx"
        general_df.to_excel(summary_path, index=False)
        print(f"\n📊 Resumo geral salvo em: {summary_path}")
    
    print(f"\n{'='*60}")
    print("Todas as comparacoes concluidas!")
    print("\n📊 Arquivos gerados:")
    for extraction_sheet in available_sheets:
        clean_name = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
        print(f"   - {output_dir / f'rouge_comparison_{clean_name}.xlsx'}")
        print(f"       • Per_Vulnerability: Scores ROUGE-L detalhados por campo")
        print(f"       • Summary: Estatísticas agregadas (média, desvio, min, max, mediana)")
        print(f"       • Categorization: Classificação completa (Similarity + Absent + Non-existent)")
        print(f"       • Mapping_Debug: Debug do pareamento de nomes")
    print(f"   - {output_dir / 'summary_all_extractions.xlsx'} (comparação consolidada entre todos os modelos)")

if __name__ == "__main__":
    main()