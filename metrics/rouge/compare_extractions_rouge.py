import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))
import pandas as pd
from pathlib import Path
import numpy as np
import re
import sys
import traceback
from metrics.common.cli import parse_arguments_common
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


def detect_scanner_type(df: pd.DataFrame) -> str:
    """Detecta o tipo de scanner baseado nos campos ou coluna source."""
    if 'source' in df.columns:
        sources = df['source'].dropna().str.upper().unique()
        if 'OPENVAS' in sources:
            return 'openvas'
        elif 'TENABLE' in sources or 'NESSUS' in sources:
            return 'tenable'
    # Fallback: verifica campos típicos
    if 'plugin' in df.columns:
        return 'tenable'
    if 'protocol' in df.columns and df['protocol'].notna().any():
        return 'openvas'
    return 'generic'


def normalize_port(port_value) -> str:
    """Normaliza porta removendo formatação numérica (vírgulas, pontos de milhar)."""
    port_str = str(port_value).strip()
    # Remove vírgulas e pontos usados como separadores de milhar
    port_str = port_str.replace(',', '').replace('.', '')
    # Se ficou vazio ou não é numérico (exceto 'general'), retorna wildcard
    if not port_str or (not port_str.isdigit() and port_str.lower() != 'general'):
        return '*'
    return port_str


def build_composite_key(row: pd.Series, scanner_type: str) -> str:
    """
    Gera chave composta para matching baseada no tipo de scanner.
    - OpenVAS: nome + porta + protocolo
    - Tenable: nome + severidade + plugin
    - Generic: apenas nome
    
    Elementos null/vazios são representados como '*' (wildcard).
    """
    name = normalize_name(str(row.get('Name', '')))
    
    if scanner_type == 'openvas':
        port = normalize_port(row.get('port', ''))
        protocol = str(row.get('protocol', '')).strip().lower() or '*'
        # Lógica especial para 'Services': usar hash do conteúdo
        if name == 'services':
            import json
            row_dict = {k: v for k, v in row.items() if pd.notnull(v)}
            vuln_serialized = json.dumps(row_dict, sort_keys=True, default=str)
            return f"services_exact|{hash(vuln_serialized)}"
        return f"{name}|{port}|{protocol}"
    elif scanner_type == 'tenable':
        severity = str(row.get('severity', '')).strip().lower() or '*'
        plugin = str(row.get('plugin', '')).strip() or '*'
        return f"{name}|{severity}|{plugin}"
    else:
        return name


def keys_match(key1: str, key2: str) -> bool:
    """
    Verifica se duas chaves compostas são compatíveis.
    Wildcards ('*') são compatíveis com qualquer valor.
    """
    parts1 = key1.split('|')
    parts2 = key2.split('|')
    
    if len(parts1) != len(parts2):
        return False
    
    for p1, p2 in zip(parts1, parts2):
        # Wildcard é compatível com qualquer valor
        if p1 == '*' or p2 == '*':
            continue
        # Valores diferentes = não match
        if p1 != p2:
            return False
    
    return True


def key_match_score(key1: str, key2: str) -> float:
    """
    Calcula score de match entre duas chaves (0.0 a 1.0).
    Quanto mais elementos concretos iguais, maior o score.
    Wildcards contribuem parcialmente.
    """
    parts1 = key1.split('|')
    parts2 = key2.split('|')
    
    if len(parts1) != len(parts2):
        return 0.0
    
    score = 0.0
    total = len(parts1)
    
    for p1, p2 in zip(parts1, parts2):
        if p1 == '*' or p2 == '*':
            # Wildcard: contribui parcialmente (0.3) - melhor que nada, pior que match exato
            score += 0.3
        elif p1 == p2:
            # Match exato: contribui totalmente
            score += 1.0
        # Valores diferentes: não contribui (0.0)
    
    return score / total if total > 0 else 0.0


# =========================
# CONFIG (específico para ROUGE)
# =========================
BASELINE_SHEET = "Vulnerabilities"

# Abas de extração para comparar
EXTRACTION_SHEETS = DEFAULT_EXTRACTION_SHEETS

# Controle de duplicatas na baseline
# False: sem duplicatas legítimas - dedup baseline antes de parear
# True: duplicatas legítimas - cada instância da baseline pode ser matched independentemente
# Controle de duplicatas na baseline
# O valor é definido via CLI (allow_duplicates) na main()

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
    
    # Normaliza nomes para pareamento
    baseline_df["_Name_norm"] = baseline_df["Name"].map(normalize_name)
    extraction_df["_Name_norm"] = extraction_df["Name"].map(normalize_name)

    # Detecta tipo de scanner para chaves compostas
    scanner_type = detect_scanner_type(baseline_df)
    print(f"   🛠️ Detected scanner: {scanner_type}")
    
    # Gera chaves compostas para matching mais preciso
    baseline_df["_composite_key"] = baseline_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)
    extraction_df["_composite_key"] = extraction_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)

    # Tratamento de duplicatas na baseline
    if not ALLOW_BASELINE_DUPLICATES:
        baseline_dedup = baseline_df.drop_duplicates(subset=["_Name_norm"], keep="first")
        if len(baseline_dedup) < len(baseline_df):
            dup_count = len(baseline_df) - len(baseline_dedup)
            print(f"   ℹ️ Removidas {dup_count} duplicatas da baseline (sem duplicatas legítimas)")
        baseline_dedup["_baseline_row_id"] = range(len(baseline_dedup))
    else:
        baseline_dedup = baseline_df.copy()
        baseline_dedup["_baseline_row_id"] = range(len(baseline_dedup))
        print(f"   ℹ️ Mantendo {len(baseline_dedup)} instâncias da baseline (duplicatas legítimas)")
    
    # FASE 1: Match por chave composta (suporta wildcards)
    # Para cada chave de extração, encontra todas as chaves da baseline compatíveis
    baseline_composite_list = baseline_dedup["_composite_key"].tolist()
    composite_map: Dict[str, str] = {}
    
    for ext_key in extraction_df["_composite_key"]:
        # Encontra matches compatíveis (considerando wildcards)
        compatible_matches = [(bk, key_match_score(ext_key, bk)) for bk in baseline_composite_list if keys_match(ext_key, bk)]
        if compatible_matches:
            # Escolhe o match com maior score de chave
            best_match = max(compatible_matches, key=lambda x: x[1])
            composite_map[ext_key] = best_match[0]
    
    # FASE 2: Pareamento EXATO por nome
    exact_map: Dict[str, str] = {}
    baseline_set = set(baseline_dedup["_Name_norm"].tolist())
    for n in extraction_df["_Name_norm"]:
        if n in baseline_set:
            exact_map[n] = n

    # FASE 3: Fuzzy para os que faltaram
    baseline_norm_list = baseline_dedup["_Name_norm"].tolist()
    fuzzy_map: Dict[str, str] = {}
    
    # Filtra os que precisam de fuzzy matching
    fuzzy_candidates = [n for n in extraction_df["_Name_norm"] if n not in exact_map and n != ""]
    
    print(f"   🔍 Fuzzy matching: {len(fuzzy_candidates)} vulnerabilidades...")
    for n in tqdm(fuzzy_candidates, desc="   Fuzzy matching", leave=False, disable=len(fuzzy_candidates) < 10):
        match_norm, score = best_fuzzy_match(n, baseline_norm_list)
        if match_norm and score >= FUZZY_THRESHOLD:
            fuzzy_map[n] = match_norm

    # Monta mapa de chave composta da baseline -> nome normalizado da baseline
    baseline_composite_to_name: Dict[str, str] = {}
    for _, br in baseline_dedup.iterrows():
        baseline_composite_to_name[br["_composite_key"]] = br["_Name_norm"]

    # Monta mapping final: prioridade para chave composta > nome exato > fuzzy
    final_map: Dict[str, Optional[str]] = {}
    final_composite_map: Dict[str, Optional[str]] = {}
    
    for idx, r in extraction_df.iterrows():
        n_norm = r["_Name_norm"]
        comp_key = r["_composite_key"]
        
        # Prioridade 1: Match por chave composta
        if comp_key in composite_map:
            baseline_comp_key = composite_map[comp_key]
            baseline_name_norm = baseline_composite_to_name.get(baseline_comp_key, n_norm)
            final_map[n_norm] = baseline_name_norm  # Nome normalizado DA BASELINE
            final_composite_map[comp_key] = baseline_comp_key
        # Prioridade 2: Match exato por nome
        elif n_norm in exact_map:
            final_map[n_norm] = exact_map[n_norm]
            final_composite_map[comp_key] = None
        # Prioridade 3: Fuzzy match
        elif n_norm in fuzzy_map:
            final_map[n_norm] = fuzzy_map[n_norm]
            final_composite_map[comp_key] = None
        else:
            final_map[n_norm] = None
            final_composite_map[comp_key] = None

    # Salva debug mapping (será incluído no Excel final)
    debug_rows = []
    for idx, r in extraction_df.iterrows():
        n_show = r["Name"]
        n_norm = r["_Name_norm"]
        comp_key = r["_composite_key"]
        m_norm = final_map.get(n_norm)
        m_comp = final_composite_map.get(comp_key)
        if m_norm is None:
            debug_rows.append([n_show, n_norm, comp_key, None, 0.0, "UNMATCHED"])
        else:
            # Usa RapidFuzz para consistência
            score = fuzz.ratio(n_norm, m_norm) / 100.0
            base_name_orig = baseline_dedup.loc[baseline_dedup["_Name_norm"] == m_norm, "Name"]
            base_name_orig = base_name_orig.iloc[0] if len(base_name_orig) else None
            match_type = "COMPOSITE" if m_comp else "NAME_ONLY"
            debug_rows.append([n_show, n_norm, comp_key, base_name_orig, score, f"MATCHED_{match_type}"])
    
    mapping_debug_df = pd.DataFrame(debug_rows, columns=["Extraction_Name", "Extraction_Name_norm", "Composite_Key", "Baseline_Name_matched", "match_score", "Status"])

    # Índice rápido baseline por chave composta e por nome
    base_idx_composite = baseline_dedup.set_index("_composite_key")
    base_idx = baseline_dedup.set_index("_Name_norm")

    # Colunas comparáveis
    common_cols = [c for c in extraction_df.columns if c not in ["Name", "_Name_norm", "_composite_key"] and c in baseline_dedup.columns]
    
    print(f"Colunas comparáveis encontradas: {len(common_cols)}")
    print(f"Colunas: {common_cols}")

    # Tracking de linhas já usadas da baseline (usa row_id, igual ao BERTScore)
    used_baseline_rowids = set()  # Usa _baseline_row_id como identificador
    base_idx_rowid = baseline_dedup.set_index("_baseline_row_id")

    # REORDENA: processa primeiro os que têm match composto (mais precisos)
    # Isso evita que match por nome "roube" a baseline de um match composto mais preciso
    extraction_rows = list(extraction_df.iterrows())
    extraction_rows_sorted = sorted(
        extraction_rows,
        key=lambda x: (0 if final_composite_map.get(x[1]["_composite_key"]) else 1)
    )

    # Comparação ROUGE-L
    print(f"[ROUGE] Calculating scores...")
    records = []
    for _, row in tqdm(extraction_rows_sorted, total=len(extraction_rows_sorted), desc="   ROUGE-L scoring", leave=False):
        name_show = row["Name"]
        key = row["_Name_norm"]
        comp_key = row["_composite_key"]
        match_comp = final_composite_map.get(comp_key)
        match_norm = final_map.get(key)

        # Tenta primeiro por chave composta (mais preciso)
        if match_comp and match_comp in base_idx_composite.index:
            base_rows = base_idx_composite.loc[[match_comp]]
            if not isinstance(base_rows, pd.DataFrame):
                base_rows = base_rows.to_frame().T
            found = False
            for _, base_row in base_rows.iterrows():
                base_rowid = base_row["_baseline_row_id"]
                if base_rowid not in used_baseline_rowids:
                    out = {"Name": name_show, "_status": "OK"}
                    for col in common_cols:
                        extraction_text = normalize_field_data(row[col])
                        base_text = normalize_field_data(base_row[col])
                        if extraction_text.strip() and base_text.strip():
                            rouge_score = rouge_l_score(extraction_text, base_text)
                        elif not extraction_text.strip() and not base_text.strip():
                            rouge_score = 1.0
                        else:
                            rouge_score = 0.0
                        out[f"{col}_rouge_l"] = rouge_score
                    records.append(out)
                    used_baseline_rowids.add(base_rowid)
                    found = True
                    break
            if not found:
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_rouge_l"] = 0.0
                records.append(out)
            continue

        # Fallback: match por nome normalizado
        if match_norm is None or match_norm not in base_idx.index:
            out = {"Name": name_show, "_status": "UNMATCHED"}
            for col in common_cols:
                out[f"{col}_rouge_l"] = 0.0
            records.append(out)
            continue

        # Pega candidatos da baseline (fallback por nome)
        base_match = base_idx.loc[match_norm]

        if isinstance(base_match, pd.DataFrame):
            available_candidates = []
            for i in range(len(base_match)):
                candidate = base_match.iloc[i]
                cand_rowid = candidate["_baseline_row_id"]
                if cand_rowid not in used_baseline_rowids:
                    available_candidates.append((i, candidate, cand_rowid))
            if not available_candidates:
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_rouge_l"] = 0.0
                records.append(out)
                continue
            best_candidate_idx = available_candidates[0][0]
            best_rowid = available_candidates[0][2]
            best_score = -1
            ext_port = str(row.get('port', '')).strip()
            ext_protocol = str(row.get('protocol', '')).strip().lower()
            for cand_idx, candidate, cand_rowid in available_candidates:
                score = 0
                if 'port' in candidate and ext_port and str(candidate['port']).strip() == ext_port:
                    score += 1
                if 'protocol' in candidate and ext_protocol and str(candidate['protocol']).strip().lower() == ext_protocol:
                    score += 1
                if score > best_score:
                    best_score = score
                    best_candidate_idx = cand_idx
                    best_rowid = cand_rowid
            base_row = base_match.iloc[best_candidate_idx]
            used_baseline_rowids.add(best_rowid)
        else:
            base_rowid = base_match["_baseline_row_id"]
            if base_rowid in used_baseline_rowids:
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_rouge_l"] = 0.0
                records.append(out)
                continue
            base_row = base_match
            used_baseline_rowids.add(base_rowid)

        out = {"Name": name_show, "_status": "OK"}
        for col in common_cols:
            extraction_text = normalize_field_data(row[col])
            base_text = normalize_field_data(base_row[col])
            if extraction_text.strip() and base_text.strip():
                rouge_score = rouge_l_score(extraction_text, base_text)
            elif not extraction_text.strip() and not base_text.strip():
                rouge_score = 1.0
            else:
                rouge_score = 0.0
            # Garante que o valor é float
            try:
                out[f"{col}_rouge_l"] = float(rouge_score)
            except (ValueError, TypeError):
                out[f"{col}_rouge_l"] = 0.0
        records.append(out)

    per_vuln_df = pd.DataFrame(records)
    
    # ==== CATEGORIZAÇÃO ====
    categorization_records = []
    
    # 1) Vulnerabilidades da extração que foram pareadas
    for _, row in per_vuln_df.iterrows():
        if row["_status"] == "OK":
            # Calcula média dos scores ROUGE-L
            rouge_cols = [c for c in row.index if c.endswith("_rouge_l")]
            # Converte todos os valores para float, ignorando strings
            rouge_scores = pd.to_numeric([row[c] for c in rouge_cols], errors='coerce')
            avg_rouge = rouge_scores.mean() if len(rouge_scores) > 0 else 0.0
            
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
    # Marca como ausente apenas as instâncias da baseline cujo rowid NÃO foi usado (igual ao BERTScore)
    baseline_rowids = set(baseline_dedup["_baseline_row_id"].tolist())
    used_rowids = set(used_baseline_rowids)
    absent_rowids = baseline_rowids - used_rowids
    for rowid in absent_rowids:
        base_row = base_idx_rowid.loc[rowid]
        categorization_records.append({
            "Vulnerability_Name": base_row["Name"],
            "Avg_ROUGE_L": 0.0,
            "Category": "Absent",
            "Type": "Absent (not extracted)"
        })
    
    categorization_df = pd.DataFrame(categorization_records)
    
    # Calcula quantas INSTÂNCIAS da baseline foram pareadas (baseado em used_baseline_rowids)
    baseline_instances_matched = len(used_baseline_rowids)
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



def main():
    # Parse argumentos da linha de comando (centralizado)
    args = parse_arguments_common(require_model=False)
    
    baseline_file = args.baseline_file
    extraction_file = args.extraction_file
    # Padronização: subpasta com nome da baseline e nome do arquivo igual ao BERT
    # Exemplo: metrics/rouge/results/OpenVAS_bBWA/rouge_comparison_vulnerabilities_deepseek.xlsx
    # Nome do modelo
    model_name = getattr(args, 'model', None)
    baseline_name = Path(baseline_file).stem
    baseline_name = "_".join(baseline_name.split())
    output_dir = Path(args.output_dir)  # Salva diretamente na pasta da run
    print("\n=== Comparison of Multiple Extractions with Baseline (ROUGE-L) ===")
    # Atualiza a configuração globalmente
    global ALLOW_BASELINE_DUPLICATES
    ALLOW_BASELINE_DUPLICATES = args.allow_duplicates
    if not ALLOW_BASELINE_DUPLICATES:
        print(f"\n[OK] No duplicates allowed in baseline - deduplication will be applied.")

    print(f"\nLoading baseline file: {baseline_file}")
    # Verifica se os arquivos existem
    if not Path(baseline_file).exists():
        print(f"[ERROR] Baseline file not found: {baseline_file}")
        sys.exit(1)
    if not Path(extraction_file).exists():
        print(f"[ERROR] Extraction file not found: {extraction_file}")
        sys.exit(1)

    # Automatic conversion from JSON to XLSX
    if extraction_file.endswith('.json'):
        try:
            from src.converters import convert_json_to_xlsx
            print(f"Converting extraction file from JSON to XLSX: {extraction_file}")
            extraction_file = convert_json_to_xlsx(extraction_file)
            print(f"Converted extraction file: {extraction_file}")
        except Exception as e:
            print(f"[ERROR] Failed to convert JSON to XLSX: {e}")
            sys.exit(1)

    # Carrega arquivo Excel
    excel_data = pd.ExcelFile(baseline_file, engine="openpyxl")
    # Carrega baseline
    print(f"Loading baseline sheet: {BASELINE_SHEET}")
    baseline_df = pd.read_excel(baseline_file, sheet_name=BASELINE_SHEET, engine="openpyxl")
    print(f"Baseline loaded - Shape: {baseline_df.shape}")
    print(f"Baseline columns: {list(baseline_df.columns)}")
    # Verifica se precisamos carregar do arquivo de extracao para comparacoes
    extraction_excel_data = pd.ExcelFile(extraction_file, engine="openpyxl")

    # Primeiro tenta encontrar abas de extração múltipla
    available_sheets = [sheet for sheet in EXTRACTION_SHEETS if sheet in extraction_excel_data.sheet_names]

    # Se não encontrou abas de extração múltipla, verifica se é um arquivo de extração simples
    if not available_sheets and 'Vulnerabilities' in extraction_excel_data.sheet_names:
        print("Simple extraction file detected - using sheet 'Vulnerabilities'")
        available_sheets = ['Vulnerabilities']
        EXTRACTION_SHEETS_TO_USE = ['Vulnerabilities']
    else:
        EXTRACTION_SHEETS_TO_USE = EXTRACTION_SHEETS

    missing_sheets = [sheet for sheet in EXTRACTION_SHEETS_TO_USE if sheet not in extraction_excel_data.sheet_names]

    if missing_sheets and available_sheets:
        print(f"\nSheets not found: {missing_sheets}")

    print(f"\nExtraction sheets found: {available_sheets}")

    if not available_sheets:
        print("No extraction sheets found for comparison!")
        return

    # Cria resumo geral das comparações
    general_summary = []

    # Processa cada aba de extração
    for extraction_sheet in available_sheets:
        print(f"\n{'='*60}")
        print(f"Processing sheet: {extraction_sheet}")
        print('='*60)
        try:
            # Carrega aba de extração
            extraction_df = pd.read_excel(extraction_file, sheet_name=extraction_sheet, engine="openpyxl")
            print(f"Shape of extraction sheet '{extraction_sheet}': {extraction_df.shape}")

            # Processa comparação
            per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances = process_extraction_comparison(
                baseline_df.copy(), 
                extraction_df.copy(), 
                extraction_sheet
            )

            # Nome do arquivo de saída padronizado
            if extraction_sheet == 'Vulnerabilities':
                extraction_name = 'vulnerabilities'
            else:
                extraction_name = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            # Usa nome do modelo se disponível
            model_suffix = f"_{model_name}" if model_name else ""
            output_file = f"rouge_comparison_{extraction_name}{model_suffix}.xlsx"
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
            print(f"[ROUGE] Comparison completed")
            print(f"        File: {output_path}")
            print(f"\n[ROUGE] Summary:")
            print(f"      • Matched baseline instances: {baseline_instances_matched}/{total_baseline_instances}")
            print(f"      • Unextracted vulnerabilities (Absent): {cat_counts.get('Absent', 0)}")
            print(f"      • Invented vulnerabilities (Non-existent): {total_nonexistent}")
            if unmatched_excess_count > 0:
                print(f"        ↳ Excess duplicates: {unmatched_excess_count}")
                print(f"        ↳ Inventions without match: {unmatched_count}")

            print(f"\n[ROUGE] Categorization:")
            print(f"      • Highly Similar (>0.7): {cat_counts.get('Highly Similar', 0)}")
            print(f"      • Moderately Similar (0.6-0.7): {cat_counts.get('Moderately Similar', 0)}")
            print(f"      • Slightly Similar (0.4-0.6): {cat_counts.get('Slightly Similar', 0)}")
            print(f"      • Divergent (≤0.4): {cat_counts.get('Divergent', 0)}")
            print(f"      • Non-existent (invented): {cat_counts.get('Non-existent', 0)}")
            print(f"      • Absent (unextracted): {cat_counts.get('Absent', 0)}")

            # Show only overall mean and a key field
            matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"].copy()
            # Converte todas as colunas *_rouge_l para float
            rouge_columns = [col for col in per_vuln_df.columns if col.endswith('_rouge_l')]
            for col in rouge_columns:
                matched_data[col] = pd.to_numeric(matched_data[col], errors='coerce')
            overall_mean = matched_data[rouge_columns].mean().mean() if not matched_data.empty else 0.0
            desc_mean = matched_data['description_rouge_l'].mean() if 'description_rouge_l' in matched_data else 0.0
            print(f"\n[ROUGE] Quality Metrics:")
            print(f"      • Overall mean ROUGE-L: {overall_mean:.3f}")
            print(f"      • Description mean: {desc_mean:.3f}")
            general_summary.append({
                'Extraction': extraction_sheet,
                'Total_Vulnerabilities': len(per_vuln_df),
                'Matched': baseline_instances_matched,
                'Invented': total_nonexistent,
                'Absent': cat_counts.get('Absent', 0),
                'Highly_Similar': cat_counts.get('Highly Similar', 0),
                'Moderately_Similar': cat_counts.get('Moderately Similar', 0),
                'Slightly_Similar': cat_counts.get('Slightly Similar', 0),
                'Divergent': cat_counts.get('Divergent', 0),
                'Overall_Mean': overall_mean,
                'Description_Mean': desc_mean
            })

        except Exception as e:
            print(f"[ERRO] Error processing {extraction_sheet}: {e}")
            traceback.print_exc()
            continue


    # Salva resumo geral de todas as extrações e imprime mensagens finais apenas se houver resultados
    if general_summary:

        import datetime
        general_df = pd.DataFrame(general_summary)
        baseline_name = Path(args.baseline_file).stem.replace(" ", "_").lower() if hasattr(args, 'baseline_file') else "baseline"
        model_name = getattr(args, 'model', None) or "model"
        # Agora salva com prefixo 'rouge' para evitar ambiguidade
        summary_name = f"summary_all_extractions_rouge_{baseline_name}_{model_name}.xlsx"
        summary_path = output_dir / summary_name
        general_df.to_excel(summary_path, index=False)
        print(f"\n[ROUGE] Summary saved: {summary_path}")
        print(f"{'='*60}")
        print("[ROUGE] All comparisons completed")
        print(f"[ROUGE] Output files:")
        for extraction_sheet in available_sheets:
            extraction_name = 'vulnerabilities' if extraction_sheet == 'Vulnerabilities' else extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            print(f"   - {output_dir / f'rouge_comparison_{extraction_name}{model_suffix}.xlsx'}")
        print(f"   - {output_dir / 'summary_all_extractions.xlsx'} (summary of all models)")

if __name__ == "__main__":
    main()