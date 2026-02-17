import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[2]))
import re
import warnings
import sys
from metrics.common.cli import parse_arguments_common
import os
from rapidfuzz import fuzz
from typing import Dict, List, Tuple, Optional
from collections import Counter
from pathlib import Path
from tqdm import tqdm

import pandas as pd

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
        # Força port como string, protocol como lower, remove espaços
        port = str(row.get('port', '')).strip()
        protocol = str(row.get('protocol', '')).strip().lower() or '*'
        # Lógica especial para 'Services': usar hash do conteúdo
        if name == 'services':
            import json
            row_dict = {k: v for k, v in row.items() if pd.notnull(v)}
            vuln_serialized = json.dumps(row_dict, sort_keys=True, default=str)
            return f"services_exact|{hash(vuln_serialized)}"
        return f"{name}|{port}|{protocol}"
    elif scanner_type == 'tenable':
        # Força severity e plugin como string/lower
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
# CONFIG (específico para BERTScore)
# =========================
BASELINE_SHEET = "Vulnerabilities"

# Abas de extração para comparar
EXTRACTION_SHEETS = DEFAULT_EXTRACTION_SHEETS

# Controle de duplicatas na baseline
# O valor é definido via CLI (args.allow_duplicates) na main()

# ---- BERTScore import (opcional)
try:
    from bert_score import BERTScorer
    BERTSCORE_AVAILABLE = True
except Exception:
    BERTScorer = None
    BERTSCORE_AVAILABLE = False

# Configuração do BERTScore
BERTSCORE_MODEL_CANDIDATES = [
    "distilbert-base-uncased",  # Modelo que funciona - prioridade máxima
    "all-mpnet-base-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "roberta-large",
    "bert-base-uncased",
]
BERTSCORE_LANG = "en"

# Cache global para modelo BERTScore
_bertscore_model_cache = None
_bertscore_tokenizer_cache = None

def get_bertscore_model():
    """Carrega e retorna o modelo BERTScore uma vez, reutilizando em cache."""
    global _bertscore_model_cache, _bertscore_tokenizer_cache

    if _bertscore_model_cache is not None:
        return _bertscore_model_cache, _bertscore_tokenizer_cache

    if not BERTSCORE_AVAILABLE or BERTScorer is None:
        return None, None

    # Detecta dispositivo disponível
    try:
        import torch
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    except Exception:
        device = 'cpu'

    model_try = BERTSCORE_MODEL_CANDIDATES[0]
    try:
        print(f"Carregando modelo BERTScore: {model_try}...")
        scorer = BERTScorer(model_type=model_try, lang=BERTSCORE_LANG, device=device, rescale_with_baseline=True)
        _bertscore_model_cache = scorer
        print("Modelo BERTScore carregado com sucesso!")
        return scorer, None
    except Exception as e:
        print(f"Erro ao carregar modelo BERTScore {model_try}: {e}")
        return None, None

# =========================
# BERTSCORE METRIC
# =========================
def bertscore_score(pred: str, ref: str) -> float:
    # Se a biblioteca não estiver disponível, retorna 0.0 (fallback seguro)
    if not BERTSCORE_AVAILABLE or BERTScorer is None:
        return 0.0

    if pred is None or ref is None:
        return 0.0

    pred_s = str(pred).strip()
    ref_s = str(ref).strip()
    if not pred_s or not ref_s:
        return 0.0

    # Obtém o modelo do cache (carrega uma vez)
    scorer, _ = get_bertscore_model()
    if scorer is None:
        return 0.0

    try:
        # Usa o scorer pré-carregado
        P, R, F = scorer.score([pred_s], [ref_s])
        f0 = F[0]
        try:
            fval = float(f0.cpu().numpy()) if hasattr(f0, 'cpu') else float(f0)
        except Exception:
            fval = float(f0)
        if fval != fval:  # Check for NaN
            return 0.0
        return max(0.0, min(1.0, fval))
    except Exception as e:
        print(f"Erro no cálculo BERTScore: {e}")
        return 0.0


def process_extraction_comparison_bertscore(baseline_df: pd.DataFrame, extraction_df: pd.DataFrame, extraction_name: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, int]:
    print(f"Processando BERTScore {extraction_name}...")

    baseline_df["_Name_norm"] = baseline_df["Name"].map(normalize_name)
    extraction_df["_Name_norm"] = extraction_df["Name"].map(normalize_name)

    # Detecta tipo de scanner para chaves compostas
    scanner_type = detect_scanner_type(baseline_df)
    print(f"   🔧 Scanner detectado: {scanner_type}")
    
    # Gera chaves compostas para matching mais preciso
    baseline_df["_composite_key"] = baseline_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)
    extraction_df["_composite_key"] = extraction_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)

    # Tratamento de duplicatas na baseline
    if not ALLOW_BASELINE_DUPLICATES:
        baseline_dedup = baseline_df.drop_duplicates(subset=["_Name_norm"], keep="first")
        if len(baseline_dedup) < len(baseline_df):
            dup_count = len(baseline_df) - len(baseline_dedup)
            print(f"   ℹ️ Removidas {dup_count} duplicatas da baseline (modo sem duplicatas legítimas)")
        # Sempre cria _baseline_row_id, mesmo sem duplicatas legítimas
        baseline_dedup["_baseline_row_id"] = range(len(baseline_dedup))
    else:
        baseline_dedup = baseline_df.copy()
        baseline_dedup["_baseline_row_id"] = range(len(baseline_dedup))
        print(f"   ℹ️ Mantendo {len(baseline_dedup)} instâncias da baseline (modo com duplicatas legítimas)")
    
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
    
    # FASE 2: Match exato por nome (fallback para casos sem chave composta completa)
    exact_map: Dict[str, str] = {}
    baseline_set = set(baseline_dedup["_Name_norm"].tolist())
    for n in extraction_df["_Name_norm"]:
        if n in baseline_set:
            exact_map[n] = n

    baseline_norm_list = baseline_dedup["_Name_norm"].tolist()
    fuzzy_map: Dict[str, str] = {}
    
    # FASE 3: Fuzzy matching apenas para não pareados
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
    
    # Monta mapa final: prioridade para chave composta > nome exato > fuzzy
    final_map: Dict[str, Optional[str]] = {}
    final_composite_map: Dict[str, Optional[str]] = {}  # Mapeia chave composta da extração -> chave composta da baseline
    
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
            final_composite_map[comp_key] = None  # Sem match composto
        # Prioridade 3: Fuzzy match
        elif n_norm in fuzzy_map:
            final_map[n_norm] = fuzzy_map[n_norm]
            final_composite_map[comp_key] = None
        else:
            final_map[n_norm] = None
            final_composite_map[comp_key] = None

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
            score = fuzz.ratio(n_norm, m_norm) / 100.0
            base_name_orig = baseline_dedup.loc[baseline_dedup["_Name_norm"] == m_norm, "Name"]
            base_name_orig = base_name_orig.iloc[0] if len(base_name_orig) else None
            match_type = "COMPOSITE" if m_comp else "NAME_ONLY"
            debug_rows.append([n_show, n_norm, comp_key, base_name_orig, score, f"MATCHED_{match_type}"])

    mapping_debug_df = pd.DataFrame(debug_rows, columns=["Extraction_Name", "Extraction_Name_norm", "Composite_Key", "Baseline_Name_matched", "match_score", "Status"])

    # Index por chave composta e por row_id para matching preciso
    base_idx_composite = baseline_dedup.set_index("_composite_key")
    base_idx = baseline_dedup.set_index("_Name_norm")
    base_idx_rowid = baseline_dedup.set_index("_baseline_row_id")

    common_cols = [c for c in extraction_df.columns if c not in ["Name", "_Name_norm", "_composite_key"] and c in baseline_dedup.columns]

    print(f"Colunas comparáveis encontradas (BERTScore): {len(common_cols)}")

    # Tracking de linhas já usadas da baseline (para matching 1:1)
    used_baseline_rowids = set()  # Usa _baseline_row_id como identificador

    # REORDENA: processa primeiro os que têm match composto (mais precisos)
    # Isso evita que match por nome "roube" a baseline de um match composto mais preciso
    extraction_rows = list(extraction_df.iterrows())
    extraction_rows_sorted = sorted(
        extraction_rows,
        key=lambda x: (0 if final_composite_map.get(x[1]["_composite_key"]) else 1)
    )

    print(f"   📊 Calculando scores BERTScore...")
    records = []
    for _, row in tqdm(extraction_rows_sorted, total=len(extraction_rows_sorted), desc="   BERTScore scoring", leave=False):
        name_show = row["Name"]
        key = row["_Name_norm"]
        comp_key = row["_composite_key"]
        match_comp = final_composite_map.get(comp_key)
        match_norm = final_map.get(key)

        # Tenta primeiro por chave composta (mais preciso)
        if match_comp and match_comp in base_idx_composite.index:
            base_rows = base_idx_composite.loc[[match_comp]]
            # Se só uma linha, transforma em DataFrame
            if not isinstance(base_rows, pd.DataFrame):
                base_rows = base_rows.to_frame().T
            # Procura a primeira linha ainda não usada
            found = False
            for _, base_row in base_rows.iterrows():
                rowid = base_row["_baseline_row_id"]
                if rowid not in used_baseline_rowids:
                    used_baseline_rowids.add(rowid)
                    out = {"Name": name_show, "_status": "OK"}
                    for col in common_cols:
                        extraction_text = normalize_field_data(row[col])
                        base_text = normalize_field_data(base_row[col])
                        if extraction_text.strip() and base_text.strip():
                            bert_val = bertscore_score(extraction_text, base_text)
                        elif not extraction_text.strip() and not base_text.strip():
                            bert_val = 1.0
                        else:
                            bert_val = 0.0
                        out[f"{col}_bertscore_f1"] = bert_val
                    records.append(out)
                    found = True
                    break
            if not found:
                # Todas as instâncias já usadas - duplicata excedente
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
            continue

        # Fallback: match por nome normalizado
        if match_norm is None or match_norm not in base_idx.index:
            out = {"Name": name_show, "_status": "UNMATCHED"}
            for col in common_cols:
                out[f"{col}_bertscore_f1"] = 0.0
            records.append(out)
            continue

        # Pega candidatos da baseline (fallback por nome - quando chave composta não bateu)
        base_match = base_idx.loc[match_norm]
        
        if isinstance(base_match, pd.DataFrame):
            # Múltiplas linhas com mesmo nome (modo com duplicatas legítimas)
            # Filtra apenas as que ainda não foram usadas (verifica por row_id)
            available_candidates = []
            for i in range(len(base_match)):
                candidate = base_match.iloc[i]
                cand_rowid = candidate["_baseline_row_id"]
                if cand_rowid not in used_baseline_rowids:
                    available_candidates.append((i, candidate, cand_rowid))
            if not available_candidates:
                # Todas as instâncias já foram usadas - extraction tem mais que baseline
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
                continue
            # Escolhe a candidata com maior similaridade (preferencialmente pela porta/protocolo)
            best_idx = 0
            best_candidate_idx = available_candidates[0][0]
            best_rowid = available_candidates[0][2]
            best_score = -1
            ext_port = str(row.get('port', '')).strip()
            ext_protocol = str(row.get('protocol', '')).strip().lower()
            for cand_idx, candidate, cand_rowid in available_candidates:
                cand_port = str(candidate.get('port', '')).strip()
                cand_protocol = str(candidate.get('protocol', '')).strip().lower()
                port_match_bonus = 0.5 if (ext_port == cand_port and ext_protocol == cand_protocol) else 0.0
                scores = []
                for col in common_cols:
                    ext_text = normalize_field_data(row[col])
                    base_text = normalize_field_data(candidate[col])
                    if ext_text.strip() and base_text.strip():
                        scores.append(bertscore_score(ext_text, base_text))
                if scores:
                    avg_score = sum(scores) / len(scores) + port_match_bonus
                    if avg_score > best_score:
                        best_score = avg_score
                        best_candidate_idx = cand_idx
                        best_rowid = cand_rowid
            base_row = base_match.iloc[best_candidate_idx]
            used_baseline_rowids.add(best_rowid)
        else:
            # Única linha
            base_rowid = base_match["_baseline_row_id"]
            if base_rowid in used_baseline_rowids:
                # Já foi usada
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
                continue
            base_row = base_match
            used_baseline_rowids.add(base_rowid)
        
        out = {"Name": name_show, "_status": "OK"}

        for col in common_cols:
            extraction_text = normalize_field_data(row[col])
            base_text = normalize_field_data(base_row[col])

            if extraction_text.strip() and base_text.strip():
                bert_val = bertscore_score(extraction_text, base_text)
            elif not extraction_text.strip() and not base_text.strip():
                bert_val = 1.0
            else:
                bert_val = 0.0

            out[f"{col}_bertscore_f1"] = bert_val

        records.append(out)

    per_vuln_df = pd.DataFrame(records)

    categorization_records = []

    # Só considera como "Matched" e "Highly Similar" os que realmente foram pareados (status OK)
    for _, row in per_vuln_df.iterrows():
        if row["_status"] == "OK":
            bcols = [c for c in row.index if c.endswith("_bertscore_f1")]
            bvals = [row[c] for c in bcols]
            avg_b = sum(bvals) / len(bvals) if bvals else 0.0

            if avg_b > 0.7:
                category = "Highly Similar"
            elif avg_b > 0.6:
                category = "Moderately Similar"
            elif avg_b > 0.4:
                category = "Slightly Similar"
            else:
                category = "Divergent"

            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_BERTScore_F1": avg_b,
                "Category": category,
                "Type": "Matched"
            })
        elif row["_status"] == "UNMATCHED_EXCESS":
            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_BERTScore_F1": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (excess duplicate)"
            })
        # UNMATCHED não marca absent, só baseline não pareada entra como absent

    # Calcula matched_counts baseado nos matches REAIS (status OK), não em final_map
    # Precisa rastrear qual baseline foi usada para cada extração OK
    # DEBUG: Mostra os rowids da baseline e os usados
    print(f"[DEBUG] baseline_dedup shape: {baseline_dedup.shape}")
    print(f"[DEBUG] baseline_dedup _baseline_row_id:")
    print(baseline_dedup["_baseline_row_id"].tolist())
    print(f"[DEBUG] used_baseline_rowids (pareados):")
    print(list(used_baseline_rowids))

    # Marca como ausente apenas as instâncias da baseline cujo rowid NÃO foi usado
    baseline_rowids = set(baseline_dedup["_baseline_row_id"].tolist())
    used_rowids = set(used_baseline_rowids)
    absent_rowids = baseline_rowids - used_rowids
    print(f"[DEBUG] absent_rowids (serão marcados como ausentes):")
    print(list(absent_rowids))
    for rowid in absent_rowids:
        base_row = base_idx_rowid.loc[rowid]
        categorization_records.append({
            "Vulnerability_Name": base_row["Name"],
            "Avg_BERTScore_F1": 0.0,
            "Category": "Absent",
            "Type": "Absent (not extracted)"
        })

    categorization_df = pd.DataFrame(categorization_records)

    # Calcula quantas INSTÂNCIAS da baseline foram pareadas (baseado em used_baseline_rows)
    baseline_instances_matched = len(used_baseline_rowids)
    total_baseline_instances = len(baseline_dedup)

    summary_data = []
    for col in common_cols:
        matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"]
        col_name = f"{col}_bertscore_f1"
        if len(matched_data) > 0:
            vals = matched_data[col_name].astype(float)
            summary_data.append({
                "Column": col,
                "Count_Matched": len(matched_data),
                "Avg_BERTScore_F1": float(vals.mean()),
                "Std_BERTScore_F1": float(vals.std()),
                "Min_BERTScore_F1": float(vals.min()),
                "Max_BERTScore_F1": float(vals.max()),
                "Median_BERTScore_F1": float(vals.median())
            })
        else:
            summary_data.append({
                "Column": col,
                "Count_Matched": 0,
                "Avg_BERTScore_F1": 0.0,
                "Std_BERTScore_F1": 0.0,
                "Min_BERTScore_F1": 0.0,
                "Max_BERTScore_F1": 0.0,
                "Median_BERTScore_F1": 0.0
            })

    summary_df = pd.DataFrame(summary_data)

    return per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances




def main():
    # Parse argumentos da linha de comando (centralizado)
    args = parse_arguments_common(require_model=False)
    
    baseline_file = args.baseline_file

    output_dir = Path(args.output_dir)
    
    global ALLOW_BASELINE_DUPLICATES
    
    print("=== Comparacao de Multiplas Extracoes com Baseline (BERTScore) ===")
    
    # Configuração baseada no parâmetro CLI
    ALLOW_BASELINE_DUPLICATES = args.allow_duplicates
    if ALLOW_BASELINE_DUPLICATES:
        print(f"\n[OK] Modo CLI: duplicatas legítimas permitidas")
    else:
        print(f"\n[OK] Modo CLI: sem duplicatas legítimas")
    
    # Verifica se os arquivos existem
    if not Path(baseline_file).exists():
        print(f"[ERRO] Arquivo baseline nao encontrado: {baseline_file}")
        sys.exit(1)
    
    if not Path(args.extraction_file).exists():
        print(f"[ERRO] Arquivo de extracao nao encontrado: {args.extraction_file}")
        sys.exit(1)
    
    # Cria diretório de saída se não existir
    args.output_dir = Path(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\nCarregando arquivo: {baseline_file}")

    excel_data = pd.ExcelFile(baseline_file)

    print(f"Carregando aba baseline: {BASELINE_SHEET}")
    baseline_df = pd.read_excel(baseline_file, sheet_name=BASELINE_SHEET)

    print(f"Baseline carregado - Shape: {baseline_df.shape}")
    print(f"Colunas baseline: {list(baseline_df.columns)}")

    # Verifica se precisamos carregar do arquivo de extracao para comparacoes
    extraction_excel_data = pd.ExcelFile(args.extraction_file)
    
    # Primeiro tenta encontrar abas de extração múltipla
    available_sheets = [sheet for sheet in EXTRACTION_SHEETS if sheet in extraction_excel_data.sheet_names]
    
    # Se não encontrou abas de extração múltipla, verifica se é um arquivo de extração simples
    if not available_sheets and 'Vulnerabilities' in extraction_excel_data.sheet_names:
        print("Arquivo de extracao simples detectado - usando aba 'Vulnerabilities'")
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

    general_summary = []

    # prepara o diretório de saída por baseline
    baseline_name = Path(baseline_file).stem
    baseline_name = "_".join(baseline_name.split())


    for extraction_sheet in available_sheets:
        print(f"\n{'='*60}")
        print(f"Processando (BERT): {extraction_sheet}")
        print('='*60)

        try:
            extraction_df = pd.read_excel(args.extraction_file, sheet_name=extraction_sheet)
            print(f"Shape da extração: {extraction_df.shape}")

            per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances = process_extraction_comparison_bertscore(
                baseline_df.copy(),
                extraction_df.copy(),
                extraction_sheet,
            )

            # Nome do relatório (baseline), aba e modelo
            relatorio_nome = Path(baseline_file).stem.replace(" ", "_").lower()
            aba_nome = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            modelo_nome = args.model if args.model else aba_nome
            if aba_nome == 'vulnerabilities' and not args.model:
                modelo_nome = Path(args.extraction_file).stem.replace("vulnerabilities_", "").replace("_converted", "").lower()
            # Cria subpasta do baseline dentro do diretório de resultados
            baseline_dir = args.output_dir / Path(baseline_file).stem
            baseline_dir.mkdir(parents=True, exist_ok=True)
            output_file = f"bert_comparison_{aba_nome}_{modelo_nome}.xlsx"
            output_path = baseline_dir / output_file

            with pd.ExcelWriter(output_path) as writer:
                per_vuln_df.to_excel(writer, sheet_name="Per_Vulnerability", index=False)
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                categorization_df.to_excel(writer, sheet_name="Categorization", index=False)
                mapping_debug_df.to_excel(writer, sheet_name="Mapping_Debug", index=False)

            unmatched_count = (per_vuln_df["_status"] == "UNMATCHED").sum()
            unmatched_excess_count = (per_vuln_df["_status"] == "UNMATCHED_EXCESS").sum()
            total_nonexistent = unmatched_count + unmatched_excess_count
            matched_count = len(per_vuln_df) - total_nonexistent

            cat_counts = categorization_df["Category"].value_counts().to_dict()

            print(f"✅ Comparação BERT concluída!")
            print(f"   → Arquivo: {output_path}")
            print(f"\n   📊 Resumo da Comparação:")
            print(f"      • Instâncias da baseline pareadas: {baseline_instances_matched}/{total_baseline_instances}")
            print(f"      • Vulnerabilidades não extraídas (Absent): {cat_counts.get('Absent', 0)}")
            print(f"      • Vulnerabilidades inventadas (Non-existent): {total_nonexistent}")
            if unmatched_excess_count > 0:
                print(f"        ↳ Duplicatas excedentes: {unmatched_excess_count}")
                print(f"        ↳ Invenções sem match: {unmatched_count}")

            print(f"\n   Categorização de Similaridade:")
            print(f"      • Highly Similar (>0.7): {cat_counts.get('Highly Similar', 0)}")
            print(f"      • Moderately Similar (0.6-0.7): {cat_counts.get('Moderately Similar', 0)}")
            print(f"      • Slightly Similar (0.4-0.6): {cat_counts.get('Slightly Similar', 0)}")
            print(f"      • Divergent (≤0.4): {cat_counts.get('Divergent', 0)}")
            print(f"      • Non-existent (inventadas): {cat_counts.get('Non-existent', 0)}")
            print(f"      • Absent (não extraídas): {cat_counts.get('Absent', 0)}")

            # Estatísticas por campo
            bert_columns = [col for col in per_vuln_df.columns if col.endswith('_bertscore_f1')]
            extraction_stats = {
                'Extraction': extraction_sheet,
                'Total_Vulnerabilities': len(per_vuln_df),
                'Matched_Vulnerabilities': matched_count,
                'Match_Rate': matched_count / total_baseline_instances if total_baseline_instances > 0 else 0,
                'Absent_Count': cat_counts.get('Absent', 0),
                'NonExistent_Count': total_nonexistent
            }

            all_bert_scores = []
            matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"]

            if len(matched_data) > 0:
                for bert_col in bert_columns:
                    field_avg = matched_data[bert_col].mean()
                    field_name = bert_col.replace('_bertscore_f1', '')
                    extraction_stats[f'{field_name}_bertscore_f1'] = field_avg
                    all_bert_scores.append(field_avg)

                extraction_stats['Overall_BERTScore_F1_Mean'] = sum(all_bert_scores) / len(all_bert_scores) if all_bert_scores else 0
            else:
                for bert_col in bert_columns:
                    field_name = bert_col.replace('_bertscore_f1', '')
                    extraction_stats[f'{field_name}_bertscore_f1'] = 0.0
                extraction_stats['Overall_BERTScore_F1_Mean'] = 0.0

            print(f"\n   Estatísticas por campo (exemplo):")
            key_columns = ['description', 'impact', 'solution']
            for col in key_columns:
                if f'{col}_bertscore_f1' in extraction_stats:
                    print(f"   → {col}: BERTScore F1={extraction_stats[f'{col}_bertscore_f1']:.3f}")

            print(f"   → Média geral de todos os {len(bert_columns)} campos: {extraction_stats['Overall_BERTScore_F1_Mean']:.3f}")

            general_summary.append(extraction_stats)

        except Exception as e:
            print(f"❌ Erro ao processar {extraction_sheet}: {e}")
            continue


    if general_summary:

        import datetime
        general_df = pd.DataFrame(general_summary)
        baseline_name = Path(args.baseline_file).stem.replace(" ", "_").lower() if hasattr(args, 'baseline_file') else "baseline"
        model_name = args.model if hasattr(args, 'model') and args.model else "model"
        # Sempre sobrescreve o summary principal para garantir só 1 por run
        summary_name = f"summary_all_extractions_bert_{baseline_name}_{model_name}.xlsx"
        summary_path = args.output_dir / summary_name
        general_df.to_excel(summary_path, index=False)
        print(f"\n📊 Resumo geral salvo em: {summary_path}")

        print(f"\n{'='*60}")
        print("✅ Todas as comparações BERT concluídas!")
        print("\n📊 Arquivos gerados:")
        for extraction_sheet in available_sheets:
            clean_name = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            print(f"   - {args.output_dir / f'bert_comparison_{clean_name}.xlsx'}")
            print(f"       • Per_Vulnerability: Scores BERTScore F1 detalhados por campo")
            print(f"       • Summary: Estatísticas agregadas (média, desvio, min, max, mediana)")
            print(f"       • Categorization: Classificação completa (Similarity + Absent + Non-existent)")
            print(f"       • Mapping_Debug: Debug do pareamento de nomes")
        print(f"   - {args.output_dir / 'summary_all_extractions_bert.xlsx'} (comparação consolidada entre todos os modelos)")


if __name__ == "__main__":
    main()
