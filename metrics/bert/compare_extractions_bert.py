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

# Configure UTF-8 encoding for Windows/Linux compatibility
if sys.platform.startswith('win'):
    # Force UTF-8 encoding on Windows
    if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    
    # Set environment variable for subprocess
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Add root directory to path to import common module
sys.path.insert(0, str(Path(__file__).parents[1]))

# Imports from common module
from common.config import BASELINE_DIR, FUZZY_THRESHOLD, SPARSE_FIELDS, DEFAULT_EXTRACTION_SHEETS
from common.normalization import normalize_name, normalize_field_data
from common.matching import best_fuzzy_match
from common.field_mapper import get_semantic_fields, get_excluded_fields


def detect_scanner_type(df: pd.DataFrame) -> str:
    """Detects scanner type based on fields or source column."""
    if 'source' in df.columns:
        sources = df['source'].dropna().str.upper().unique()
        if 'OPENVAS' in sources:
            return 'openvas'
        elif 'TENABLE' in sources or 'NESSUS' in sources:
            return 'tenable'
    # Fallback: check for typical fields
    if 'plugin' in df.columns:
        return 'tenable'
    if 'protocol' in df.columns and df['protocol'].notna().any():
        return 'openvas'
    return 'generic'


def normalize_port(port_value) -> str:
    """Normalizes port by removing numeric formatting (commas, thousands separators)."""
    port_str = str(port_value).strip()
    # Remove commas and periods used as thousands separators
    port_str = port_str.replace(',', '').replace('.', '')
    # If empty or not numeric (except 'general'), return wildcard
    if not port_str or (not port_str.isdigit() and port_str.lower() != 'general'):
        return '*'
    return port_str


def build_composite_key(row: pd.Series, scanner_type: str) -> str:
    """
    Generate composite key for matching based on scanner type.
    - OpenVAS: name + port + protocol
    - Tenable: name + severity + plugin
    - Generic: name only
    
    Null/empty elements are represented as '*' (wildcard).
    """
    name = normalize_name(str(row.get('Name', '')))
    
    if scanner_type == 'openvas':
        # Force port as string, protocol as lower, remove spaces
        port = str(row.get('port', '')).strip()
        protocol = str(row.get('protocol', '')).strip().lower() or '*'
        # Special logic for 'Services': use content hash
        if name == 'services':
            import json
            row_dict = {k: v for k, v in row.items() if pd.notnull(v)}
            vuln_serialized = json.dumps(row_dict, sort_keys=True, default=str)
            return f"services_exact|{hash(vuln_serialized)}"
        return f"{name}|{port}|{protocol}"
    elif scanner_type == 'tenable':
        # Force severity and plugin as string/lower
        severity = str(row.get('severity', '')).strip().lower() or '*'
        plugin = str(row.get('plugin', '')).strip() or '*'
        return f"{name}|{severity}|{plugin}"
    else:
        return name


def keys_match(key1: str, key2: str) -> bool:
    """
    Check if two composite keys are compatible.
    Wildcards ('*') are compatible with any value.
    """
    parts1 = key1.split('|')
    parts2 = key2.split('|')
    
    if len(parts1) != len(parts2):
        return False
    
    for p1, p2 in zip(parts1, parts2):
        # Wildcard is compatible with any value
        if p1 == '*' or p2 == '*':
            continue
        # Different values = no match
        if p1 != p2:
            return False
    
    return True


def key_match_score(key1: str, key2: str) -> float:
    """
    Calculate match score between two keys (0.0 to 1.0).
    More concrete equal elements = higher score.
    Wildcards contribute partially.
    """
    parts1 = key1.split('|')
    parts2 = key2.split('|')
    
    if len(parts1) != len(parts2):
        return 0.0
    
    score = 0.0
    total = len(parts1)
    
    for p1, p2 in zip(parts1, parts2):
        if p1 == '*' or p2 == '*':
            # Wildcard: contributes partially (0.3) - better than nothing, worse than exact match
            score += 0.3
        elif p1 == p2:
            # Exact match: contributes fully
            score += 1.0
        # Different values: contributes 0.0
    
    return score / total if total > 0 else 0.0

# =========================
# CONFIG (specific to BERTScore)
# =========================
BASELINE_SHEET = "Vulnerabilities"

# Extraction sheets to compare
EXTRACTION_SHEETS = DEFAULT_EXTRACTION_SHEETS

# Baseline duplicate control
# Value is defined via CLI (args.allow_duplicates) in main()

# ---- BERTScore import (optional)
try:
    from bert_score import BERTScorer
    BERTSCORE_AVAILABLE = True
except Exception:
    BERTScorer = None
    BERTSCORE_AVAILABLE = False

# BERTScore configuration
BERTSCORE_MODEL_CANDIDATES = [
    "distilbert-base-uncased",  
    "all-mpnet-base-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "roberta-large",
    "bert-base-uncased",
]
BERTSCORE_LANG = "en"

# Global cache for BERTScore model
_bertscore_model_cache = None
_bertscore_tokenizer_cache = None

def get_bertscore_model():
    """Loads and returns BERTScore model once, reusing from cache."""
    global _bertscore_model_cache, _bertscore_tokenizer_cache

    if _bertscore_model_cache is not None:
        return _bertscore_model_cache, _bertscore_tokenizer_cache

    if not BERTSCORE_AVAILABLE or BERTScorer is None:
        return None, None

    # Detects available device
    try:
        import torch
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    except Exception:
        device = 'cpu'

    model_try = BERTSCORE_MODEL_CANDIDATES[0]
    try:
        print(f"Loading BERTScore model: {model_try}...")
        scorer = BERTScorer(model_type=model_try, lang=BERTSCORE_LANG, device=device, rescale_with_baseline=True)
        _bertscore_model_cache = scorer
        print("BERTScore model loaded successfully!")
        return scorer, None
    except Exception as e:
        print(f"Error loading BERTScore model {model_try}: {e}")
        return None, None

# =========================
# BERTSCORE METRIC
# =========================
def bertscore_score(pred: str, ref: str) -> float:
    # If library is not available, return 0.0 (safe fallback)
    if not BERTSCORE_AVAILABLE or BERTScorer is None:
        return 0.0

    if pred is None or ref is None:
        return 0.0

    pred_s = str(pred).strip()
    ref_s = str(ref).strip()
    if not pred_s or not ref_s:
        return 0.0

    # Gets model from cache (loads once)
    scorer, _ = get_bertscore_model()
    if scorer is None:
        return 0.0

    try:
        # Use pre-loaded scorer
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
        print(f"Error in BERTScore calculation: {e}")
        return 0.0


def process_extraction_comparison_bertscore(baseline_df: pd.DataFrame, extraction_df: pd.DataFrame, extraction_name: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, int]:
    print(f"Processing BERTScore {extraction_name}...")

    baseline_df["_Name_norm"] = baseline_df["Name"].map(normalize_name)
    extraction_df["_Name_norm"] = extraction_df["Name"].map(normalize_name)

    # Detect scanner type for composite keys
    scanner_type = detect_scanner_type(baseline_df)
    print(f"   🛠️ Detected scanner: {scanner_type}")
    
    # Generate composite keys for more accurate matching
    baseline_df["_composite_key"] = baseline_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)
    extraction_df["_composite_key"] = extraction_df.apply(lambda r: build_composite_key(r, scanner_type), axis=1)

    # Duplicate handling in baseline
    # _baseline_row_id preserves the ORIGINAL positional index in baseline_df,
    # so downstream consumers (e.g., entity metrics) can use baseline_df.iloc[row_id]
    # to recover the exact row matched by BERT — even when multiple rows share a Name.
    if not ALLOW_BASELINE_DUPLICATES:
        baseline_dedup = baseline_df.drop_duplicates(subset=["_Name_norm"], keep="first")
        if len(baseline_dedup) < len(baseline_df):
            dup_count = len(baseline_df) - len(baseline_dedup)
            print(f"   ℹ️ Removed {dup_count} duplicates from the baseline (no legitimate duplicates mode)")
        baseline_dedup["_baseline_row_id"] = baseline_dedup.index
    else:
        baseline_dedup = baseline_df.copy()
        baseline_dedup["_baseline_row_id"] = baseline_dedup.index
        print(f"   ℹ️ Keeping {len(baseline_dedup)} instances from the baseline (legitimate duplicates mode)")
    
    # PHASE 1: Match by composite key (supports wildcards)
    # For each extraction key, finds all compatible baseline keys
    baseline_composite_list = baseline_dedup["_composite_key"].tolist()
    composite_map: Dict[str, str] = {}
    
    for ext_key in extraction_df["_composite_key"]:
        # Find compatible matches (considering wildcards)
        compatible_matches = [(bk, key_match_score(ext_key, bk)) for bk in baseline_composite_list if keys_match(ext_key, bk)]
        if compatible_matches:
            # Choose match with highest key score
            best_match = max(compatible_matches, key=lambda x: x[1])
            composite_map[ext_key] = best_match[0]
    
    # PHASE 2: Exact match by name (fallback for cases without complete composite key)
    exact_map: Dict[str, str] = {}
    baseline_set = set(baseline_dedup["_Name_norm"].tolist())
    for n in extraction_df["_Name_norm"]:
        if n in baseline_set:
            exact_map[n] = n

    baseline_norm_list = baseline_dedup["_Name_norm"].tolist()
    fuzzy_map: Dict[str, str] = {}
    
    # PHASE 3: Fuzzy matching only for unmatched
    fuzzy_candidates = [n for n in extraction_df["_Name_norm"] if n not in exact_map and n != ""]
    print(f"   🔍 Fuzzy matching: {len(fuzzy_candidates)} vulnerabilities...")
    for n in tqdm(fuzzy_candidates, desc="   Fuzzy matching", leave=False, disable=len(fuzzy_candidates) < 10):
        match_norm, score = best_fuzzy_match(n, baseline_norm_list)
        if match_norm and score >= FUZZY_THRESHOLD:
            fuzzy_map[n] = match_norm

    # Build map of composite key from baseline -> normalized name of baseline
    baseline_composite_to_name: Dict[str, str] = {}
    for _, br in baseline_dedup.iterrows():
        baseline_composite_to_name[br["_composite_key"]] = br["_Name_norm"]
    
    # Build final mapping: priority for composite key > exact name > fuzzy
    final_map: Dict[str, Optional[str]] = {}
    final_composite_map: Dict[str, Optional[str]] = {}  # Maps extraction composite key -> baseline composite key
    
    for idx, r in extraction_df.iterrows():
        n_norm = r["_Name_norm"]
        comp_key = r["_composite_key"]
        
        # Priority 1: Match by composite key
        if comp_key in composite_map:
            baseline_comp_key = composite_map[comp_key]
            baseline_name_norm = baseline_composite_to_name.get(baseline_comp_key, n_norm)
            final_map[n_norm] = baseline_name_norm  # Normalized name FROM BASELINE
            final_composite_map[comp_key] = baseline_comp_key
        # Priority 2: Exact match by name
        elif n_norm in exact_map:
            final_map[n_norm] = exact_map[n_norm]
            final_composite_map[comp_key] = None  # No composite match
        # Priority 3: Fuzzy match
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
            debug_rows.append([idx, None, n_show, n_norm, comp_key, None, 0.0, "UNMATCHED"])
        else:
            score = fuzz.ratio(n_norm, m_norm) / 100.0
            base_name_orig = baseline_dedup.loc[baseline_dedup["_Name_norm"] == m_norm, "Name"]
            base_name_orig = base_name_orig.iloc[0] if len(base_name_orig) else None
            match_type = "COMPOSITE" if m_comp else "NAME_ONLY"
            debug_rows.append([idx, None, n_show, n_norm, comp_key, base_name_orig, score, f"MATCHED_{match_type}"])

    mapping_debug_df = pd.DataFrame(debug_rows, columns=["extraction_row_id", "baseline_row_id", "Extraction_Name", "Extraction_Name_norm", "Composite_Key", "Baseline_Name_matched", "match_score", "Status"])

    # Index by composite key and by row_id for precise matching
    base_idx_composite = baseline_dedup.set_index("_composite_key")
    base_idx = baseline_dedup.set_index("_Name_norm")
    base_idx_rowid = baseline_dedup.set_index("_baseline_row_id")

    # Columns for comparison (use field_mapper configuration)
    # Exclude: deterministic fields (handled by entity metrics) + excluded fields
    excluded_set = get_excluded_fields()
    semantic_fields = get_semantic_fields(baseline_dedup.columns)
    
    common_cols = [c for c in extraction_df.columns if c.lower() in semantic_fields and c in baseline_dedup.columns]

    print(f"[BERT] Columns for comparison: {len(common_cols)}")

    # Tracking of already used baseline rows (for 1:1 matching)
    used_baseline_rowids = set()  # Uses _baseline_row_id as identifier
    # Authoritative extraction→baseline row mapping, populated as scoring commits matches.
    # Downstream entity metrics rely on this to recover the exact baseline row per extraction.
    ext_to_baseline_rowid: Dict[int, int] = {}

    # REORDER: process first those with composite match (more accurate)
    # This prevents name matching from "stealing" baseline from more accurate composite match
    extraction_rows = list(extraction_df.iterrows())
    extraction_rows_sorted = sorted(
        extraction_rows,
        key=lambda x: (0 if final_composite_map.get(x[1]["_composite_key"]) else 1)
    )

    print(f"[BERT] Calculating scores...")
    records = []
    for ext_idx, row in tqdm(extraction_rows_sorted, total=len(extraction_rows_sorted), desc="   BERTScore scoring", leave=False):
        name_show = row["Name"]
        key = row["_Name_norm"]
        comp_key = row["_composite_key"]
        match_comp = final_composite_map.get(comp_key)
        match_norm = final_map.get(key)

        # Try first by composite key (more accurate)
        if match_comp and match_comp in base_idx_composite.index:
            base_rows = base_idx_composite.loc[[match_comp]]
            # If only one line, transform to DataFrame
            if not isinstance(base_rows, pd.DataFrame):
                base_rows = base_rows.to_frame().T
            # Find first unused line
            found = False
            for _, base_row in base_rows.iterrows():
                rowid = base_row["_baseline_row_id"]
                if rowid not in used_baseline_rowids:
                    used_baseline_rowids.add(rowid)
                    ext_to_baseline_rowid[ext_idx] = int(rowid)
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
                # All instances already used - excess duplicate
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
            continue

        # Fallback: match by normalized name
        if match_norm is None or match_norm not in base_idx.index:
            out = {"Name": name_show, "_status": "UNMATCHED"}
            for col in common_cols:
                out[f"{col}_bertscore_f1"] = 0.0
            records.append(out)
            continue

        # Get baseline candidates (fallback by name - when composite key didn't match)
        base_match = base_idx.loc[match_norm]
        
        if isinstance(base_match, pd.DataFrame):
            # Multiple lines with same name (mode with legitimate duplicates)
            # Filter only those not yet used (check by row_id)
            available_candidates = []
            for i in range(len(base_match)):
                candidate = base_match.iloc[i]
                cand_rowid = candidate["_baseline_row_id"]
                if cand_rowid not in used_baseline_rowids:
                    available_candidates.append((i, candidate, cand_rowid))
            if not available_candidates:
                # All instances already used - extraction has more than baseline
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
                continue
            # Choose candidate with highest similarity (preferably by port/protocol)
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
            ext_to_baseline_rowid[ext_idx] = int(best_rowid)
        else:
            # Single line
            base_rowid = base_match["_baseline_row_id"]
            if base_rowid in used_baseline_rowids:
                # Already used
                out = {"Name": name_show, "_status": "UNMATCHED_EXCESS"}
                for col in common_cols:
                    out[f"{col}_bertscore_f1"] = 0.0
                records.append(out)
                continue
            base_row = base_match
            used_baseline_rowids.add(base_rowid)
            ext_to_baseline_rowid[ext_idx] = int(base_rowid)
        
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

    # Only consider as "Matched" and "Highly Similar" those really paired (status OK)
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
        elif row["_status"] == "UNMATCHED":
            # Pure LLM invention: no match in baseline
            categorization_records.append({
                "Vulnerability_Name": row["Name"],
                "Avg_BERTScore_F1": 0.0,
                "Category": "Non-existent",
                "Type": "Non-existent (LLM invention)"
            })

    # Calculate matched_counts based on REAL matches (status OK), not final_map
    # Need to track which baseline was used for each extraction OK
    # Mark as absent only the baseline instances whose rowid was NOT used
    baseline_rowids = set(baseline_dedup["_baseline_row_id"].tolist())
    used_rowids = set(used_baseline_rowids)
    absent_rowids = baseline_rowids - used_rowids
    for rowid in absent_rowids:
        base_row = base_idx_rowid.loc[rowid]
        categorization_records.append({
            "Vulnerability_Name": base_row["Name"],
            "Avg_BERTScore_F1": 0.0,
            "Category": "Absent",
            "Type": "Absent (not extracted)"
        })

    categorization_df = pd.DataFrame(categorization_records)

    # Calculates how many INSTANCES of baseline were paired (based on used_baseline_rows)
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

    # Populate baseline_row_id in mapping_debug_df from the authoritative
    # scoring-phase mapping. This is the fix for Name-based lookups collapsing
    # duplicate Names (e.g. "Services" across different ports).
    if ext_to_baseline_rowid:
        mapping_debug_df["baseline_row_id"] = mapping_debug_df["extraction_row_id"].map(ext_to_baseline_rowid)

    return per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances




def main():
    # Parse arguments from command line (centralized)
    args = parse_arguments_common(require_model=False)
    
    baseline_file = args.baseline_file
    output_dir = Path(args.output_dir)
    global ALLOW_BASELINE_DUPLICATES
    print("\n=== Comparison of Multiple Extractions with Baseline (BERTScore) ===")
    # Configuration based on CLI parameter
    ALLOW_BASELINE_DUPLICATES = args.allow_duplicates
    if ALLOW_BASELINE_DUPLICATES:
        print(f"\n[OK] CLI Mode: legitimate duplicates allowed")
    else:
        print(f"\n[OK] CLI Mode: no legitimate duplicates allowed")

    # Check if files exist
    if not Path(baseline_file).exists():
        print(f"[ERROR] Baseline file not found: {baseline_file}")
        sys.exit(1)
    extraction_file = args.extraction_file
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

    # Create output directory if it doesn't exist
    args.output_dir = Path(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nLoading baseline file: {baseline_file}")
    excel_data = pd.ExcelFile(baseline_file, engine="openpyxl")
    print(f"Loading baseline sheet: {BASELINE_SHEET}")
    baseline_df = pd.read_excel(baseline_file, sheet_name=BASELINE_SHEET, engine="openpyxl")
    print(f"Baseline loaded - Shape: {baseline_df.shape}")
    print(f"Baseline columns: {list(baseline_df.columns)}")
    
    # Count total baseline vulnerabilities (non-null rows)
    baseline_total_vulns = len(baseline_df.dropna(how='all'))
    print(f"Total baseline vulnerabilities: {baseline_total_vulns}")
    # Check if we need to load from extraction file for comparisons
    extraction_excel_data = pd.ExcelFile(extraction_file, engine="openpyxl")
    
    # First try to find multiple extraction sheets
    available_sheets = [sheet for sheet in EXTRACTION_SHEETS if sheet in extraction_excel_data.sheet_names]
    
    # If no multiple extraction sheets found, check if it's a simple extraction file
    if not available_sheets and 'Vulnerabilities' in extraction_excel_data.sheet_names:
        print("Extraction file appears to be a single extraction sheet. Using 'Vulnerabilities' for comparison.")
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

    general_summary = []


    for extraction_sheet in available_sheets:
        print(f"\n{'='*60}")
        print(f"Processing (BERT): {extraction_sheet}")
        print('='*60)

        try:
            extraction_df = pd.read_excel(extraction_file, sheet_name=extraction_sheet, engine="openpyxl")
            print(f"Shape of extraction data: {extraction_df.shape}")

            per_vuln_df, summary_df, mapping_debug_df, categorization_df, baseline_instances_matched, total_baseline_instances = process_extraction_comparison_bertscore(
                baseline_df.copy(),
                extraction_df.copy(),
                extraction_sheet,
            )

            # Report name (baseline), sheet, and model
            relatorio_nome = Path(baseline_file).stem.replace(" ", "_").lower()
            aba_nome = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            modelo_nome = args.llm if args.llm else aba_nome
            if aba_nome == 'vulnerabilities' and not args.llm:
                modelo_nome = Path(args.extraction_file).stem.replace("vulnerabilities_", "").replace("_converted", "").lower()
            # Salva diretamente na pasta da run
            output_file = f"bert_comparison_{aba_nome}_{modelo_nome}.xlsx"
            output_path = args.output_dir / output_file

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

            print(f"[BERT] Comparison completed")
            print(f"       File: {output_path}")
            print(f"\n[BERT] Summary:")
            print(f"      • Matched baseline instances: {baseline_instances_matched}/{total_baseline_instances}")
            print(f"      • Unextracted vulnerabilities (Absent): {cat_counts.get('Absent', 0)}")
            print(f"      • Invented vulnerabilities (Non-existent): {total_nonexistent}")
            if unmatched_excess_count > 0:
                print(f"        ↳ Excess duplicates: {unmatched_excess_count}")
                print(f"        ↳ Inventions without match: {unmatched_count}")

            print(f"\n[BERT] Categorization:")
            print(f"      • Highly Similar (>0.7): {cat_counts.get('Highly Similar', 0)}")
            print(f"      • Moderately Similar (0.6-0.7): {cat_counts.get('Moderately Similar', 0)}")
            print(f"      • Slightly Similar (0.4-0.6): {cat_counts.get('Slightly Similar', 0)}")
            print(f"      • Divergent (≤0.4): {cat_counts.get('Divergent', 0)}")
            print(f"      • Non-existent (invented): {cat_counts.get('Non-existent', 0)}")
            print(f"      • Absent (unextracted): {cat_counts.get('Absent', 0)}")

            # Show only overall mean and a key field
            bert_columns = [col for col in per_vuln_df.columns if col.endswith('_bertscore_f1')]
            matched_data = per_vuln_df[per_vuln_df["_status"] == "OK"]
            overall_mean = matched_data[bert_columns].mean().mean() if not matched_data.empty else 0.0
            desc_mean = matched_data['description_bertscore_f1'].mean() if 'description_bertscore_f1' in matched_data else 0.0
            print(f"\n[BERT] Quality Metrics:")
            print(f"      • Overall mean BERTScore F1: {overall_mean:.3f}")
            print(f"      • Description mean: {desc_mean:.3f}")
            general_summary.append({
                'Extraction': extraction_sheet,
                'Baseline_Total_Vulnerabilities': baseline_total_vulns,
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
            print(f"[ERROR] Failed to process {extraction_sheet}: {e}")
            continue


    if general_summary:

        import datetime
        general_df = pd.DataFrame(general_summary)
        baseline_name = Path(args.baseline_file).stem.replace(" ", "_").lower() if hasattr(args, 'baseline_file') else "baseline"
        model_name = args.llm if hasattr(args, 'llm') and args.llm else "model"
        # Always overwrites main summary to ensure only 1 per run
        summary_name = f"summary_all_extractions_bert_{baseline_name}_{model_name}.xlsx"
        summary_path = args.output_dir / summary_name
        general_df.to_excel(summary_path, index=False)
        print(f"\n[BERT] Summary saved: {summary_path}")
        print(f"{'='*60}")
        print("[BERT] All comparisons completed")
        print(f"[BERT] Output files:")
        for extraction_sheet in available_sheets:
            clean_name = extraction_sheet.replace("Extração ", "").replace(" ", "_").lower()
            print(f"   - {args.output_dir / f'bert_comparison_{clean_name}.xlsx'}")
        print(f"   - {args.output_dir / 'summary_all_extractions_bert.xlsx'} (summary of all models)")


if __name__ == "__main__":
    main()
