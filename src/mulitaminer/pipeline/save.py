"""Persist extracted vulnerabilities: validate, consolidate, then dump to JSON.

Validity filtering (records without a usable Name/description) happens once,
inside consolidation — which also writes the `_removed_log.txt`. It used to be
duplicated here, re-filtering already-filtered data and clobbering that log.

The post-LLM validator (validate_and_normalize_vulnerability) runs here, per
record, before consolidation. It is a safety net for weak models: drops
section-header garbage mistaken for names, fills missing fields with
type-appropriate defaults, coerces unambiguous type mismatches, and maps
INFO→LOG. Verified no-op on strong-model output (0/53 records changed).
CAIS profiles are excluded — their records use dotted field names the V3
normalizer would mangle.
"""
import json

from mulitaminer.llm import validate_and_normalize_vulnerability
from mulitaminer.scanners.consolidation import central_custom_allow_duplicates


def _validate_records(vulnerabilities: list, profile_config: dict = None) -> list:
    """Run the post-LLM validator on every record; drop the ones it rejects."""
    reader = (profile_config or {}).get('reader', '')
    if 'cais' in reader.lower():
        return vulnerabilities  # CAIS schema is dotted; V3 normalization doesn't apply

    validated = []
    dropped = 0
    for vuln in vulnerabilities:
        normalized = validate_and_normalize_vulnerability(vuln)
        if normalized is None:
            dropped += 1
        else:
            validated.append(normalized)
    if dropped:
        print(f"[VALIDATE] Dropped {dropped} record(s) with missing/garbage Name")
    return validated


def save_results(vulnerabilities: list, output_file: str, profile_config: dict = None, allow_duplicates: bool = False) -> dict:
    """
    Save vulnerabilities to JSON file.

    Args:
        vulnerabilities: List of vulnerabilities
        output_file: Path to output file
        profile_config: Optional profile configuration
        allow_duplicates: Whether to allow duplicate entries

    Returns:
        Dictionary with status and counts: {'success': bool, 'extracted': int, 'after_consolidation': int, 'final': int}
    """
    try:
        extracted_count = len(vulnerabilities)
        vulnerabilities = _validate_records(vulnerabilities, profile_config)

        print(f"\n[PROCESSING] Consolidating vulnerabilities (allow_duplicates={allow_duplicates})")
        final_vulns = central_custom_allow_duplicates(vulnerabilities, profile_config, allow_duplicates, output_file=output_file)
        after_consolidation_count = len(final_vulns) if final_vulns else 0
        if not final_vulns:
            print(f"\n[EXTRACTION] No vulnerabilities found.")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)

        print("\n" + "="*60)
        print("[SUMMARY] EXTRACTION COMPLETE")
        print("="*60)
        print(f"Output file: {output_file}")
        print(f"Final vulnerabilities: {len(final_vulns)}")
        print("="*60 + "\n")

        return {
            'success': True,
            'extracted': extracted_count,
            'after_consolidation': after_consolidation_count,
            'final': len(final_vulns)
        }
    except Exception as e:
        print(f"Error saving JSON: {e}")
        return {
            'success': False,
            'extracted': len(vulnerabilities) if vulnerabilities else 0,
            'after_consolidation': 0,
            'final': 0
        }
