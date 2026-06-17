"""Persist extracted vulnerabilities: consolidate, filter, dump to JSON."""
import json
import os

from mulitaminer.scanners.consolidation import central_custom_allow_duplicates


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
        print(f"\n[PROCESSING] Consolidating vulnerabilities (allow_duplicates={allow_duplicates})")
        final_vulns = central_custom_allow_duplicates(vulnerabilities, profile_config, allow_duplicates, output_file=output_file)
        after_consolidation_count = len(final_vulns) if final_vulns else 0
        if not final_vulns:
            print(f"\n[EXTRACTION] No vulnerabilities found.")

        def has_valid_description(vuln):
            """Check if vulnerability has valid description field."""
            desc = vuln.get("description")
            if not desc:
                return False
            if isinstance(desc, list):
                return any(str(d).strip() for d in desc)
            return bool(str(desc).strip())

        def has_valid_name(vuln):
            """Check if vulnerability has valid Name field."""
            name = vuln.get("Name")
            if not name:
                return False
            return bool(str(name).strip())

        def is_valid(vuln):
            return has_valid_name(vuln) and has_valid_description(vuln)

        removed_vulns = [v for v in final_vulns if not is_valid(v)]
        final_vulns = [v for v in final_vulns if is_valid(v)]

        if removed_vulns:
            log_path = os.path.splitext(output_file)[0] + '_removed_log.txt'
            with open(log_path, 'w', encoding='utf-8') as logf:
                logf.write(
                    "VULNERABILITY REMOVAL LOG\n"
                    "This file lists all vulnerabilities removed due to lack of valid Name or description.\n"
                    "Each item presents relevant details for traceability.\n\n"
                )
                logf.write(f"Total vulnerabilities removed: {len(removed_vulns)}\n\n")
                for idx, v in enumerate(removed_vulns, 1):
                    name = str(v.get('Name', 'NO NAME'))
                    port = str(v.get('port', ''))
                    protocol = str(v.get('protocol', ''))
                    severity = str(v.get('severity', ''))
                    logf.write(f"{idx}. Name: {name}\n")
                    logf.write(f"   Port: {port} | Protocol: {protocol} | Severity: {severity}\n")
                    desc = v.get('description', '')
                    if desc:
                        if isinstance(desc, list):
                            desc = ' '.join([str(d) for d in desc if d])
                        desc = str(desc).strip().replace('\n', ' ')
                        logf.write(f"   Original description (invalid): {desc[:200]}{'...' if len(desc)>200 else ''}\n")
                    logf.write("\n")
                logf.write(f"Final summary: {len(removed_vulns)} vulnerabilities removed due to lack of valid Name or description.\n")
            print(f"[REMOVED] Invalid entries filtered: {len(removed_vulns)}")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_vulns, f, indent=2, ensure_ascii=False)

        print("\n" + "="*60)
        print("[SUMMARY] EXTRACTION COMPLETE")
        print("="*60)
        print(f"Output file: {output_file}")
        print(f"Final vulnerabilities: {len(final_vulns)}")
        if removed_vulns:
            print(f"  (removed {len(removed_vulns)} invalid)")
        print("="*60 + "\n")

        return {
            'success': True,
            'extracted': len(vulnerabilities),
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
