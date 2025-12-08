#!/usr/bin/env python3
"""
Validate and normalize CAIS vulnerability objects.
Adapted from utils.py but for CAIS field schema with dotted names.
"""

def validate_cais_vulnerability(vuln):
    """
    Validate CAIS vulnerability object with dotted field names.
    
    CAIS fields: definition.name, asset.display_fqdn, etc
    Returns normalized vuln or None if invalid.
    """
    if not isinstance(vuln, dict):
        return None
    
    # CAIS required fields
    cais_fields = {
        "id": str,
        "asset.name": (type(None), str),
        "asset.display_fqdn": (type(None), str),
        "asset.display_ipv4_address": (type(None), str),
        "asset.host_name": (type(None), str),
        "asset.operating_system": (type(None), str),
        "asset.system_type": (type(None), str),
        
        "definition.name": str,  # REQUIRED
        "definition.severity": str,
        "definition.description": (type(None), str),
        "definition.solution": (type(None), str),
        "definition.id": (type(None), str),
        "definition.family": (type(None), str),
        "definition.type": (type(None), str),
        "definition.cve": (type(None), str),
        "definition.cwe": (type(None), str),
        "definition.cpe": (type(None), str),
        "definition.references": (type(None), list),
        "definition.see_also": (type(None), list),
        "definition.cvss3.base_score": (type(None), int, float),
        "definition.cvss3.base_vector": (type(None), str),
        "definition.cvss2.base_score": (type(None), int, float),
        "definition.cvss2.base_vector": (type(None), str),
        "definition.synopsis": (type(None), str),
        "definition.plugin_published": (type(None), str),
        "definition.vulnerability_published": (type(None), str),
        "definition.patch_published": (type(None), str),
        "definition.epss.score": (type(None), int, float),
        "definition.exploitability_ease": (type(None), str),
        
        "output": (type(None), str),
        "port": (type(None), int, str),
        "protocol": (type(None), str),
        
        "scan.id": (type(None), str),
        "scan.target": (type(None), str),
        
        "severity": str,
        "state": (type(None), str),
        "first_observed": (type(None), str),
        "last_seen": (type(None), str),
        "age_in_days": (type(None), int),
    }
    
    # Normalize all fields
    for field, expected_type in cais_fields.items():
        if field not in vuln:
            # Set default
            if expected_type == list:
                vuln[field] = []
            elif expected_type == str:
                if field == "definition.name":  # Required
                    return None  # Invalid: missing required name
                vuln[field] = ""
            elif expected_type == (type(None), str):
                vuln[field] = None
            elif expected_type == (type(None), int, float):
                vuln[field] = None
            elif expected_type == (type(None), int, str):
                vuln[field] = None
            elif expected_type == (type(None), list):
                vuln[field] = []
            continue
        
        value = vuln[field]
        
        # Type validation
        if isinstance(expected_type, tuple):
            if not isinstance(value, expected_type):
                if expected_type == (type(None), str) and value is not None:
                    vuln[field] = str(value)
                elif expected_type == (type(None), int, str) and value is not None:
                    if isinstance(value, str):
                        vuln[field] = int(value) if value.isdigit() else None
                elif expected_type == (type(None), int, float) and value is not None:
                    try:
                        vuln[field] = float(value)
                    except (ValueError, TypeError):
                        vuln[field] = None
                else:
                    vuln[field] = None
        elif expected_type == str:
            if not isinstance(value, str):
                vuln[field] = str(value) if value is not None else ""
        elif expected_type == list:
            if not isinstance(value, list):
                vuln[field] = [value] if value else []
    
    # Validate required field
    if not vuln.get("definition.name") or not str(vuln.get("definition.name")).strip():
        return None
    
    return vuln


def process_cais_response(vulnerabilities, chunk_id=""):
    """Process and validate CAIS vulnerability array."""
    if not isinstance(vulnerabilities, list):
        print(f"[AVISO{chunk_id}] Response is not a list: {type(vulnerabilities)}")
        return []
    
    valid_vulns = []
    for vuln in vulnerabilities:
        normalized = validate_cais_vulnerability(vuln)
        if normalized:
            valid_vulns.append(normalized)
        else:
            print(f"[WARN{chunk_id}] Vulnerability rejected (missing required fields or invalid)")
    
    return valid_vulns


if __name__ == "__main__":
    # Test
    test_vuln = {
        "id": "vuln_1",
        "definition.name": "SSL Certificate Expired",
        "definition.severity": "HIGH",
        "severity": "HIGH",
        "port": 443,
        "protocol": "https",
    }
    
    result = validate_cais_vulnerability(test_vuln)
    print(f"Validated: {result is not None}")
    if result:
        print(f"Fields: {len(result)}")
