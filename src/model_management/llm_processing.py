"""
Vulnerability processing and normalization.

Validates and normalizes vulnerability objects returned by LLMs,
ensuring data consistency and quality.
"""

import re
from typing import Optional, Dict, Any


def validate_and_normalize_vulnerability(vuln) -> Optional[Dict[str, Any]]:
    """
    Validate and normalize a single vulnerability object.
    
    Ensures all required fields exist with correct types and removes
    invalid vulnerabilities (missing Name, wrong types, metadata, etc).
    
    CRITICAL: Rejects vulnerabilities with invalid names (metadata, headings, etc)
    CRITICAL FIX: Validates that INSTANCES vulnerabilities have "Instances (N)" in Name
    
    Args:
        vuln: Vulnerability dictionary to validate
    
    Returns:
        Normalized vulnerability dict, or None if invalid
    """
    if not isinstance(vuln, dict):
        return None
    
    # REJECT invalid name patterns - metadata or index entries
    name = vuln.get("Name", "").strip()
    
    # Reject "VULNERABILITY ... PLUGIN ID ..." pattern (these are metadata, not vulnerability names)
    if re.match(r'^\s*VULNERABILITY\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO|LOG)\s+PLUGIN\s+ID\s+\d+', 
                name, re.IGNORECASE):
        return None
    
    # Reject if name is empty
    if not name:
        return None
    
    # CRITICAL FIX: Check if this should be an INSTANCES vulnerability
    # If it has identification array with URLs, it should have "Instances" in name
    identification = vuln.get('identification', [])
    has_urls = any(isinstance(u, str) and (u.startswith('http://') or u.startswith('https://')) 
                   for u in identification)
    
    if has_urls and 'Instances' not in name:
        # This has URLs (typical of INSTANCES) but lacks "Instances" in name
        # This is likely the prompt returning incomplete Name
        # We can try to fix it if we have HTTP info to count instances
        http_info = vuln.get('http_info', [])
        count = len(identification) if identification else len(http_info) if http_info else 0
        
        if count > 0:
            # Try to infer: append "Instances (N)" to the name
            vuln['Name'] = f"{name} Instances ({count})"
        else:
            # Can't determine count, reject as malformed
            return None
    
    # Required fields with their expected types
    # cvss accepts scalar (OpenVAS: single number) or list (Tenable: score + vector strings)
    required_structure = {
        "Name": str,
        "description": list,
        "detection_result": list,
        "detection_method": list,
        "impact": list,
        "solution": list,
        "insight": list,
        "product_detection_result": list,
        "log_method": list,
        "cvss": (type(None), int, float, list),
        "port": (type(None), int, str),
        "protocol": (type(None), str),
        "severity": str,
        "references": list,
        "plugin": list,
        "identification": list,
        "http_info": list,
        "source": str,
    }

    # Normalize fields
    for field, expected_type in required_structure.items():
        if field not in vuln:
            # Set default value based on type
            if expected_type == list:
                vuln[field] = []
            elif expected_type == str:
                vuln[field] = ""
            elif expected_type == int:
                vuln[field] = None
            elif isinstance(expected_type, tuple):
                vuln[field] = None
            continue

        # Validate and fix type
        value = vuln[field]
        if expected_type == list and not isinstance(value, list):
            if value is None:
                vuln[field] = []
            elif isinstance(value, str):
                vuln[field] = [value] if value.strip() else []
            else:
                vuln[field] = [value]
        elif expected_type == str and not isinstance(value, str):
            vuln[field] = str(value) if value is not None else ""
        elif isinstance(expected_type, tuple) and not isinstance(value, expected_type):
            vuln[field] = None
    
    # Map "Info" severity to "LOG" (per SECTION B of prompt)
    if vuln.get("severity", "").upper() == "INFO":
        vuln["severity"] = "LOG"
    
    return vuln
