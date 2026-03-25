#!/usr/bin/env python3
"""
Script to read a vulnerability extraction JSON and print a summary in the terminal.

Usage:
    python tools/summarize_vulnerabilities.py --input <extraction_file.json>
    
Example:
    python tools/summarize_vulnerabilities.py --input results_runs/OpenVAS_JuiceShop/deepseek/run1/openvas_test.json
"""

import json
import sys
import argparse
from pathlib import Path


def extract_cve_from_references(references):
    """Extract first CVE from references list."""
    if not references:
        return "N/A"
    
    for ref in references:
        if isinstance(ref, str):
            if ref.startswith("cve:"):
                return ref.replace("cve:", "").strip()
            elif "CVE-" in ref:
                # Try to extract CVE pattern
                parts = ref.split()
                for part in parts:
                    if "CVE-" in part:
                        return part.replace("cve:", "").strip()
    
    return "N/A"


def format_port_protocol(port, protocol):
    """Format port and protocol."""
    if port and protocol:
        return f"{port}/{protocol}"
    elif port:
        return str(port)
    else:
        return "N/A"


def print_vulnerability_summary(vuln):
    """Print a single vulnerability in summary format."""
    severity = vuln.get("severity", "N/A").upper()
    name = vuln.get("Name", "N/A")
    
    # CVSS
    cvss_list = vuln.get("cvss", [])
    cvss = cvss_list[0] if cvss_list else "N/A"
    
    # Port and protocol
    port = vuln.get("port", "N/A")
    protocol = vuln.get("protocol", "tcp")
    port_protocol = format_port_protocol(port, protocol)
    
    # References (CVE)
    references = vuln.get("references", [])
    cve = extract_cve_from_references(references)
    
    # Print in format: SEVERITY | NAME | CVSS X.X | PORT/PROTOCOL | CVE
    print(f"{severity:10} | {name:50} | CVSS {cvss:3} | {port_protocol:10} | {cve}")


def main():
    parser = argparse.ArgumentParser(
        description="Read a vulnerability extraction JSON and print a summary in the terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to the extraction JSON file"
    )
    
    args = parser.parse_args()
    json_file = args.input
    
    # Check if file exists
    if not Path(json_file).exists():
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)
    
    # Read JSON
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            vulnerabilities = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error reading JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Ensure it's a list
    if not isinstance(vulnerabilities, list):
        print("Error: JSON file must contain a list of vulnerabilities.")
        sys.exit(1)
    
    if not vulnerabilities:
        print("No vulnerabilities found in file.")
        sys.exit(0)
    
    # Print header
    print("\n" + "="*120)
    print(f"{'SEVERITY':10} | {'NAME':50} | {'CVSS':7} | {'PORT/PROTO':10} | CVE")
    print("="*120)
    
    # Print each vulnerability
    for vuln in vulnerabilities:
        try:
            print_vulnerability_summary(vuln)
        except Exception as e:
            print(f"Error processing vulnerability: {e}")
            continue
    
    # Print footer
    print("="*120)
    print(f"Total vulnerabilities: {len(vulnerabilities)}\n")


if __name__ == "__main__":
    main()
